const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const {
  JWT_SECRET,
  hashPassword,
  verifyPassword,
  generateToken,
  authenticate,
  requireAdmin,
  requireManagementOrAdmin
} = require('./auth');
const {
  canAccessProject,
  canAccessWeeklyReport,
  detectMilestoneCycles,
  detectTaskCycles
} = require('./permissions');
const { awardXP, checkBadge, calculateLevel, getLevelTitle } = require('./gamification');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ---------------------------------------------------------------------
// MONGODB CONNECTION
// ---------------------------------------------------------------------
let mongoStatus = {
  connected: false,
  dbName: null,
  message: 'Connecting to MongoDB...'
};

async function connectMongo(uri) {
  if (!uri || !uri.trim()) {
    mongoStatus = { connected: false, dbName: null, message: 'No MongoDB URI configured' };
    return false;
  }
  const cleanUri = uri.trim().replace(/^"|"$/g, '');
  try {
    console.log('[MongoDB] Connecting to database...');
    await mongoose.connect(cleanUri);
    const dbName = mongoose.connection.name || 'innovative_hub';
    mongoStatus = {
      connected: true,
      dbName,
      message: `Connected to MongoDB: ${dbName}`
    };
    console.log(`[MongoDB] Connected successfully to: ${dbName}`);
    await db.syncAllWithMongo();
    return true;
  } catch (err) {
    console.error(`[MongoDB] Connection notice: ${err.message}`);
    mongoStatus = {
      connected: false,
      dbName: null,
      message: err.message
    };
    return false;
  }
}

// Connect MongoDB on boot
let mongoInitPromise = null;
if (process.env.MONGODB_URI && process.env.MONGODB_URI.trim()) {
  mongoInitPromise = connectMongo(process.env.MONGODB_URI);
}

function recordAudit(actorId, action, entityType, entityId, beforeSummary = null, afterSummary = null, reason = null) {
  return db.auditEvents.insertOne({
    actorId: actorId ? Number(actorId) : null,
    action,
    entityType,
    entityId: Number(entityId),
    beforeSummary,
    afterSummary,
    reason,
    timestamp: new Date().toISOString()
  });
}

// ---------------------------------------------------------------------
// REAL-TIME NOTIFICATIONS: SSE BROADCAST HUB
// ---------------------------------------------------------------------
const sseClients = new Map();
let nextSseClientId = 1;

function broadcastNotification(notif) {
  if (!notif) return;
  const rawData = JSON.stringify(notif);
  for (const [clientId, client] of sseClients.entries()) {
    try {
      const recipientMatch = notif.recipientId && String(notif.recipientId) === String(client.userId);
      const roleMatch = notif.recipientRole && String(notif.recipientRole).toUpperCase() === String(client.role).toUpperCase();
      const isPublic = !notif.recipientId && !notif.recipientRole;

      if (recipientMatch || roleMatch || isPublic) {
        client.res.write(`event: notification\ndata: ${rawData}\n\n`);
      }
    } catch (err) {
      console.warn(`[SSE] Client ${clientId} write error:`, err.message);
      sseClients.delete(clientId);
    }
  }
}

// Hook db.notifications.insertOne so ANY notification created anywhere automatically pushes in real-time
const _origNotifInsertOne = db.notifications.insertOne.bind(db.notifications);
db.notifications.insertOne = function(item) {
  const result = _origNotifInsertOne(item);
  try {
    broadcastNotification(result);
  } catch (err) {
    console.error('[SSE] Broadcast error on insertOne:', err.message);
  }
  return result;
};

function sanitizeUser(user) {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  const userBadges = db.userBadges.find({ userId: user.id });
  const badges = userBadges.map(ub => {
    const b = db.badges.findById(ub.badgeId);
    return {
      ...b,
      awardedAt: ub.awardedAt,
      reason: ub.reason
    };
  }).filter(Boolean);

  return {
    ...rest,
    badges
  };
}

// ---------------------------------------------------------------------
// 1. AUTHENTICATION & DEMO SWITCHER
// ---------------------------------------------------------------------

app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  // Ensure fresh user data directly from MongoDB Atlas
  await db.users.syncFromMongo();

  const user = db.users.findOne({ email });
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  if (!user.active) {
    return res.status(403).json({ message: 'Account is deactivated. Contact Administrator.' });
  }

  db.users.updateById(user.id, { lastLogin: new Date().toISOString() });
  const token = generateToken(user);
  return res.json({
    token,
    user: sanitizeUser(user)
  });
});

app.get('/api/v1/auth/me', authenticate, (req, res) => {
  return res.json(sanitizeUser(req.user));
});

app.post('/api/v1/auth/switch-user', (req, res) => {
  return res.status(403).json({ message: 'User switching is disabled for security. Please sign in directly.' });
});

// ---------------------------------------------------------------------
// 2. USER MANAGEMENT (SRS 7.1 Admin)
// ---------------------------------------------------------------------

app.get('/api/v1/users', authenticate, async (req, res) => {
  // Directly pull from MongoDB Atlas so any external deletes/changes reflect immediately
  await db.users.syncFromMongo();
  const allUsers = db.users.find();
  return res.json(allUsers.map(sanitizeUser));
});

app.post('/api/v1/users', authenticate, requireManagementOrAdmin, (req, res) => {
  const { fullName, email, password, role, department } = req.body;
  if (!fullName || !email || !password || !role) {
    return res.status(400).json({ message: 'Missing required user fields' });
  }

  // Hierarchy enforcement:
  // Admin can create ADMIN, CEO, COO, EMPLOYEE
  // CEO can create COO, EMPLOYEE
  // COO can create EMPLOYEE
  if (req.user.role === 'CEO' && ['ADMIN'].includes(role)) {
    return res.status(403).json({ message: 'CEO cannot provision Administrator accounts' });
  }
  if (req.user.role === 'COO' && ['ADMIN', 'CEO'].includes(role)) {
    return res.status(403).json({ message: 'COO can only provision Employee accounts' });
  }

  const existing = db.users.findOne({ email });
  if (existing) {
    return res.status(400).json({ message: 'Email is already registered' });
  }

  const newUser = db.users.insertOne({
    fullName,
    email,
    passwordHash: hashPassword(password),
    role,
    department: department || 'Engineering',
    active: true,
    xp: 100,
    level: 1,
    streakCount: 1,
    avatarTitle: 'Junior Innovator',
    createdAt: new Date().toISOString()
  });

  recordAudit(req.user.id, 'USER_CREATED', 'USER', newUser.id, null, `${newUser.fullName} (${newUser.role})`, `${req.user.role} provisioned ${newUser.role}`);

  // Governance alert for Admin
  db.notifications.insertOne({
    recipientRole: 'ADMIN',
    type: 'USER_PROVISIONED',
    title: `Account Provisioned: ${newUser.fullName}`,
    body: `${req.user.fullName} (${req.user.role}) provisioned user account for ${newUser.fullName} (${newUser.role} - ${newUser.department}).`,
    targetType: 'USER',
    targetId: newUser.id,
    createdAt: new Date().toISOString()
  });

  return res.status(201).json(sanitizeUser(newUser));
});

app.patch('/api/v1/users/:id', authenticate, requireManagementOrAdmin, (req, res) => {
  const userId = Number(req.params.id) || req.params.id;
  const user = db.users.findById(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const actorRole = (req.user.role || '').toUpperCase();
  const targetRole = (user.role || '').toUpperCase();

  // Hierarchy enforcement:
  // Admin can edit all accounts
  // CEO cannot edit Admin accounts or promote to Admin
  // COO can only edit Employee accounts
  if (actorRole === 'CEO' && targetRole === 'ADMIN') {
    return res.status(403).json({ message: 'CEO is not authorized to modify Administrator accounts' });
  }
  if (actorRole === 'COO' && ['ADMIN', 'CEO'].includes(targetRole)) {
    return res.status(403).json({ message: 'COO can only modify Employee accounts' });
  }
  if (req.body.role) {
    const newRole = String(req.body.role).toUpperCase();
    if (actorRole === 'CEO' && newRole === 'ADMIN') {
      return res.status(403).json({ message: 'CEO cannot promote accounts to Administrator' });
    }
    if (actorRole === 'COO' && ['ADMIN', 'CEO'].includes(newRole)) {
      return res.status(403).json({ message: 'COO cannot promote accounts to CEO or Administrator' });
    }
  }

  const beforeSummary = `role=${user.role}, active=${user.active}`;
  const updates = {};
  if (req.body.fullName) updates.fullName = req.body.fullName;
  if (req.body.email) updates.email = req.body.email;
  if (req.body.role) updates.role = req.body.role;
  if (req.body.department) updates.department = req.body.department;
  if (typeof req.body.active === 'boolean') updates.active = req.body.active;
  if (req.body.password) updates.passwordHash = hashPassword(req.body.password);

  const updated = db.users.updateById(userId, updates);
  recordAudit(req.user.id, 'USER_UPDATED', 'USER', userId, beforeSummary, `role=${updated.role}, active=${updated.active}`, `${actorRole} user edit`);
  return res.json(sanitizeUser(updated));
});

app.delete('/api/v1/users/:id', authenticate, requireManagementOrAdmin, async (req, res) => {
  const userId = Number(req.params.id) || req.params.id;
  await db.users.syncFromMongo();
  const user = db.users.findById(userId);
  if (!user) {
    return res.status(404).json({ message: 'User not found in system or database' });
  }

  if (String(user.id) === String(req.user.id) || String(user._id) === String(req.user.id)) {
    return res.status(400).json({ message: 'Users cannot delete their own active account' });
  }

  const actorRole = (req.user.role || '').toUpperCase();
  const targetRole = (user.role || '').toUpperCase();

  // Hierarchy enforcement:
  // Admin can delete any user except self
  // CEO cannot delete Admin accounts
  // COO can only delete Employee accounts
  if (actorRole === 'CEO' && targetRole === 'ADMIN') {
    return res.status(403).json({ message: 'CEO is not authorized to delete Administrator accounts' });
  }
  if (actorRole === 'COO' && ['ADMIN', 'CEO'].includes(targetRole)) {
    return res.status(403).json({ message: 'COO can only delete Employee accounts' });
  }

  // Delete from collection and MongoDB Atlas
  db.users.deleteById(userId);

  // Clean up any assigned memberships
  const memberships = db.projectMemberships.find({ userId: Number(userId) || userId });
  memberships.forEach(m => db.projectMemberships.deleteById(m.id));

  recordAudit(
    req.user.id,
    'USER_DELETED',
    'USER',
    userId,
    `${user.fullName} (${user.role}) - ${user.email}`,
    null,
    `${actorRole} deleted account`
  );

  return res.json({ message: `User ${user.fullName} successfully deleted from MongoDB Atlas`, deletedId: userId });
});

// ---------------------------------------------------------------------
// 3. PROJECTS (SRS 5.5, 7.2)
// ---------------------------------------------------------------------

function enrichProject(project) {
  if (!project) return null;
  const owner = db.users.findById(project.ownerId);
  const memberships = db.projectMemberships.find().filter(m =>
    Number(m.projectId) === Number(project.id) || String(m.projectId) === String(project.id)
  );
  const members = memberships.map(m => {
    const u = db.users.findById(m.userId);
    return u ? {
      id: m.id,
      userId: u.id,
      userName: u.fullName,
      userEmail: u.email,
      userRole: u.role,
      projectRole: m.projectRole
    } : null;
  }).filter(Boolean);

  const milestonesList = db.milestones.find().filter(m =>
    Number(m.projectId) === Number(project.id) || String(m.projectId) === String(project.id)
  ).sort((a, b) => (a.sequence || 0) - (b.sequence || 0));

  let completedMilestones = 0;
  let totalTasks = 0;
  let completedTasks = 0;

  const milestones = milestonesList.map(m => {
    const mOwner = db.users.findById(m.ownerId);
    const mReviewer = db.users.findById(m.reviewerId);
    const mDeps = db.milestoneDependencies.find({ milestoneId: m.id }).map(d => d.dependsOnMilestoneId);

    const mTasks = db.tasks.find({ milestoneId: m.id }).map(t => {
      const tOwner = db.users.findById(t.ownerId);
      const tDeps = db.taskDependencies.find({ taskId: t.id }).map(d => d.dependsOnTaskId);
      const updates = db.progressUpdates.find({ taskId: t.id }).map(up => {
        const author = db.users.findById(up.authorId);
        return {
          ...up,
          authorName: author ? author.fullName : 'Unknown'
        };
      });

      if (t.status === 'APPROVED_COMPLETED') completedTasks++;
      totalTasks++;

      return {
        ...t,
        ownerName: tOwner ? tOwner.fullName : 'Unassigned',
        milestoneTitle: m.title,
        projectName: project.name,
        predecessorIds: tDeps,
        updates
      };
    });

    if (m.status === 'APPROVED_COMPLETED') completedMilestones++;

    return {
      ...m,
      ownerName: mOwner ? mOwner.fullName : 'Unassigned',
      reviewerName: mReviewer ? mReviewer.fullName : 'Unassigned',
      predecessorIds: mDeps,
      tasks: mTasks
    };
  });

  const totalM = milestones.length;
  const progressPercentage = totalM > 0 ? Number(((completedMilestones / totalM) * 100).toFixed(1)) : 0;

  return {
    ...project,
    ownerName: owner ? owner.fullName : 'Unknown',
    members,
    milestones,
    milestonesCount: totalM,
    tasksCount: totalTasks,
    completedMilestones,
    completedTasks,
    progressPercentage
  };
}

app.get('/api/v1/projects', authenticate, async (req, res) => {
  await Promise.all([
    db.projects.syncFromMongo(),
    db.projectMemberships.syncFromMongo(),
    db.milestones.syncFromMongo(),
    db.milestoneDependencies.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.taskDependencies.syncFromMongo(),
    db.progressUpdates.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const includeArchived = req.query.includeArchived === 'true';
  let list = db.projects.find();

  if (!includeArchived) {
    list = list.filter(p => p.status !== 'ARCHIVED');
  }

  // RBAC filter (SRS AT-02): Employee sees only assigned/member projects
  if (req.user.role === 'EMPLOYEE') {
    list = list.filter(p => canAccessProject(req.user, p.id));
  }

  return res.json(list.map(enrichProject));
});

app.get('/api/v1/projects/:id', authenticate, async (req, res) => {
  await Promise.all([
    db.projects.syncFromMongo(),
    db.projectMemberships.syncFromMongo(),
    db.milestones.syncFromMongo(),
    db.milestoneDependencies.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.taskDependencies.syncFromMongo(),
    db.progressUpdates.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const projectId = Number(req.params.id);
  const proj = db.projects.findById(projectId);
  if (!proj) return res.status(404).json({ message: 'Project not found' });

  // Access check (AT-02)
  if (!canAccessProject(req.user, projectId)) {
    return res.status(403).json({ message: 'Access denied: You are not assigned to this project' });
  }

  return res.json(enrichProject(proj));
});

app.post('/api/v1/projects', authenticate, requireManagementOrAdmin, (req, res) => {
  const { code, name, objective, scope, deliverables, priority, startDate, targetDate, milestones, memberIds } = req.body;
  if (!code || !name || !objective || !startDate || !targetDate) {
    return res.status(400).json({ message: 'Missing required project fields' });
  }

  const existing = db.projects.findOne({ code });
  if (existing) {
    return res.status(400).json({ message: `Project code '${code}' is already taken` });
  }

  const ownerId = req.body.ownerId !== undefined && req.body.ownerId !== '' ? Number(req.body.ownerId) : req.user.id;
  const newProj = db.projects.insertOne({
    code,
    name,
    objective,
    scope: scope || '',
    deliverables: deliverables || '',
    ownerId,
    status: 'ACTIVE',
    priority: priority || 'MEDIUM',
    startDate,
    targetDate,
    createdAt: new Date().toISOString()
  });

  // Add owner to members
  db.projectMemberships.insertOne({
    projectId: newProj.id,
    userId: ownerId,
    projectRole: 'PROJECT_OWNER'
  });

  if (Array.isArray(memberIds)) {
    memberIds.forEach(mId => {
      const numMId = Number(mId);
      if (numMId && numMId !== ownerId) {
        db.projectMemberships.insertOne({
          projectId: newProj.id,
          userId: numMId,
          projectRole: 'CONTRIBUTOR'
        });
      }
    });
  }

  // Create custom milestones if supplied in creation wizard (Dynamic milestone count 3, 8, 12, etc.)
  if (Array.isArray(milestones) && milestones.length > 0) {
    const firstContributorId = (Array.isArray(memberIds) && memberIds.length > 0) ? Number(memberIds[0]) : ownerId;
    milestones.forEach((m, idx) => {
      db.milestones.insertOne({
        projectId: newProj.id,
        title: m.title,
        description: m.description || '',
        sequence: m.sequence || (idx + 1),
        ownerId: m.ownerId ? Number(m.ownerId) : firstContributorId,
        reviewerId: m.reviewerId ? Number(m.reviewerId) : ownerId,
        status: 'NOT_STARTED',
        startDate: m.startDate || startDate,
        dueDate: m.dueDate || targetDate,
        acceptanceCriteria: m.acceptanceCriteria || 'Deliverable verification signed off.',
        xpReward: m.xpReward || 300
      });
    });
  }

  recordAudit(req.user.id, 'PROJECT_CREATED', 'PROJECT', newProj.id, null, `${newProj.code}: ${newProj.name}`, 'Project wizard setup');
  awardXP(req.user.id, 150, `Created project plan '${newProj.name}'`);

  // Real-time notifications: Executive awareness & Admin governance
  const ceoUser = db.users.findOne({ role: 'CEO' });
  const cooUser = db.users.findOne({ role: 'COO' });
  if (req.user.role === 'COO' && ceoUser) {
    db.notifications.insertOne({
      recipientId: ceoUser.id,
      type: 'PROJECT_CREATED',
      title: `New Project Launched: ${newProj.name}`,
      body: `COO ${req.user.fullName} initialized new project "${newProj.name}" (${newProj.code}).`,
      targetType: 'PROJECT',
      targetId: newProj.id,
      createdAt: new Date().toISOString()
    });
  } else if (req.user.role === 'CEO' && cooUser) {
    db.notifications.insertOne({
      recipientId: cooUser.id,
      type: 'PROJECT_CREATED',
      title: `New Project Plan: ${newProj.name}`,
      body: `CEO ${req.user.fullName} initialized new project "${newProj.name}" (${newProj.code}).`,
      targetType: 'PROJECT',
      targetId: newProj.id,
      createdAt: new Date().toISOString()
    });
  }

  // Notify assigned contributors
  if (Array.isArray(memberIds)) {
    memberIds.forEach(mId => {
      if (Number(mId) !== req.user.id) {
        db.notifications.insertOne({
          recipientId: Number(mId),
          type: 'PROJECT_ASSIGNED',
          title: `Assigned to Project: ${newProj.name}`,
          body: `You were assigned as a team member to project "${newProj.name}" (${newProj.code}).`,
          targetType: 'PROJECT',
          targetId: newProj.id,
          createdAt: new Date().toISOString()
        });
      }
    });
  }

  // Admin platform monitor (only if created by non-admin)
  if (req.user.role !== 'ADMIN') {
    db.notifications.insertOne({
      recipientRole: 'ADMIN',
      type: 'PROJECT_CREATED',
      title: `Project Registered: ${newProj.name}`,
      body: `${req.user.fullName} (${req.user.role}) launched enterprise project ${newProj.code}.`,
      targetType: 'PROJECT',
      targetId: newProj.id,
      createdAt: new Date().toISOString()
    });
  }

  return res.status(201).json(enrichProject(newProj));
});

app.patch('/api/v1/projects/:id', authenticate, requireManagementOrAdmin, (req, res) => {
  const rawId = req.params.id;
  const proj = db.projects.findById(rawId);
  if (!proj) return res.status(404).json({ message: 'Project not found' });

  const targetId = proj.id !== undefined ? proj.id : rawId;
  const beforeSummary = `name=${proj.name}, status=${proj.status}, priority=${proj.priority}`;
  const updates = {};
  ['code', 'name', 'objective', 'scope', 'deliverables', 'status', 'priority', 'startDate', 'targetDate'].forEach(f => {
    if (req.body[f] !== undefined) updates[f] = req.body[f];
  });

  const updated = db.projects.updateById(targetId, updates);

  if (req.body.ownerId !== undefined && req.body.ownerId !== '') {
    const newOwnerId = Number(req.body.ownerId);
    db.projects.updateById(targetId, { ownerId: newOwnerId });
    const existingOwnerMem = db.projectMemberships.find().find(m =>
      (Number(m.projectId) === Number(targetId) || String(m.projectId) === String(targetId)) &&
      (Number(m.userId) === newOwnerId || String(m.userId) === String(newOwnerId))
    );
    if (existingOwnerMem) {
      db.projectMemberships.updateById(existingOwnerMem.id, { projectRole: 'PROJECT_OWNER' });
    } else {
      db.projectMemberships.insertOne({
        projectId: Number(targetId),
        userId: newOwnerId,
        projectRole: 'PROJECT_OWNER'
      });
    }
  }

  if (Array.isArray(req.body.memberIds)) {
    const desiredMemberIds = req.body.memberIds.map(Number);
    desiredMemberIds.forEach(mId => {
      const exists = db.projectMemberships.find().some(m =>
        (Number(m.projectId) === Number(targetId) || String(m.projectId) === String(targetId)) &&
        Number(m.userId) === mId
      );
      if (!exists) {
        db.projectMemberships.insertOne({
          projectId: Number(targetId),
          userId: mId,
          projectRole: 'CONTRIBUTOR'
        });
      }
    });
  }

  recordAudit(req.user.id, 'PROJECT_UPDATED', 'PROJECT', targetId, beforeSummary, `name=${updated.name}, status=${updated.status}`, `${req.user.role} project edit`);
  return res.json(enrichProject(updated));
});

app.post('/api/v1/projects/:id/members', authenticate, requireManagementOrAdmin, (req, res) => {
  const proj = db.projects.findById(req.params.id);
  if (!proj) return res.status(404).json({ message: 'Project not found' });
  const targetId = proj.id !== undefined ? proj.id : req.params.id;

  const { userId, projectRole } = req.body;
  const existing = db.projectMemberships.findOne({ projectId: targetId, userId: Number(userId) });
  if (existing) {
    db.projectMemberships.updateById(existing.id, { projectRole: projectRole || 'MEMBER' });
  } else {
    db.projectMemberships.insertOne({
      projectId: targetId,
      userId: Number(userId),
      projectRole: projectRole || 'MEMBER'
    });
  }
  return res.json(enrichProject(proj));
});

app.post('/api/v1/projects/:id/archive', authenticate, requireManagementOrAdmin, (req, res) => {
  const proj = db.projects.findById(req.params.id);
  if (!proj) return res.status(404).json({ message: 'Project not found' });
  const targetId = proj.id !== undefined ? proj.id : req.params.id;

  db.projects.updateById(targetId, { status: 'ARCHIVED', archivedAt: new Date().toISOString() });
  recordAudit(req.user.id, 'PROJECT_ARCHIVED', 'PROJECT', targetId, 'Status: ACTIVE', 'Status: ARCHIVED', 'Project completed or archived');
  return res.json(enrichProject(db.projects.findById(targetId)));
});

app.post('/api/v1/projects/:id/restore', authenticate, requireManagementOrAdmin, (req, res) => {
  const proj = db.projects.findById(req.params.id);
  if (!proj) return res.status(404).json({ message: 'Project not found' });
  const targetId = proj.id !== undefined ? proj.id : req.params.id;

  db.projects.updateById(targetId, { status: 'ACTIVE', archivedAt: null });
  recordAudit(req.user.id, 'PROJECT_RESTORED', 'PROJECT', targetId, 'Status: ARCHIVED', 'Status: ACTIVE', `${req.user.role} project restoration`);
  return res.json(enrichProject(db.projects.findById(targetId)));
});

app.delete('/api/v1/projects/:id', authenticate, requireManagementOrAdmin, async (req, res) => {
  const rawId = req.params.id;
  const reason = (req.body && req.body.reason) || req.query.reason || '';
  if (!reason || reason.trim().length < 5) {
    return res.status(400).json({ message: 'Audit reason of at least 5 characters is mandatory for permanent deletion' });
  }

  const proj = db.projects.findById(rawId);
  if (!proj) return res.status(404).json({ message: 'Project not found' });

  const targetId = proj.id !== undefined ? proj.id : rawId;
  db.projects.deleteById(targetId);
  if (proj._id && proj._id !== targetId) {
    db.projects.deleteById(proj._id);
  }

  // delete children
  const mList = db.milestones.find().filter(m => String(m.projectId) === String(targetId) || String(m.projectId) === String(proj.id));
  mList.forEach(m => {
    db.tasks.find().filter(t => String(t.milestoneId) === String(m.id)).forEach(t => db.tasks.deleteById(t.id));
    db.milestones.deleteById(m.id);
  });
  db.projectMemberships.find().filter(mem => String(mem.projectId) === String(targetId) || String(mem.projectId) === String(proj.id)).forEach(mem => db.projectMemberships.deleteById(mem.id));

  recordAudit(req.user.id, 'PROJECT_DELETED', 'PROJECT', targetId, `${proj.code}: ${proj.name}`, 'Permanently Deleted', reason.trim());

  // Real-time alert to Admin & Executive team
  if (req.user.role !== 'ADMIN') {
    db.notifications.insertOne({
      recipientRole: 'ADMIN',
      type: 'PROJECT_DELETED',
      title: `Project Deleted: ${proj.name}`,
      body: `${req.user.fullName} (${req.user.role}) permanently deleted project ${proj.code}. Reason: ${reason.trim()}`,
      targetType: 'PROJECT',
      targetId: targetId,
      createdAt: new Date().toISOString()
    });
  }

  const ceo = db.users.findOne({ role: 'CEO' });
  const coo = db.users.findOne({ role: 'COO' });
  if (ceo && ceo.id !== req.user.id) {
    db.notifications.insertOne({
      recipientId: ceo.id,
      type: 'PROJECT_DELETED',
      title: `Project Deletion Notice: ${proj.name}`,
      body: `${req.user.fullName} (${req.user.role}) deleted project ${proj.code}. Reason: ${reason.trim()}`,
      targetType: 'PROJECT',
      targetId: targetId,
      createdAt: new Date().toISOString()
    });
  }
  if (coo && coo.id !== req.user.id && (!ceo || coo.id !== ceo.id)) {
    db.notifications.insertOne({
      recipientId: coo.id,
      type: 'PROJECT_DELETED',
      title: `Project Deletion Notice: ${proj.name}`,
      body: `${req.user.fullName} (${req.user.role}) deleted project ${proj.code}. Reason: ${reason.trim()}`,
      targetType: 'PROJECT',
      targetId: targetId,
      createdAt: new Date().toISOString()
    });
  }

  return res.json({ message: `Project '${proj.name}' permanently deleted.` });
});

// ---------------------------------------------------------------------
// 4. MILESTONES (SRS MILE-01 to MILE-03, 5.3)
// ---------------------------------------------------------------------

function enrichMilestone(m) {
  if (!m) return null;
  const owner = db.users.findById(m.ownerId);
  const reviewer = db.users.findById(m.reviewerId);
  const project = db.projects.findById(m.projectId);
  const deps = db.milestoneDependencies.find({ milestoneId: m.id }).map(d => d.dependsOnMilestoneId);

  const tasks = db.tasks.find({ milestoneId: m.id }).map(t => {
    const tOwner = db.users.findById(t.ownerId);
    const tDeps = db.taskDependencies.find({ taskId: t.id }).map(d => d.dependsOnTaskId);
    const updates = db.progressUpdates.find({ taskId: t.id }).map(up => {
      const author = db.users.findById(up.authorId);
      return {
        ...up,
        authorName: author ? author.fullName : 'Unknown'
      };
    });

    return {
      ...t,
      ownerName: tOwner ? tOwner.fullName : 'Unassigned',
      milestoneTitle: m.title,
      projectName: project ? project.name : '',
      predecessorIds: tDeps,
      updates
    };
  });

  return {
    ...m,
    ownerName: owner ? owner.fullName : 'Unassigned',
    reviewerName: reviewer ? reviewer.fullName : 'Unassigned',
    projectName: project ? project.name : '',
    predecessorIds: deps,
    tasks
  };
}

app.post('/api/v1/projects/:projectId/milestones', authenticate, requireManagementOrAdmin, (req, res) => {
  const projectId = Number(req.params.projectId);
  const { title, description, sequence, ownerId, reviewerId, startDate, dueDate, acceptanceCriteria, xpReward, predecessorIds } = req.body;

  if (!title || !startDate || !dueDate || !acceptanceCriteria) {
    return res.status(400).json({ message: 'Title, dates, and acceptance criteria are required' });
  }

  if (new Date(dueDate) < new Date(startDate)) {
    return res.status(400).json({ message: 'Due date cannot be earlier than start date' });
  }

  const newM = db.milestones.insertOne({
    projectId,
    title,
    description: description || '',
    sequence: Number(sequence) || 1,
    ownerId: ownerId ? Number(ownerId) : req.user.id,
    reviewerId: reviewerId ? Number(reviewerId) : req.user.id,
    status: 'NOT_STARTED',
    startDate,
    dueDate,
    acceptanceCriteria,
    xpReward: Number(xpReward) || 300
  });

  // Dependency & Cycle Validation (SRS AT-05)
  if (Array.isArray(predecessorIds) && predecessorIds.length > 0) {
    if (detectMilestoneCycles(newM.id, predecessorIds)) {
      db.milestones.deleteById(newM.id);
      return res.status(400).json({ message: 'Circular dependency detected! Operation rejected.' });
    }
    predecessorIds.forEach(pid => {
      db.milestoneDependencies.insertOne({
        milestoneId: newM.id,
        dependsOnMilestoneId: Number(pid)
      });
    });
  }

  recordAudit(req.user.id, 'MILESTONE_CREATED', 'MILESTONE', newM.id, null, newM.title, 'Milestone addition');
  return res.status(201).json(enrichMilestone(newM));
});

app.patch('/api/v1/milestones/:id', authenticate, requireManagementOrAdmin, (req, res) => {
  const mId = Number(req.params.id);
  const ms = db.milestones.findById(mId);
  if (!ms) return res.status(404).json({ message: 'Milestone not found' });

  const beforeSummary = `title=${ms.title}, status=${ms.status}, dueDate=${ms.dueDate}`;
  const updates = {};
  ['title', 'description', 'sequence', 'ownerId', 'reviewerId', 'startDate', 'dueDate', 'status', 'acceptanceCriteria'].forEach(f => {
    if (req.body[f] !== undefined) updates[f] = req.body[f];
  });

  if (Array.isArray(req.body.predecessorIds)) {
    if (detectMilestoneCycles(mId, req.body.predecessorIds)) {
      return res.status(400).json({ message: 'Circular dependency detected! Operation rejected.' });
    }
    // Remove existing and re-add
    db.milestoneDependencies.find({ milestoneId: mId }).forEach(d => db.milestoneDependencies.deleteById(d.id));
    req.body.predecessorIds.forEach(pid => {
      db.milestoneDependencies.insertOne({ milestoneId: mId, dependsOnMilestoneId: Number(pid) });
    });
  }

  const updated = db.milestones.updateById(mId, updates);
  recordAudit(req.user.id, 'MILESTONE_UPDATED', 'MILESTONE', mId, beforeSummary, `title=${updated.title}, status=${updated.status}`, 'Management edit');
  return res.json(enrichMilestone(updated));
});

app.post('/api/v1/milestones/:id/submit-review', authenticate, (req, res) => {
  const mId = Number(req.params.id);
  const ms = db.milestones.findById(mId);
  if (!ms) return res.status(404).json({ message: 'Milestone not found' });

  // SRS AT-06: Status MUST become SUBMITTED_FOR_REVIEW, never APPROVED directly!
  const { evidenceNotes, evidenceUrl } = req.body;
  const updated = db.milestones.updateById(mId, {
    status: 'SUBMITTED_FOR_REVIEW',
    evidenceNotes: evidenceNotes || '',
    evidenceUrl: evidenceUrl || null
  });

  // Notify Reviewer
  if (ms.reviewerId) {
    db.notifications.insertOne({
      recipientId: ms.reviewerId,
      type: 'MILESTONE_REVIEW',
      title: 'Milestone Submitted for Verification',
      body: `${req.user.fullName} submitted milestone '${ms.title}' with acceptance test evidence.`,
      targetType: 'MILESTONE',
      targetId: ms.id,
      createdAt: new Date().toISOString()
    });
  }

  awardXP(req.user.id, 60, `Submitted milestone '${ms.title}' for verification`);
  recordAudit(req.user.id, 'MILESTONE_SUBMITTED_FOR_REVIEW', 'MILESTONE', mId, 'In Progress', 'SUBMITTED_FOR_REVIEW', 'Assignee deliverable submission');
  return res.json(enrichMilestone(updated));
});

app.post('/api/v1/milestones/:id/review', authenticate, (req, res) => {
  const mId = Number(req.params.id);
  const ms = db.milestones.findById(mId);
  if (!ms) return res.status(404).json({ message: 'Milestone not found' });

  // Must be designated reviewer or executive management
  const isReviewer = ms.reviewerId === req.user.id;
  const isMgmt = ['ADMIN', 'CEO', 'COO'].includes(req.user.role);
  if (!isReviewer && !isMgmt) {
    return res.status(403).json({ message: 'Only designated reviewer or management can conduct milestone review' });
  }

  const { decision, comments } = req.body;
  if (!decision || !comments) {
    return res.status(400).json({ message: 'Decision (APPROVED or CHANGES_REQUESTED) and review comments are required' });
  }

  db.reviewDecisions.insertOne({
    targetType: 'MILESTONE',
    targetId: mId,
    reviewerId: req.user.id,
    decision,
    comments,
    decidedAt: new Date().toISOString()
  });

  if (decision === 'APPROVED') {
    db.milestones.updateById(mId, {
      status: 'APPROVED_COMPLETED',
      acceptedAt: new Date().toISOString()
    });

    if (ms.ownerId) {
      awardXP(ms.ownerId, ms.xpReward || 300, `Milestone '${ms.title}' approved!`);
      checkBadge(ms.ownerId, 'sprint_champion', `Milestone '${ms.title}' completed`);
      db.notifications.insertOne({
        recipientId: ms.ownerId,
        type: 'REVIEW_APPROVED',
        title: `🎉 Milestone Approved: ${ms.title}`,
        body: `Reviewer comments: ${comments}`,
        targetType: 'MILESTONE',
        targetId: ms.id,
        createdAt: new Date().toISOString()
      });
    }
    awardXP(req.user.id, 80, `Conducted milestone sign-off for '${ms.title}'`);
  } else {
    // Changes Requested (AT-07)
    db.milestones.updateById(mId, { status: 'CHANGES_REQUESTED' });
    if (ms.ownerId) {
      db.notifications.insertOne({
        recipientId: ms.ownerId,
        type: 'REVIEW_CHANGES_REQUESTED',
        title: `⚠️ Changes Requested on Milestone: ${ms.title}`,
        body: `Reviewer comments: ${comments}`,
        targetType: 'MILESTONE',
        targetId: ms.id,
        createdAt: new Date().toISOString()
      });
    }
  }

  recordAudit(req.user.id, `MILESTONE_REVIEW_${decision}`, 'MILESTONE', mId, 'SUBMITTED_FOR_REVIEW', decision, comments);
  return res.json(enrichMilestone(db.milestones.findById(mId)));
});

// ---------------------------------------------------------------------
// 5. TASKS (SRS TASK-01 to TASK-03, 5.4)
// ---------------------------------------------------------------------

function enrichTask(t) {
  if (!t) return null;
  const owner = db.users.findById(t.ownerId);
  const milestone = db.milestones.findById(t.milestoneId);
  const project = db.projects.findById(t.projectId);
  const deps = db.taskDependencies.find({ taskId: t.id }).map(d => d.dependsOnTaskId);
  const updates = db.progressUpdates.find({ taskId: t.id }).map(up => {
    const author = db.users.findById(up.authorId);
    return {
      ...up,
      authorName: author ? author.fullName : 'Unknown'
    };
  });

  return {
    ...t,
    ownerName: owner ? owner.fullName : 'Unassigned',
    milestoneTitle: milestone ? milestone.title : '',
    projectName: project ? project.name : '',
    predecessorIds: deps,
    updates
  };
}

app.get('/api/v1/tasks', authenticate, async (req, res) => {
  await Promise.all([
    db.tasks.syncFromMongo(),
    db.taskDependencies.syncFromMongo(),
    db.progressUpdates.syncFromMongo(),
    db.milestones.syncFromMongo(),
    db.projects.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const { projectId, milestoneId, onlyMine } = req.query;
  let list = db.tasks.find();

  if (projectId) list = list.filter(t => t.projectId === Number(projectId));
  if (milestoneId) list = list.filter(t => t.milestoneId === Number(milestoneId));

  if (onlyMine === 'true' || req.user.role === 'EMPLOYEE') {
    if (onlyMine === 'true') {
      list = list.filter(t => t.ownerId === req.user.id);
    } else {
      // Employee sees tasks in projects they belong to or own
      list = list.filter(t => t.ownerId === req.user.id || canAccessProject(req.user, t.projectId));
    }
  }

  return res.json(list.map(enrichTask));
});

app.post('/api/v1/milestones/:milestoneId/tasks', authenticate, requireManagementOrAdmin, (req, res) => {
  const milestoneId = Number(req.params.milestoneId);
  const ms = db.milestones.findById(milestoneId);
  if (!ms) return res.status(404).json({ message: 'Milestone not found' });

  const { title, description, ownerId, priority, startDate, dueDate, acceptanceCriteria, deliverableExpected, xpReward, predecessorIds } = req.body;
  if (!title || !startDate || !dueDate) {
    return res.status(400).json({ message: 'Title and dates are required' });
  }

  const newTask = db.tasks.insertOne({
    projectId: ms.projectId,
    milestoneId: ms.id,
    title,
    description: description || '',
    ownerId: ownerId ? Number(ownerId) : null,
    status: 'ASSIGNED',
    priority: priority || 'MEDIUM',
    startDate,
    dueDate,
    originalDueDate: dueDate,
    acceptanceCriteria: acceptanceCriteria || '',
    deliverableExpected: deliverableExpected || '',
    xpReward: Number(xpReward) || 80
  });

  if (Array.isArray(predecessorIds) && predecessorIds.length > 0) {
    if (detectTaskCycles(newTask.id, predecessorIds)) {
      db.tasks.deleteById(newTask.id);
      return res.status(400).json({ message: 'Circular task dependency detected! Operation rejected.' });
    }
    predecessorIds.forEach(pid => {
      db.taskDependencies.insertOne({ taskId: newTask.id, dependsOnTaskId: Number(pid) });
    });
  }

  if (newTask.ownerId) {
    db.notifications.insertOne({
      recipientId: newTask.ownerId,
      type: 'TASK_ASSIGNED',
      title: 'New Task Assignment',
      body: `You were assigned to '${newTask.title}' under milestone '${ms.title}'.`,
      targetType: 'TASK',
      targetId: newTask.id,
      createdAt: new Date().toISOString()
    });
  }

  recordAudit(req.user.id, 'TASK_CREATED', 'TASK', newTask.id, null, newTask.title, 'Task creation');
  return res.status(201).json(enrichTask(newTask));
});

app.patch('/api/v1/tasks/:id', authenticate, (req, res) => {
  const taskId = Number(req.params.id);
  const task = db.tasks.findById(taskId);
  if (!task) return res.status(404).json({ message: 'Task not found' });

  const isOwner = task.ownerId === req.user.id;
  const isMgmt = ['ADMIN', 'CEO', 'COO'].includes(req.user.role);
  if (!isOwner && !isMgmt) {
    return res.status(403).json({ message: 'Not authorized to modify this task' });
  }

  const beforeSummary = `status=${task.status}, dueDate=${task.dueDate}, priority=${task.priority}`;
  const updates = {};

  if (isMgmt) {
    ['title', 'ownerId', 'priority', 'acceptanceCriteria'].forEach(f => {
      if (req.body[f] !== undefined) updates[f] = req.body[f];
    });
  }

  if (req.body.description !== undefined) updates.description = req.body.description;
  if (req.body.deliverableExpected !== undefined) updates.deliverableExpected = req.body.deliverableExpected;

  if (req.body.status) {
    if (req.body.status === 'APPROVED_COMPLETED' && !isMgmt) {
      return res.status(403).json({ message: 'Only managers can approve task completion. Submit for review instead.' });
    }
    updates.status = req.body.status;
    if (req.body.status === 'APPROVED_COMPLETED') {
      updates.completedAt = new Date().toISOString();
      if (task.ownerId) {
        awardXP(task.ownerId, task.xpReward || 80, `Task '${task.title}' approved`);
      }
    } else if (req.body.status === 'SUBMITTED_FOR_REVIEW') {
      updates.submittedAt = new Date().toISOString();
      awardXP(req.user.id, 30, `Submitted task '${task.title}' for verification`);
    }
  }

  const updated = db.tasks.updateById(taskId, updates);
  recordAudit(req.user.id, 'TASK_UPDATED', 'TASK', taskId, beforeSummary, `status=${updated.status}`, 'Progress update');
  return res.json(enrichTask(updated));
});

app.post('/api/v1/tasks/:id/updates', authenticate, (req, res) => {
  // SRS 10.2 & EXC-01: Blocker update with 5 mandatory fields
  const taskId = Number(req.params.id);
  const task = db.tasks.findById(taskId);
  if (!task) return res.status(404).json({ message: 'Task not found' });

  const { summary, impact, proposedSolution, expectedResolutionDate, supportNeeded, workLog } = req.body;
  if (!summary || !impact || !proposedSolution || !supportNeeded) {
    return res.status(400).json({ message: 'Summary, impact, proposed solution, and support needed are mandatory for blocker reports' });
  }

  db.tasks.updateById(taskId, { status: 'BLOCKED' });

  const updateEntry = db.progressUpdates.insertOne({
    taskId,
    milestoneId: task.milestoneId,
    authorId: req.user.id,
    statusSnapshot: 'BLOCKED',
    note: summary,
    workLog: workLog || '',
    isBlocker: true,
    blockerReason: summary,
    impact,
    proposedSolution,
    expectedResolutionDate: expectedResolutionDate || null,
    supportNeeded,
    createdAt: new Date().toISOString()
  });

  // Alert project owner, COO & Admin
  const proj = db.projects.findById(task.projectId);
  const coo = db.users.findOne({ role: 'COO' });
  const blockerTargets = new Set();
  if (proj && proj.ownerId && proj.ownerId !== req.user.id) blockerTargets.add(proj.ownerId);
  if (coo && coo.id !== req.user.id) blockerTargets.add(coo.id);

  for (const recipientId of blockerTargets) {
    db.notifications.insertOne({
      recipientId,
      type: 'BLOCKER_ALERT',
      title: `🚨 Blocker Escalation: ${task.title}`,
      body: `${req.user.fullName} reported critical blocker: "${summary}". Proposed solution: "${proposedSolution || 'Mitigation required'}".`,
      targetType: 'TASK',
      targetId: task.id,
      createdAt: new Date().toISOString()
    });
  }

  // Admin platform monitor
  db.notifications.insertOne({
    recipientRole: 'ADMIN',
    type: 'BLOCKER_ALERT',
    title: `Critical Blocker Escalated: ${task.title}`,
    body: `${req.user.fullName} escalated blocker on task "${task.title}" (${proj ? proj.name : ''}).`,
    targetType: 'TASK',
    targetId: task.id,
    createdAt: new Date().toISOString()
  });

  recordAudit(req.user.id, 'TASK_BLOCKER_REPORTED', 'TASK', taskId, 'Active', 'BLOCKED', `Impact: ${impact}`);
  awardXP(req.user.id, 30, `Reported blocker with proactive recovery solution for '${task.title}'`);
  return res.status(201).json(enrichTask(db.tasks.findById(taskId)));
});

app.post('/api/v1/tasks/:id/submit-review', authenticate, (req, res) => {
  const taskId = Number(req.params.id);
  const task = db.tasks.findById(taskId);
  if (!task) return res.status(404).json({ message: 'Task not found' });

  const { notes } = req.body;
  db.tasks.updateById(taskId, {
    status: 'SUBMITTED_FOR_REVIEW',
    submittedAt: new Date().toISOString()
  });

  db.progressUpdates.insertOne({
    taskId,
    milestoneId: task.milestoneId,
    authorId: req.user.id,
    statusSnapshot: 'SUBMITTED_FOR_REVIEW',
    note: notes || 'Deliverable ready for acceptance testing.',
    isBlocker: false,
    createdAt: new Date().toISOString()
  });

  // Notify Reviewer / COO
  const milestone = db.milestones.findById(task.milestoneId);
  const proj = db.projects.findById(task.projectId);
  const reviewerId = (milestone && milestone.reviewerId) || (proj && proj.ownerId);
  if (reviewerId && reviewerId !== req.user.id) {
    db.notifications.insertOne({
      recipientId: reviewerId,
      type: 'TASK_SUBMITTED',
      title: `Task Ready for Review: ${task.title}`,
      body: `${req.user.fullName} submitted deliverable for "${task.title}". Acceptance verification required.`,
      targetType: 'TASK',
      targetId: task.id,
      createdAt: new Date().toISOString()
    });
  }

  const coo = db.users.findOne({ role: 'COO' });
  if (coo && coo.id !== reviewerId && coo.id !== req.user.id) {
    db.notifications.insertOne({
      recipientId: coo.id,
      type: 'TASK_SUBMITTED',
      title: `Task Ready for Review: ${task.title}`,
      body: `${req.user.fullName} submitted deliverable for "${task.title}".`,
      targetType: 'TASK',
      targetId: task.id,
      createdAt: new Date().toISOString()
    });
  }

  awardXP(req.user.id, 40, `Submitted task '${task.title}' for verification`);
  return res.json(enrichTask(db.tasks.findById(taskId)));
});

app.post('/api/v1/tasks/:id/review', authenticate, requireManagementOrAdmin, (req, res) => {
  const taskId = Number(req.params.id);
  const task = db.tasks.findById(taskId);
  if (!task) return res.status(404).json({ message: 'Task not found' });

  const { decision, comments } = req.body;
  if (!decision || !comments) {
    return res.status(400).json({ message: 'Decision and review comments are required' });
  }

  db.reviewDecisions.insertOne({
    targetType: 'TASK',
    targetId: taskId,
    reviewerId: req.user.id,
    decision,
    comments,
    decidedAt: new Date().toISOString()
  });

  if (decision === 'APPROVED') {
    db.tasks.updateById(taskId, {
      status: 'APPROVED_COMPLETED',
      completedAt: new Date().toISOString()
    });

    if (task.ownerId) {
      awardXP(task.ownerId, task.xpReward || 80, `Task '${task.title}' accepted and approved!`);
      db.notifications.insertOne({
        recipientId: task.ownerId,
        type: 'TASK_APPROVED',
        title: `✅ Task Approved: ${task.title}`,
        body: `Reviewer notes: ${comments}`,
        targetType: 'TASK',
        targetId: task.id,
        createdAt: new Date().toISOString()
      });
    }
    awardXP(req.user.id, 40, `Reviewed deliverable for '${task.title}'`);
  } else {
    db.tasks.updateById(taskId, { status: 'CHANGES_REQUESTED' });
    if (task.ownerId) {
      db.notifications.insertOne({
        recipientId: task.ownerId,
        type: 'TASK_CHANGES_REQUESTED',
        title: `⚠️ Changes Requested: ${task.title}`,
        body: `Feedback: ${comments}`,
        targetType: 'TASK',
        targetId: task.id,
        createdAt: new Date().toISOString()
      });
    }
  }

  recordAudit(req.user.id, `TASK_REVIEW_${decision}`, 'TASK', taskId, 'SUBMITTED_FOR_REVIEW', decision, comments);
  return res.json(enrichTask(db.tasks.findById(taskId)));
});

app.post('/api/v1/tasks/:id/request-schedule-change', authenticate, (req, res) => {
  // SRS 6.4: The original due date must be preserved. Propose revised date with audit trail.
  const taskId = Number(req.params.id);
  const task = db.tasks.findById(taskId);
  if (!task) return res.status(404).json({ message: 'Task not found' });

  const { newDueDate, reason } = req.body;
  if (!newDueDate || !reason) {
    return res.status(400).json({ message: 'Proposed new due date and reason are required' });
  }

  const reqDoc = db.scheduleRequests.insertOne({
    taskId,
    milestoneId: task.milestoneId,
    requesterId: req.user.id,
    oldDueDate: task.dueDate,
    newDueDate,
    reason,
    status: 'PENDING',
    createdAt: new Date().toISOString()
  });

  recordAudit(req.user.id, 'SCHEDULE_CHANGE_REQUESTED', 'TASK', taskId, task.dueDate, newDueDate, reason);
  return res.status(201).json(reqDoc);
});

// ---------------------------------------------------------------------
// 6. WEEKLY REPORTS (SRS 6.1 - 6.2, REP-01, REP-02)
// ---------------------------------------------------------------------

function enrichWeeklyReport(rep) {
  if (!rep) return null;
  const user = db.users.findById(rep.userId);
  const reviewer = rep.reviewedBy ? db.users.findById(rep.reviewedBy) : null;
  const versions = db.weeklyReportVersions.find({ reportId: rep.id })
    .sort((a, b) => b.versionNumber - a.versionNumber)
    .map(v => {
      const sub = db.users.findById(v.submittedBy);
      return {
        ...v,
        submitterName: sub ? sub.fullName : 'Unknown'
      };
    });

  return {
    ...rep,
    userName: user ? user.fullName : 'Unknown',
    reviewerName: reviewer ? reviewer.fullName : null,
    versions
  };
}

app.get('/api/v1/weekly-reports', authenticate, async (req, res) => {
  await Promise.all([
    db.weeklyReports.syncFromMongo(),
    db.weeklyReportVersions.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  let list = db.weeklyReports.find();

  // SRS AT-01 Rule: Employee can ONLY view their own reports!
  if (req.user.role === 'EMPLOYEE') {
    list = list.filter(r => r.userId === req.user.id);
  } else if (req.query.userId) {
    list = list.filter(r => r.userId === Number(req.query.userId));
  }

  return res.json(list.map(enrichWeeklyReport));
});

app.get('/api/v1/weekly-reports/:id', authenticate, async (req, res) => {
  await Promise.all([
    db.weeklyReports.syncFromMongo(),
    db.weeklyReportVersions.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const repId = Number(req.params.id);
  const rep = db.weeklyReports.findById(repId);
  if (!rep) return res.status(404).json({ message: 'Weekly report not found' });

  // Strict AT-01 check: Forbidden if another employee tries to access
  if (!canAccessWeeklyReport(req.user, rep)) {
    return res.status(403).json({ message: 'Access denied: You cannot view another employee private report' });
  }

  return res.json(enrichWeeklyReport(rep));
});

app.post('/api/v1/weekly-reports', authenticate, (req, res) => {
  const {
    periodStart,
    periodEnd,
    completedThisWeek,
    inProgress,
    blockersRisks,
    reasonForDelay,
    proposedSolution,
    nextWeekPlan,
    supportDecisionsRequired,
    isDraft
  } = req.body;

  if (!periodStart || !periodEnd || (!isDraft && (!completedThisWeek || !inProgress || !nextWeekPlan))) {
    return res.status(400).json({ message: 'Required weekly report fields are missing' });
  }

  const existing = db.weeklyReports.findOne({
    userId: req.user.id,
    periodStart
  });

  const statusVal = isDraft ? 'DRAFT' : 'SUBMITTED';
  let report = null;

  if (existing) {
    if (existing.status !== 'DRAFT' && existing.status !== 'CHANGES_REQUESTED') {
      return res.status(400).json({ message: `Report for period starting ${periodStart} is already ${existing.status}.` });
    }
    const nextVer = (existing.currentVersion || 1) + 1;
    report = db.weeklyReports.updateById(existing.id, {
      status: statusVal,
      currentVersion: nextVer,
      submittedAt: isDraft ? null : new Date().toISOString()
    });
  } else {
    report = db.weeklyReports.insertOne({
      userId: req.user.id,
      periodStart,
      periodEnd,
      status: statusVal,
      currentVersion: 1,
      submittedAt: isDraft ? null : new Date().toISOString()
    });
  }

  // Save version snapshot (SRS REP-02 revision history preservation)
  db.weeklyReportVersions.insertOne({
    reportId: report.id,
    versionNumber: report.currentVersion,
    completedThisWeek: completedThisWeek || '',
    inProgress: inProgress || '',
    blockersRisks: blockersRisks || '',
    reasonForDelay: reasonForDelay || '',
    proposedSolution: proposedSolution || '',
    nextWeekPlan: nextWeekPlan || '',
    supportDecisionsRequired: supportDecisionsRequired || '',
    submittedAt: new Date().toISOString(),
    submittedBy: req.user.id
  });

  if (!isDraft) {
    awardXP(req.user.id, 50, `Submitted weekly report for period ${periodStart}`);
    recordAudit(req.user.id, 'WEEKLY_REPORT_SUBMITTED', 'WEEKLY_REPORT', report.id, null, `Version ${report.currentVersion}`, 'Weekly reporting cycle');
  }

  return res.status(201).json(enrichWeeklyReport(report));
});

app.post('/api/v1/weekly-reports/:id/review', authenticate, requireManagementOrAdmin, (req, res) => {
  const repId = Number(req.params.id);
  const rep = db.weeklyReports.findById(repId);
  if (!rep) return res.status(404).json({ message: 'Weekly report not found' });

  const { decision, comments } = req.body;
  if (!decision || !comments) {
    return res.status(400).json({ message: 'Decision and comments are required' });
  }

  db.reviewDecisions.insertOne({
    targetType: 'WEEKLY_REPORT',
    targetId: repId,
    reviewerId: req.user.id,
    decision,
    comments,
    decidedAt: new Date().toISOString()
  });

  if (decision === 'APPROVED') {
    db.weeklyReports.updateById(repId, {
      status: 'REVIEWED',
      reviewedBy: req.user.id,
      reviewedAt: new Date().toISOString(),
      reviewerFeedback: comments
    });

    awardXP(rep.userId, 100, 'Weekly report approved without defect changes!');
    checkBadge(rep.userId, 'flawless_report', 'Flawless weekly report approval');

    db.notifications.insertOne({
      recipientId: rep.userId,
      type: 'REPORT_REVIEWED',
      title: 'Weekly Report Approved',
      body: `Reviewer comments: ${comments}`,
      targetType: 'WEEKLY_REPORT',
      targetId: rep.id,
      createdAt: new Date().toISOString()
    });
  } else {
    // Changes requested (REP-02)
    db.weeklyReports.updateById(repId, {
      status: 'CHANGES_REQUESTED',
      reviewedBy: req.user.id,
      reviewedAt: new Date().toISOString(),
      reviewerFeedback: comments
    });

    db.notifications.insertOne({
      recipientId: rep.userId,
      type: 'REPORT_CHANGES_REQUESTED',
      title: 'Weekly Report Revision Requested',
      body: `Reviewer notes: ${comments}`,
      targetType: 'WEEKLY_REPORT',
      targetId: rep.id,
      createdAt: new Date().toISOString()
    });
  }

  awardXP(req.user.id, 50, `Completed review for weekly report #${rep.id}`);
  recordAudit(req.user.id, `WEEKLY_REPORT_REVIEW_${decision}`, 'WEEKLY_REPORT', rep.id, 'SUBMITTED', decision, comments);
  return res.json(enrichWeeklyReport(db.weeklyReports.findById(repId)));
});

// ---------------------------------------------------------------------
// 7. REVIEW INBOX & SCHEDULE CHANGES (SRS 6.4, 7.2)
// ---------------------------------------------------------------------

app.get('/api/v1/review-inbox', authenticate, requireManagementOrAdmin, async (req, res) => {
  await Promise.all([
    db.milestones.syncFromMongo(),
    db.milestoneDependencies.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.taskDependencies.syncFromMongo(),
    db.progressUpdates.syncFromMongo(),
    db.weeklyReports.syncFromMongo(),
    db.weeklyReportVersions.syncFromMongo(),
    db.scheduleRequests.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const pendingMilestones = db.milestones.find({ status: 'SUBMITTED_FOR_REVIEW' }).map(enrichMilestone);
  const pendingTasks = db.tasks.find({ status: 'SUBMITTED_FOR_REVIEW' }).map(enrichTask);
  const pendingReports = db.weeklyReports.find({ status: 'SUBMITTED' }).map(enrichWeeklyReport);
  const pendingSchedules = db.scheduleRequests.find({ status: 'PENDING' }).map(sq => {
    const task = db.tasks.findById(sq.taskId);
    const requester = db.users.findById(sq.requesterId);
    return {
      ...sq,
      taskTitle: task ? task.title : 'Unknown',
      requesterName: requester ? requester.fullName : 'Unknown'
    };
  });

  return res.json({
    pendingMilestones,
    pendingTasks,
    pendingReports,
    pendingSchedules,
    totalBacklog: pendingMilestones.length + pendingTasks.length + pendingReports.length + pendingSchedules.length
  });
});

app.get('/api/v1/schedule-requests', authenticate, async (req, res) => {
  await Promise.all([
    db.scheduleRequests.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const list = db.scheduleRequests.find().map(sq => {
    const task = db.tasks.findById(sq.taskId);
    const requester = db.users.findById(sq.requesterId);
    const approver = sq.approverId ? db.users.findById(sq.approverId) : null;
    return {
      ...sq,
      taskTitle: task ? task.title : 'Unknown',
      requesterName: requester ? requester.fullName : 'Unknown',
      approverName: approver ? approver.fullName : null
    };
  });
  return res.json(list);
});

app.post('/api/v1/schedule-requests/:id/review', authenticate, requireManagementOrAdmin, (req, res) => {
  const reqId = Number(req.params.id);
  const sq = db.scheduleRequests.findById(reqId);
  if (!sq) return res.status(404).json({ message: 'Schedule request not found' });

  const { status, decisionNotes } = req.body;
  if (!['APPROVED', 'REJECTED'].includes(status)) {
    return res.status(400).json({ message: 'Status must be APPROVED or REJECTED' });
  }

  db.scheduleRequests.updateById(reqId, {
    status,
    approverId: req.user.id,
    decidedAt: new Date().toISOString(),
    decisionNotes: decisionNotes || ''
  });

  if (status === 'APPROVED' && sq.taskId) {
    const task = db.tasks.findById(sq.taskId);
    if (task) {
      db.tasks.updateById(task.id, { dueDate: sq.newDueDate });
      recordAudit(req.user.id, 'SCHEDULE_CHANGE_APPROVED', 'TASK', task.id, task.dueDate, sq.newDueDate, sq.reason);
    }
  }

  return res.json(db.scheduleRequests.findById(reqId));
});

// ---------------------------------------------------------------------
// 8. NOTIFICATIONS & AUDIT TRAIL (SRS NOT-01, AUD-01)
// ---------------------------------------------------------------------

app.get('/api/v1/notifications/stream', async (req, res) => {
  let token = req.query.token;
  if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ message: 'Authentication required for live notification stream' });
  }

  let user = null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    user = db.users.findById(payload.sub);
    if (!user) {
      await db.users.syncFromMongo();
      user = db.users.findById(payload.sub);
    }
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired stream token' });
  }

  if (!user || !user.active) {
    return res.status(403).json({ message: 'User unauthorized' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (res.flushHeaders) res.flushHeaders();

  const clientId = nextSseClientId++;
  const clientObj = {
    id: clientId,
    userId: user.id,
    role: user.role,
    res
  };
  sseClients.set(clientId, clientObj);

  // Send initial connected handshake
  res.write(`event: connected\ndata: ${JSON.stringify({ status: 'connected', userId: user.id, role: user.role })}\n\n`);

  // Heartbeat ping every 20 seconds to keep SSE pipe alive through firewalls/proxies
  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {
      clearInterval(heartbeat);
      sseClients.delete(clientId);
    }
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(clientId);
  });
});

app.get('/api/v1/notifications', authenticate, async (req, res) => {
  await db.notifications.syncFromMongo();
  const uid = String(req.user.id || req.user._id);
  const uRole = (req.user.role || '').toUpperCase();
  const notifs = db.notifications.find()
    .filter(n => {
      // Direct recipient user match
      if (n.recipientId !== undefined && n.recipientId !== null) {
        return String(n.recipientId) === uid;
      }
      // Role-based notification match
      if (n.recipientRole) {
        return String(n.recipientRole).toUpperCase() === uRole;
      }
      // Public broadcast (no recipientId or recipientRole specified)
      return true;
    })
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 50);
  return res.json(notifs);
});

app.post('/api/v1/notifications/:id/read', authenticate, (req, res) => {
  const nId = req.params.id;
  const updated = db.notifications.updateById(nId, { readAt: new Date().toISOString() });
  return res.json({ status: 'ok', notification: updated });
});

app.post('/api/v1/notifications/read-all', authenticate, (req, res) => {
  const uid = String(req.user.id || req.user._id);
  const uRole = (req.user.role || '').toUpperCase();
  const now = new Date().toISOString();
  const unread = db.notifications.find().filter(n => {
    if (n.readAt) return false;
    if (n.recipientId !== undefined && n.recipientId !== null) {
      return String(n.recipientId) === uid;
    }
    if (n.recipientRole) {
      return String(n.recipientRole).toUpperCase() === uRole;
    }
    return true;
  });
  unread.forEach(n => db.notifications.updateById(n.id || n._id, { readAt: now }));
  return res.json({ status: 'ok', count: unread.length });
});

app.get('/api/v1/audit-events', authenticate, requireManagementOrAdmin, async (req, res) => {
  await Promise.all([
    db.auditEvents.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const { actorId, entityType } = req.query;
  let list = db.auditEvents.find();
  if (actorId) list = list.filter(e => e.actorId === Number(actorId));
  if (entityType) list = list.filter(e => e.entityType === entityType);

  const results = list
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 100)
    .map(e => {
      const actor = e.actorId ? db.users.findById(e.actorId) : null;
      return {
        ...e,
        actorName: actor ? actor.fullName : 'System'
      };
    });

  return res.json(results);
});

// Alias for Admin Portal audit trail
app.get('/api/v1/audit', authenticate, requireManagementOrAdmin, async (req, res) => {
  await Promise.all([
    db.auditEvents.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const { actorId, entityType } = req.query;
  let list = db.auditEvents.find();
  if (actorId) list = list.filter(e => e.actorId === Number(actorId));
  if (entityType) list = list.filter(e => e.entityType === entityType);

  const results = list
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 100)
    .map(e => {
      const actor = e.actorId ? db.users.findById(e.actorId) : null;
      return {
        ...e,
        actorName: actor ? actor.fullName : 'System'
      };
    });

  return res.json(results);
});

// ---------------------------------------------------------------------
// 9. DASHBOARD SUMMARY & GAMIFICATION (SRS 12.3 & Gamification)
// ---------------------------------------------------------------------

app.get('/api/v1/dashboard/summary', authenticate, async (req, res) => {
  await Promise.all([
    db.milestones.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.weeklyReports.syncFromMongo(),
    db.scheduleRequests.syncFromMongo(),
    db.users.syncFromMongo()
  ]);

  const today = new Date().toISOString().split('T')[0];

  const allMilestones = db.milestones.find({ status: { $ne: 'CANCELLED' } });
  const approvedMilestones = allMilestones.filter(m => m.status === 'APPROVED_COMPLETED');
  const mRate = allMilestones.length > 0 ? Number(((approvedMilestones.length / allMilestones.length) * 100).toFixed(1)) : 0;

  const allTasks = db.tasks.find({ status: { $ne: 'CANCELLED' } });
  const completedTasks = allTasks.filter(t => t.status === 'APPROVED_COMPLETED');
  const tRate = allTasks.length > 0 ? Number(((completedTasks.length / allTasks.length) * 100).toFixed(1)) : 0;

  const overdueTasks = allTasks.filter(t => t.dueDate < today && t.status !== 'APPROVED_COMPLETED');
  const overdueMilestones = allMilestones.filter(m => m.dueDate < today && m.status !== 'APPROVED_COMPLETED');
  const overdueCount = overdueTasks.length + overdueMilestones.length;

  const atRiskCount = allTasks.filter(t => t.status === 'AT_RISK').length + allMilestones.filter(m => m.status === 'AT_RISK').length;
  const blockedCount = allTasks.filter(t => t.status === 'BLOCKED').length + allMilestones.filter(m => m.status === 'BLOCKED').length;

  const activeEmployees = db.users.find({ active: true, role: 'EMPLOYEE' });
  const employeeIdsWithReports = new Set(
    db.weeklyReports.find({ status: { $in: ['SUBMITTED', 'REVIEWED'] } }).map(r => String(r.userId))
  );
  const compliantCount = activeEmployees.filter(e => employeeIdsWithReports.has(String(e.id || e._id))).length;
  const complianceRate = activeEmployees.length > 0 
    ? Math.min(100, Number(((compliantCount / activeEmployees.length) * 100).toFixed(1))) 
    : 100;

  const reviewBacklog = (
    db.milestones.find({ status: 'SUBMITTED_FOR_REVIEW' }).length +
    db.tasks.find({ status: 'SUBMITTED_FOR_REVIEW' }).length +
    db.weeklyReports.find({ status: 'SUBMITTED' }).length +
    db.scheduleRequests.find({ status: 'PENDING' }).length
  );

  return res.json({
    milestoneCompletionRate: mRate,
    totalMilestones: allMilestones.length,
    approvedMilestones: approvedMilestones.length,
    taskCompletionRate: tRate,
    totalTasks: allTasks.length,
    completedTasks: completedTasks.length,
    overdueCount,
    atRiskCount,
    blockedCount,
    weeklyReportComplianceRate: complianceRate,
    reviewBacklogCount: reviewBacklog,
    userXP: req.user.xp || 0,
    userLevel: req.user.level || 1,
    userStreak: req.user.streakCount || 0,
    userTitle: req.user.avatarTitle || 'Junior Innovator'
  });
});

app.get('/api/v1/gamification/leaderboard', authenticate, async (req, res) => {
  await Promise.all([
    db.users.syncFromMongo(),
    db.tasks.syncFromMongo(),
    db.userBadges.syncFromMongo()
  ]);

  const users = db.users.find({ active: true })
    .sort((a, b) => (b.xp || 0) - (a.xp || 0));

  const leaderboard = users.map((u, index) => {
    const compCount = db.tasks.find({ ownerId: u.id, status: 'APPROVED_COMPLETED' }).length;
    const badgesCount = db.userBadges.find({ userId: u.id }).length;
    return {
      id: u.id,
      fullName: u.fullName,
      role: u.role,
      department: u.department,
      xp: u.xp || 0,
      level: u.level || 1,
      streakCount: u.streakCount || 0,
      avatarTitle: u.avatarTitle || 'Junior Innovator',
      completedTasksCount: compCount,
      badgesCount,
      rank: index + 1
    };
  });

  return res.json(leaderboard);
});

app.get('/api/v1/gamification/badges', authenticate, async (req, res) => {
  await db.badges.syncFromMongo();
  return res.json(db.badges.find());
});

app.get('/api/v1/config', authenticate, async (req, res) => {
  await db.systemConfigs.syncFromMongo();
  return res.json(db.systemConfigs.findById(1) || {});
});

app.patch('/api/v1/config', authenticate, requireAdmin, (req, res) => {
  const updated = db.systemConfigs.updateById(1, req.body);
  recordAudit(req.user.id, 'SYSTEM_CONFIG_UPDATED', 'CONFIG', 1, null, 'Settings saved', 'Admin configuration');
  return res.json(updated);
});

// ---------------------------------------------------------------------
// MONGODB ATLAS ENDPOINTS
// ---------------------------------------------------------------------
app.get('/api/v1/system/mongodb-status', (req, res) => {
  return res.json({
    connected: mongoStatus.connected,
    dbName: mongoStatus.dbName,
    message: mongoStatus.message,
    hasConfiguredUri: Boolean(process.env.MONGODB_URI && process.env.MONGODB_URI.trim())
  });
});

app.post('/api/v1/system/mongodb-uri', async (req, res) => {
  const { uri } = req.body;
  if (!uri || !uri.trim()) {
    return res.status(400).json({ message: 'MongoDB connection URI is required' });
  }

  const success = await connectMongo(uri);
  if (success) {
    try {
      const envPath = path.join(__dirname, '.env');
      let envContent = '';
      if (fs.existsSync(envPath)) {
        envContent = fs.readFileSync(envPath, 'utf8');
        if (envContent.includes('MONGODB_URI=')) {
          envContent = envContent.replace(/MONGODB_URI=.*(\r?\n|$)/g, `MONGODB_URI=${uri.trim()}$1`);
        } else {
          envContent += `\nMONGODB_URI=${uri.trim()}\n`;
        }
      } else {
        envContent = `PORT=5000\nJWT_SECRET=jg_innovative_hub_secret_key_2026_gamified\nMONGODB_URI=${uri.trim()}\n`;
      }
      fs.writeFileSync(envPath, envContent, 'utf8');
      process.env.MONGODB_URI = uri.trim();
    } catch (saveErr) {
      console.warn('Could not write .env file:', saveErr.message);
    }

    return res.json({
      connected: true,
      dbName: mongoStatus.dbName,
      message: mongoStatus.message
    });
  } else {
    return res.status(400).json({
      connected: false,
      message: mongoStatus.message
    });
  }
});

// 1. Static files serving for compiled Standalone Admin Portal (/admin)
const adminDist = path.join(__dirname, '..', 'admin', 'dist');
if (fs.existsSync(adminDist)) {
  app.use('/admin', express.static(adminDist));
  app.get('/admin*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(adminDist, 'index.html'));
  });
}

// 2. Static files serving for compiled Staff Frontend (/)
const frontendDist = path.join(__dirname, '..', 'frontend', 'dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path.startsWith('/admin')) return next();
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

async function startServer() {
  if (mongoInitPromise) {
    await mongoInitPromise;
  }
  app.listen(PORT, () => {
    console.log(`JG Innovative Hub MERN Server running on port ${PORT}`);
    console.log(`Web application ready at http://localhost:${PORT}`);
  });
}

startServer();

