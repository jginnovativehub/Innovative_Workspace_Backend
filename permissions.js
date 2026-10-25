const db = require('./db');

function canAccessProject(user, projectId) {
  if (!user) return false;
  if (['ADMIN', 'CEO', 'COO'].includes(user.role)) {
    return true;
  }

  const pId = Number(projectId);
  const uId = Number(user.id);

  // 1. Direct project ownership
  const proj = db.projects.findById(projectId) || (pId ? db.projects.findById(pId) : null);
  if (proj) {
    if (Number(proj.ownerId) === uId || String(proj.ownerId) === String(user.id)) {
      return true;
    }
  }

  // 2. Project membership (checking with number and string equality)
  const memberships = db.projectMemberships.find();
  const membership = memberships.find(m => 
    (Number(m.projectId) === pId || String(m.projectId) === String(projectId)) &&
    (Number(m.userId) === uId || String(m.userId) === String(user.id))
  );
  if (membership) return true;

  // 3. Task assignment
  const tasks = db.tasks.find();
  const task = tasks.find(t => 
    (Number(t.projectId) === pId || String(t.projectId) === String(projectId)) &&
    (Number(t.ownerId) === uId || String(t.ownerId) === String(user.id))
  );
  if (task) return true;

  // 4. Milestone assignment (owner or reviewer)
  const milestones = db.milestones.find();
  const milestone = milestones.find(m =>
    (Number(m.projectId) === pId || String(m.projectId) === String(projectId)) &&
    (Number(m.ownerId) === uId || String(m.ownerId) === String(user.id) ||
     Number(m.reviewerId) === uId || String(m.reviewerId) === String(user.id))
  );
  if (milestone) return true;

  return false;
}

function canAccessWeeklyReport(user, report) {
  // AT-01 Rule: Employee cannot view another employee's private weekly report
  if (report.userId === user.id) return true;
  if (['ADMIN', 'CEO', 'COO'].includes(user.role)) return true;
  if (report.reviewedBy === user.id) return true;
  return false;
}

function detectMilestoneCycles(milestoneId, newPredecessorIds = []) {
  const mId = Number(milestoneId);
  const preds = newPredecessorIds.map(Number);

  if (preds.includes(mId)) {
    return true; // Self-dependency
  }

  const visited = new Set();
  function dfs(currId) {
    if (currId === mId) return true;
    if (visited.has(currId)) return false;
    visited.add(currId);

    const deps = db.milestoneDependencies.find({ milestoneId: currId });
    for (const d of deps) {
      if (dfs(Number(d.dependsOnMilestoneId))) return true;
    }
    return false;
  }

  for (const pred of preds) {
    if (dfs(pred)) return true;
  }
  return false;
}

function detectTaskCycles(taskId, newPredecessorIds = []) {
  const tId = Number(taskId);
  const preds = newPredecessorIds.map(Number);

  if (preds.includes(tId)) {
    return true;
  }

  const visited = new Set();
  function dfs(currId) {
    if (currId === tId) return true;
    if (visited.has(currId)) return false;
    visited.add(currId);

    const deps = db.taskDependencies.find({ taskId: currId });
    for (const d of deps) {
      if (dfs(Number(d.dependsOnTaskId))) return true;
    }
    return false;
  }

  for (const pred of preds) {
    if (dfs(pred)) return true;
  }
  return false;
}

module.exports = {
  canAccessProject,
  canAccessWeeklyReport,
  detectMilestoneCycles,
  detectTaskCycles
};

