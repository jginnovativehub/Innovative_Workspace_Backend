const db = require('./db');

const LEVEL_TITLES = {
  1: 'Junior Innovator',
  2: 'Agile Builder',
  3: 'System Craftsman',
  4: 'Lead Architect',
  5: 'Master Pioneer'
};

function calculateLevel(xp) {
  return Math.max(1, 1 + Math.floor(xp / 400));
}

function getLevelTitle(level) {
  return LEVEL_TITLES[level] || 'Master Pioneer';
}

function awardXP(userId, amount, reason) {
  const user = db.users.findById(userId);
  if (!user) return { awarded: 0, totalXP: 0 };

  const oldLevel = user.level || 1;
  const currentXP = (user.xp || 0) + amount;
  const newLevel = calculateLevel(currentXP);
  const newTitle = getLevelTitle(newLevel);
  const leveledUp = newLevel > oldLevel;

  db.users.updateById(user.id, {
    xp: currentXP,
    level: newLevel,
    avatarTitle: newTitle
  });

  if (leveledUp) {
    db.notifications.insertOne({
      recipientId: user.id,
      type: 'LEVEL_UP',
      title: `🎉 Level Up! You reached Level ${newLevel}`,
      body: `Congratulations! You unlocked the rank '${newTitle}' with ${currentXP} total XP.`,
      targetType: 'USER',
      targetId: user.id,
      createdAt: new Date().toISOString()
    });
  } else {
    db.notifications.insertOne({
      recipientId: user.id,
      type: 'XP_GAIN',
      title: `⚡ +${amount} Innovation XP Earned!`,
      body: `${reason}. Total XP: ${currentXP}`,
      targetType: 'USER',
      targetId: user.id,
      createdAt: new Date().toISOString()
    });
  }

  return {
    awarded: amount,
    totalXP: currentXP,
    level: newLevel,
    title: newTitle,
    leveledUp
  };
}

function checkBadge(userId, badgeCode, reason = '') {
  const badge = db.badges.findOne({ code: badgeCode });
  if (!badge) return null;

  const existing = db.userBadges.findOne({
    userId: Number(userId),
    badgeId: badge.id
  });
  if (existing) return null; // already earned

  db.userBadges.insertOne({
    userId: Number(userId),
    badgeId: badge.id,
    reason,
    awardedAt: new Date().toISOString()
  });

  // Award bonus XP for badge
  awardXP(userId, badge.xpBonus || 100, `Unlocked Achievement: ${badge.title}`);

  db.notifications.insertOne({
    recipientId: Number(userId),
    type: 'BADGE_UNLOCKED',
    title: `🏆 Achievement Unlocked: ${badge.title}!`,
    body: `${badge.description} (+${badge.xpBonus} XP bonus)`,
    targetType: 'BADGE',
    targetId: badge.id,
    createdAt: new Date().toISOString()
  });

  return badge;
}

module.exports = {
  calculateLevel,
  getLevelTitle,
  awardXP,
  checkBadge
};

