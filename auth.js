const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'jg-innovative-hub-secure-token-secret-2026';
const TOKEN_EXPIRY = '7d';

function hashPassword(password) {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return bcrypt.hashSync(password, 10);
}

function verifyPassword(plain, hashed) {
  if (!plain || !hashed || typeof plain !== 'string' || typeof hashed !== 'string') return false;
  try {
    return bcrypt.compareSync(plain, hashed);
  } catch {
    return false;
  }
}

function generateToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required. Token missing.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    let user = db.users.findById(payload.sub);
    if (!user) {
      await db.users.syncFromMongo();
      user = db.users.findById(payload.sub);
    }
    if (!user) {
      return res.status(401).json({ message: 'User account not found' });
    }
    if (!user.active) {
      return res.status(403).json({ message: 'Account is deactivated. Contact Administrator.' });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired authentication token' });
  }
}

function requireAdmin(req, res, next) {
  const role = (req.user && req.user.role ? String(req.user.role).trim().toUpperCase() : '');
  if (role !== 'ADMIN') {
    return res.status(403).json({ message: 'Administrator authority required for this action' });
  }
  next();
}

function requireManagementOrAdmin(req, res, next) {
  const role = (req.user && req.user.role ? String(req.user.role).trim().toUpperCase() : '');
  if (!['ADMIN', 'CEO', 'COO'].includes(role)) {
    return res.status(403).json({ message: 'Executive Management (CEO/COO) or Administrator access required' });
  }
  next();
}

module.exports = {
  JWT_SECRET,
  hashPassword,
  verifyPassword,
  generateToken,
  authenticate,
  requireAdmin,
  requireManagementOrAdmin
};

