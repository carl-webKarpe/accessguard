const crypto = require('crypto');
const { db } = require('../config/database');

function getUser(userId) {
  return db.prepare(`SELECT u.id, u.full_name, u.username, u.email, u.status, u.created_at, u.last_login, r.id AS role_id, r.name AS role
    FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?`).get(userId);
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Authentication is required.' });
  const user = getUser(req.session.userId);
  if (!user || user.status !== 'ACTIVE') return req.session.destroy(() => res.status(401).json({ error: 'Your session is no longer valid.' }));
  req.user = user;
  next();
}
function csrfToken(req, res) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.json({ csrfToken: req.session.csrfToken });
}
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const provided = Buffer.from(req.get('X-CSRF-Token') || '');
  const expected = Buffer.from(req.session.csrfToken || '');
  if (!expected.length || provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return res.status(403).json({ error: 'Invalid security token. Refresh and try again.' });
  next();
}
module.exports = { getUser, requireAuth, csrfToken, requireCsrf };