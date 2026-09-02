const { db } = require('../config/database');
function requirePermission(permission) {
  return (req, res, next) => {
    const allowed = db.prepare(`SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ? AND p.name = ?`).get(req.user.role_id, permission);
    if (!allowed) return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    next();
  };
}
module.exports = { requirePermission };