const { db } = require('../config/database');
function audit(req, action, target, description) {
  db.prepare('INSERT INTO audit_logs (user_id, action, target, description, ip_address) VALUES (?, ?, ?, ?, ?)')
    .run(req.user?.id || null, action, target, description, req.ip);
}
module.exports = { audit };