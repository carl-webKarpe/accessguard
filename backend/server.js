const path = require('path');
try { require('dotenv').config({ path: path.join(__dirname, '.env') }); } catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
const bcrypt = require('bcrypt');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { db, initializeDatabase } = require('./config/database');
const { getUser, requireAuth, csrfToken, requireCsrf } = require('./middleware/auth');
const { requirePermission } = require('./middleware/authorization');
const { audit } = require('./services/auditService');

initializeDatabase();
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const createDemo = db.prepare('INSERT INTO users (full_name, username, email, password_hash, role_id) VALUES (?, ?, ?, ?, ?)');
  const role = (name) => db.prepare('SELECT id FROM roles WHERE name = ?').get(name).id;
  createDemo.run('System Administrator', 'admin', 'admin@accessguard.local', bcrypt.hashSync('admin123', 12), role('ADMIN'));
  createDemo.run('Operations Staff', 'staff', 'staff@accessguard.local', bcrypt.hashSync('staff123', 12), role('STAFF'));
}
for (const demo of [{ username: 'admin', oldPassword: 'Admin123!', password: 'admin123' }, { username: 'staff', oldPassword: 'Staff123!', password: 'staff123' }]) {
  const account = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(demo.username);
  if (account && bcrypt.compareSync(demo.oldPassword, account.password_hash)) db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(bcrypt.hashSync(demo.password, 12), account.id);
}
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: false, credentials: true }));
app.use(express.json({ limit: '20kb' }));
app.use(session({ secret: process.env.SESSION_SECRET || 'development-secret-change-me', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 } }));
const authenticationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: process.env.NODE_ENV === 'production' ? 10 : 100,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'Too many sign-in attempts. Please wait 15 minutes before trying again.' })
});

const publicUser = (user) => user && ({ id: user.id, fullName: user.full_name, username: user.username, email: user.email, role: user.role, status: user.status, createdAt: user.created_at, lastLogin: user.last_login });
const validText = (value, min, max) => typeof value === 'string' && value.trim().length >= min && value.trim().length <= max && !/[<>]/.test(value);
app.get('/api/auth/csrf', csrfToken);
app.post('/api/auth/register', authenticationLimiter, requireCsrf, async (req, res, next) => { try {
  const { fullName, username, email, password } = req.body;
  if (!validText(fullName, 2, 100) || !/^[a-zA-Z0-9_]{3,30}$/.test(username || '') || !/^\S+@\S+\.\S+$/.test(email || '') || !validText(password, 8, 128)) return res.status(400).json({ error: 'Provide a name, valid username and email, and a password of at least 8 characters.' });
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ? OR email = ?').get(username.trim(), email.trim().toLowerCase());
  if (exists) return res.status(409).json({ error: 'That username or email is already registered.' });
  const role = db.prepare("SELECT id FROM roles WHERE name = 'USER'").get();
  const result = db.prepare('INSERT INTO users (full_name, username, email, password_hash, role_id) VALUES (?, ?, ?, ?, ?)').run(fullName.trim(), username.trim(), email.trim().toLowerCase(), await bcrypt.hash(password, 12), role.id);
  req.session.userId = result.lastInsertRowid; req.session.csrfToken = undefined;
  res.status(201).json({ user: publicUser(getUser(result.lastInsertRowid)) });
} catch (error) { next(error); } });
app.post('/api/auth/login', authenticationLimiter, requireCsrf, async (req, res, next) => { try {
  const identifier = String(req.body.identifier || '').trim(); const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(identifier, identifier.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials.' });
  if (user.status !== 'ACTIVE') return res.status(403).json({ error: 'This account is inactive.' });
  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  req.session.userId = user.id; audit({ user, ip: req.ip }, 'LOGIN', 'AUTH', 'Successful sign in'); res.json({ user: publicUser(getUser(user.id)) });
} catch (error) { next(error); } });
app.post('/api/auth/logout', requireAuth, requireCsrf, (req, res) => { audit(req, 'LOGOUT', 'AUTH', 'Signed out'); req.session.destroy(() => res.clearCookie('connect.sid').json({ message: 'Signed out.' })); });
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.put('/api/auth/profile', requireAuth, requireCsrf, (req, res) => {
  const { fullName, email } = req.body;
  if (!validText(fullName, 2, 100) || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Provide a valid name and email.' });
  try { db.prepare('UPDATE users SET full_name=?, email=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(fullName.trim(), email.trim().toLowerCase(), req.user.id); audit(req, 'UPDATE_PROFILE', `USER:${req.user.id}`, 'Updated own profile'); res.json({ user: publicUser(getUser(req.user.id)) }); } catch (error) { if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That email is already registered.' }); throw error; }
});
app.put('/api/auth/password', requireAuth, requireCsrf, async (req, res, next) => { try {
  const { currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT password_hash FROM users WHERE id=?').get(req.user.id);
  if (!validText(newPassword, 8, 128)) return res.status(400).json({ error: 'Your new password must contain at least 8 characters.' });
  if (!(await bcrypt.compare(currentPassword || '', user.password_hash))) return res.status(400).json({ error: 'Your current password is incorrect.' });
  db.prepare('UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(await bcrypt.hash(newPassword, 12), req.user.id); audit(req, 'CHANGE_PASSWORD', `USER:${req.user.id}`, 'Changed own password'); res.json({ message: 'Password changed.' });
} catch (error) { next(error); } });

app.get('/api/dashboard', requireAuth, (req, res) => {
  const records = db.prepare('SELECT COUNT(*) AS count FROM records').get().count;
  const users = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  const events = db.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE created_at >= datetime('now', '-1 day')").get().count;
  const activity = db.prepare(`SELECT a.*, u.full_name, r.name AS role FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id LEFT JOIN roles r ON r.id = u.role_id ORDER BY a.id DESC LIMIT 8`).all();
  res.json({ stats: { users, activeUsers: db.prepare("SELECT COUNT(*) AS count FROM users WHERE status = 'ACTIVE'").get().count, records, events }, activity });
});
app.get('/api/records', requireAuth, requirePermission('VIEW_RECORDS'), (req, res) => res.json({ records: db.prepare('SELECT r.*, u.full_name AS creator FROM records r JOIN users u ON u.id = r.created_by ORDER BY r.id DESC').all() }));
app.get('/api/records/:id', requireAuth, requirePermission('VIEW_RECORDS'), (req, res) => { const record = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id); if (!record) return res.status(404).json({ error: 'Record not found.' }); res.json({ record }); });
app.post('/api/records', requireAuth, requireCsrf, requirePermission('CREATE_RECORDS'), (req, res) => { const { title, description } = req.body; if (!validText(title, 2, 120) || !validText(description, 2, 2000)) return res.status(400).json({ error: 'Title and description are required.' }); const result = db.prepare('INSERT INTO records (title, description, created_by) VALUES (?, ?, ?)').run(title.trim(), description.trim(), req.user.id); audit(req, 'CREATE_RECORD', `RECORD:${result.lastInsertRowid}`, `Created record: ${title.trim()}`); res.status(201).json({ id: result.lastInsertRowid }); });
app.put('/api/records/:id', requireAuth, requireCsrf, requirePermission('UPDATE_RECORDS'), (req, res) => { const record = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id); if (!record) return res.status(404).json({ error: 'Record not found.' }); const { title, description } = req.body; if (!validText(title, 2, 120) || !validText(description, 2, 2000)) return res.status(400).json({ error: 'Title and description are required.' }); db.prepare('UPDATE records SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(title.trim(), description.trim(), record.id); audit(req, 'UPDATE_RECORD', `RECORD:${record.id}`, `Updated record: ${title.trim()}`); res.json({ message: 'Record updated.' }); });
app.delete('/api/records/:id', requireAuth, requireCsrf, requirePermission('DELETE_RECORDS'), (req, res) => { const record = db.prepare('SELECT * FROM records WHERE id = ?').get(req.params.id); if (!record) return res.status(404).json({ error: 'Record not found.' }); db.prepare('DELETE FROM records WHERE id = ?').run(record.id); audit(req, 'DELETE_RECORD', `RECORD:${record.id}`, `Deleted record: ${record.title}`); res.json({ message: 'Record deleted.' }); });

app.get('/api/users', requireAuth, requirePermission('MANAGE_USERS'), (req, res) => res.json({ users: db.prepare('SELECT u.id,u.full_name,u.username,u.email,u.status,u.created_at,u.last_login,r.name AS role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id DESC').all() }));
app.post('/api/users', requireAuth, requireCsrf, requirePermission('MANAGE_USERS'), async (req, res, next) => { try { const { fullName, username, email, password, roleId } = req.body; if (!validText(fullName, 2, 100) || !/^[a-zA-Z0-9_]{3,30}$/.test(username || '') || !/^\S+@\S+\.\S+$/.test(email || '') || !validText(password, 8, 128) || !db.prepare('SELECT 1 FROM roles WHERE id = ?').get(roleId)) return res.status(400).json({ error: 'Invalid user information.' }); const created = db.prepare('INSERT INTO users(full_name,username,email,password_hash,role_id) VALUES(?,?,?,?,?)').run(fullName.trim(), username.trim(), email.trim().toLowerCase(), await bcrypt.hash(password, 12), roleId); audit(req, 'CREATE_USER', `USER:${created.lastInsertRowid}`, `Created user: ${username}`); res.status(201).json({ id: created.lastInsertRowid }); } catch (error) { next(error); } });
app.put('/api/users/:id', requireAuth, requireCsrf, requirePermission('MANAGE_USERS'), (req, res) => { const { fullName, email, status } = req.body; if (!validText(fullName, 2, 100) || !/^\S+@\S+\.\S+$/.test(email || '') || !['ACTIVE', 'INACTIVE'].includes(status)) return res.status(400).json({ error: 'Invalid user information.' }); const changed = db.prepare('UPDATE users SET full_name=?,email=?,status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(fullName.trim(), email.trim().toLowerCase(), status, req.params.id); if (!changed.changes) return res.status(404).json({ error: 'User not found.' }); audit(req, 'UPDATE_USER', `USER:${req.params.id}`, `Updated user: ${fullName.trim()}`); res.json({ message: 'User updated.' }); });
app.put('/api/users/:id/role', requireAuth, requireCsrf, requirePermission('MANAGE_ROLES'), (req, res) => { if (!db.prepare('SELECT 1 FROM roles WHERE id = ?').get(req.body.roleId)) return res.status(400).json({ error: 'Invalid role.' }); const changed = db.prepare('UPDATE users SET role_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.body.roleId, req.params.id); if (!changed.changes) return res.status(404).json({ error: 'User not found.' }); audit(req, 'CHANGE_ROLE', `USER:${req.params.id}`, 'Changed user role'); res.json({ message: 'Role updated.' }); });
app.delete('/api/users/:id', requireAuth, requireCsrf, requirePermission('MANAGE_USERS'), (req, res) => { if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account.' }); const changed = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id); if (!changed.changes) return res.status(404).json({ error: 'User not found.' }); audit(req, 'DELETE_USER', `USER:${req.params.id}`, 'Deleted user'); res.json({ message: 'User deleted.' }); });
app.get('/api/roles', requireAuth, (req, res) => res.json({ roles: db.prepare('SELECT * FROM roles ORDER BY id').all() }));
app.get('/api/permissions', requireAuth, requirePermission('MANAGE_ROLES'), (req, res) => res.json({ permissions: db.prepare('SELECT * FROM permissions ORDER BY name').all() }));
app.get('/api/roles/:id/permissions', requireAuth, (req, res) => res.json({ permissions: db.prepare('SELECT p.* FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? ORDER BY p.name').all(req.params.id) }));
app.get('/api/audit-logs', requireAuth, requirePermission('VIEW_LOGS'), (req, res) => res.json({ logs: db.prepare('SELECT a.*,u.full_name,r.name AS role FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN roles r ON r.id=u.role_id ORDER BY a.id DESC LIMIT 100').all() }));
app.get('/admin', (req, res) => {
  const user = req.session.userId && getUser(req.session.userId);
  if (!user || user.role !== 'ADMIN') return res.status(403).sendFile(path.join(__dirname, '..', 'frontend', '403.html'));
  res.sendFile(path.join(__dirname, '..', 'frontend', 'dashboard.html'));
});
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html')));
app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, '..', 'frontend', '404.html')));
app.use((error, req, res, next) => { if (error?.code === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That value is already in use.' }); console.error(error); res.status(500).json({ error: 'An unexpected server error occurred.' }); });
const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`AccessGuard is running at http://localhost:${port}`));