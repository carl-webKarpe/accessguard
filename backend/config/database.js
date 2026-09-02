const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const databaseDirectory = path.join(__dirname, '..', 'database');
fs.mkdirSync(databaseDirectory, { recursive: true });
const db = new Database(path.join(databaseDirectory, 'database.sqlite'));
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

function initializeDatabase() {
  db.exec(fs.readFileSync(path.join(databaseDirectory, 'schema.sql'), 'utf8'));
  const roles = [['ADMIN', 'Full system access'], ['STAFF', 'Management access'], ['USER', 'Basic user access']];
  const addRole = db.prepare('INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)');
  roles.forEach((role) => addRole.run(...role));
  const permissions = [
    ['VIEW_DASHBOARD', 'View dashboards'], ['VIEW_RECORDS', 'View records'], ['CREATE_RECORDS', 'Create records'],
    ['UPDATE_RECORDS', 'Update records'], ['DELETE_RECORDS', 'Delete records'], ['MANAGE_USERS', 'Manage users'],
    ['MANAGE_ROLES', 'Manage roles and permissions'], ['VIEW_LOGS', 'View activity logs'], ['MANAGE_SETTINGS', 'Manage settings']
  ];
  const addPermission = db.prepare('INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)');
  permissions.forEach((permission) => addPermission.run(...permission));
  const roleId = (name) => db.prepare('SELECT id FROM roles WHERE name = ?').get(name).id;
  const permissionId = (name) => db.prepare('SELECT id FROM permissions WHERE name = ?').get(name).id;
  const grant = db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
  const grants = {
    ADMIN: permissions.map(([name]) => name),
    STAFF: ['VIEW_DASHBOARD', 'VIEW_RECORDS', 'CREATE_RECORDS', 'UPDATE_RECORDS'],
    USER: ['VIEW_DASHBOARD', 'VIEW_RECORDS']
  };
  Object.entries(grants).forEach(([role, names]) => names.forEach((name) => grant.run(roleId(role), permissionId(name))));
}

module.exports = { db, initializeDatabase };