const AccessGuardStore = (() => {
  const KEYS = { users: 'accessguard_users', records: 'accessguard_records', activity: 'accessguard_activity', session: 'accessguard_session', notices: 'accessguard_notifications' };
  const permissions = {
    ADMIN: ['view_records', 'create_record', 'edit_record', 'delete_record', 'manage_users', 'manage_roles', 'view_logs', 'settings'],
    STAFF: ['view_records', 'create_record', 'edit_record', 'view_logs'],
    USER: ['view_records', 'profile']
  };
  const read = (key, fallback) => JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback));
  const write = (key, value) => localStorage.setItem(key, JSON.stringify(value));
  const seed = () => {
    if (localStorage.getItem(KEYS.users)) return;
    write(KEYS.users, [
      { id: 1, name: 'Alex Morgan', username: 'admin', email: 'admin@accessguard.local', password: 'admin123', role: 'ADMIN', status: 'ACTIVE', lastLogin: null, createdAt: '2026-08-10T09:00:00Z' },
      { id: 2, name: 'Jordan Lee', username: 'staff', email: 'staff@accessguard.local', password: 'staff123', role: 'STAFF', status: 'ACTIVE', lastLogin: null, createdAt: '2026-08-14T10:00:00Z' },
      { id: 3, name: 'Taylor Brooks', username: 'user', email: 'user@accessguard.local', password: 'user123', role: 'USER', status: 'ACTIVE', lastLogin: null, createdAt: '2026-08-16T11:00:00Z' }
    ]);
    write(KEYS.records, [
      { id: 1, title: 'Quarterly access review', description: 'Review privileged account assignments for the operations group.', owner: 'Alex Morgan', createdAt: '2026-08-30T09:20:00Z', updatedAt: '2026-08-30T09:20:00Z' },
      { id: 2, title: 'Vendor onboarding controls', description: 'Confirm role boundaries before granting external access.', owner: 'Jordan Lee', createdAt: '2026-08-31T13:45:00Z', updatedAt: '2026-08-31T13:45:00Z' }
    ]);
    write(KEYS.activity, [{ id: 1, user: 'System', action: 'Security workspace initialized', status: 'SUCCESS', createdAt: new Date().toISOString() }]);
    write(KEYS.notices, [{ id: 1, title: 'Security posture stable', message: 'All access controls are operating normally.', read: false }]);
  };
  const users = () => read(KEYS.users, []); const records = () => read(KEYS.records, []); const activity = () => read(KEYS.activity, []);
  const saveUsers = (value) => write(KEYS.users, value); const saveRecords = (value) => write(KEYS.records, value);
  const log = (user, action, status = 'SUCCESS') => { const list = activity(); list.unshift({ id: Date.now(), user, action, status, createdAt: new Date().toISOString() }); write(KEYS.activity, list.slice(0, 100)); };
  const currentUser = () => read(KEYS.session, null);
  const login = (identifier, password, remember) => { const account = users().find(user => (user.username.toLowerCase() === identifier.toLowerCase() || user.email.toLowerCase() === identifier.toLowerCase()) && user.password === password); if (!account || account.status !== 'ACTIVE') return null; account.lastLogin = new Date().toISOString(); saveUsers(users().map(user => user.id === account.id ? account : user)); write(KEYS.session, { ...account, remember: Boolean(remember) }); log(account.name, 'Signed in to AccessGuard'); return account; };
  const logout = () => { const user = currentUser(); if (user) log(user.name, 'Signed out of AccessGuard'); localStorage.removeItem(KEYS.session); };
  const can = (permission) => { const user = currentUser(); return Boolean(user && permissions[user.role]?.includes(permission)); };
  return { KEYS, permissions, seed, users, records, activity, saveUsers, saveRecords, log, currentUser, login, logout, can, read, write };
})();
AccessGuardStore.seed();