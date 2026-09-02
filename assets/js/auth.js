const Auth = (() => {
  const pageFor = (role) => {
    const page = role === 'ADMIN' ? 'admin.html' : role === 'STAFF' ? 'staff.html' : 'user.html';
    return location.pathname.toLowerCase().includes('/pages/') ? page : `pages/${page}`;
  };
  const requireRole = (role) => { const user = AccessGuardStore.currentUser(); if (!user) { location.replace('../login.html'); return null; } if (user.role !== role) { location.replace(pageFor(user.role)); return null; } return user; };
  const requireUser = () => { const user = AccessGuardStore.currentUser(); if (!user) location.replace('login.html'); return user; };
  return { pageFor, requireRole, requireUser };
})();