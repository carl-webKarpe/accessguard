const API = {
  csrf: null,
  async token() { if (!this.csrf) this.csrf = (await fetch('/api/auth/csrf', { credentials: 'same-origin' }).then(r => r.json())).csrfToken; return this.csrf; },
  async request(url, options = {}) {
    if (location.protocol === 'file:') throw new Error('Open AccessGuard at http://localhost:3000 after running npm run dev. Do not open the HTML files directly.');
    const method = (options.method || 'GET').toUpperCase(); const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    if (!['GET', 'HEAD'].includes(method)) headers['X-CSRF-Token'] = await this.token();
    const response = await fetch(`/api${url}`, { credentials: 'same-origin', ...options, method, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) { const error = new Error(data.error || 'Request failed.'); error.status = response.status; throw error; }
    return data;
  }
};
function toast(message, type = 'success') { const colors = { success:'bg-emerald-600', error:'bg-rose-600', warning:'bg-amber-500' }; const item = document.createElement('div'); item.className = `toast ${colors[type]} text-white px-4 py-3 rounded-lg shadow-xl text-sm font-bold`; item.textContent = message; document.querySelector('#toasts').append(item); setTimeout(() => item.remove(), 3800); }