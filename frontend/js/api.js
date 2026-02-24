/**
 * NEXUS API Client v2.1
 * Connects frontend to backend REST API + WebSocket
 */
const API_BASE = window.location.origin;
let wsConnection = null;
let authToken = localStorage.getItem('nexus_token');

const api = {
  // ── AUTH ──
  async register(email, password, name) {
    return fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, name })
    }).then(r => r.json());
  },

  async login(email, password) {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    }).then(r => r.json());
    if (res.token) {
      authToken = res.token;
      localStorage.setItem('nexus_token', authToken);
    }
    return res;
  },

  logout() {
    authToken = null;
    localStorage.removeItem('nexus_token');
    window.location.href = '/login.html';
  },

  // ── DOMAINS ──
  async getDomains() { return this._get('/api/domains'); },
  async addDomain(url, name) { return this._post('/api/domains', { url, name }); },
  async deleteDomain(id) { return this._delete(`/api/domains/${id}`); },

  // ── SCANS ──
  async getScans(limit = 20) { return this._get(`/api/scans/list?limit=${limit}`); },
  async startScan(domainId) { return this._post('/api/scans/start', { domain_id: domainId }); },
  async getScan(id) { return this._get(`/api/scans/${id}`); },
  async getScanProgress(id) { return this._get(`/api/scans/${id}/progress`); },
  async getScanVulns(id, severity) {
    const q = severity ? `?severity=${severity}` : '';
    return this._get(`/api/scans/${id}/vulnerabilities${q}`);
  },
  async cancelScan(id) { return this._post(`/api/scans/${id}/cancel`, {}); },

  // ── REPORTS ──
  async downloadPDF(scanId) {
    const res = await fetch(`${API_BASE}/api/reports/${scanId}/pdf`, { headers: this._headers() });
    if (!res.ok) throw new Error('PDF generation failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `nexus-report-${scanId}.pdf`; a.click();
    URL.revokeObjectURL(url);
  },

  async downloadCSV(scanId) {
    const res = await fetch(`${API_BASE}/api/reports/${scanId}/csv`, { headers: this._headers() });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `nexus-report-${scanId}.csv`; a.click();
    URL.revokeObjectURL(url);
  },

  // ── ANALYTICS ──
  async getOverview() { return this._get('/api/analytics/overview'); },
  async getTrends(days = 30) { return this._get(`/api/analytics/trends?days=${days}`); },
  async getTopVulns() { return this._get('/api/analytics/top-vulnerabilities'); },
  async getDomainScores() { return this._get('/api/analytics/domain-scores'); },

  // ── HEALTH ──
  async getHealth() { return fetch(`${API_BASE}/health`).then(r => r.json()); },

  // ── WEBSOCKET ──
  connectWS(onMessage) {
    if (wsConnection) wsConnection.close();
    const wsUrl = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws`;
    wsConnection = new WebSocket(wsUrl);

    wsConnection.onopen = () => {
      if (authToken) wsConnection.send(JSON.stringify({ type: 'auth', token: authToken }));
    };
    wsConnection.onmessage = (e) => {
      try { onMessage(JSON.parse(e.data)); } catch (err) {}
    };
    wsConnection.onclose = () => {
      setTimeout(() => this.connectWS(onMessage), 3000); // Reconnect
    };
    return wsConnection;
  },

  // ── INTERNALS ──
  _headers() {
    return { 'Content-Type': 'application/json', ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}) };
  },
  async _get(path) {
    const res = await fetch(`${API_BASE}${path}`, { headers: this._headers() });
    if (res.status === 401) { this.logout(); return; }
    return res.json();
  },
  async _post(path, body) {
    const res = await fetch(`${API_BASE}${path}`, { method: 'POST', headers: this._headers(), body: JSON.stringify(body) });
    if (res.status === 401) { this.logout(); return; }
    return res.json();
  },
  async _delete(path) {
    const res = await fetch(`${API_BASE}${path}`, { method: 'DELETE', headers: this._headers() });
    return res.json();
  },

  isAuthenticated() { return !!authToken; },
  getToken() { return authToken; }
};

window.api = api;
