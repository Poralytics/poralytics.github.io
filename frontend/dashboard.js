// API Configuration
const API = '/api';
let token = localStorage.getItem('nexus_token');
if (!token) {
  window.location.href = 'login.html';
}

// API Helper
const api = async (path, opts = {}) => {
  try {
    const response = await fetch(API + path, {
      ...opts,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...opts.headers
      }
    });
    
    if (response.status === 401) {
      localStorage.clear();
      window.location.href = 'login.html';
      return;
    }
    
    return await response.json();
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
};

// Load User Info
const user = JSON.parse(localStorage.getItem('nexus_user') || '{}');
document.getElementById('userName').textContent = user.name || user.email || 'User';
document.getElementById('userPlan').textContent = (user.plan || 'free').toUpperCase();
document.getElementById('userAvatar').textContent = (user.name || user.email || 'U')[0].toUpperCase();

// Navigation
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;
    showPage(page);
  });
});

function showPage(page) {
  // Hide all pages
  document.querySelectorAll('[id^="page-"]').forEach(p => {
    p.style.display = 'none';
  });
  
  // Show selected page
  document.getElementById(`page-${page}`).style.display = 'block';
  
  // Update nav
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelector(`[data-page="${page}"]`).classList.add('active');
  
  // Update title
  const titles = {
    overview: 'Overview',
    domains: 'Domains',
    scans: 'Security Scans',
    vulnerabilities: 'Vulnerabilities',
    reports: 'Reports',
    compliance: 'Compliance',
    settings: 'Settings'
  };
  document.getElementById('pageTitle').textContent = titles[page];
  
  // Load page data
  if (page === 'overview') loadOverview();
  if (page === 'domains') loadDomains();
  if (page === 'scans') loadScans();
  if (page === 'vulnerabilities') loadVulnerabilities();
  if (page === 'reports') loadReports();
  if (page === 'settings') loadSettings();
}

// OVERVIEW PAGE
async function loadOverview() {
  try {
    // Load stats
    const overview = await api('/analytics/overview');
    document.getElementById('totalDomains').textContent = overview.domains || 0;
    document.getElementById('totalScans').textContent = overview.scans || 0;
    document.getElementById('totalCritical').textContent = overview.critical || 0;
    document.getElementById('avgScore').textContent = Math.round(overview.average_security_score || 0);
    
    // Update badges
    document.getElementById('scanBadge').textContent = overview.running_scans || 0;
    document.getElementById('vulnBadge').textContent = overview.critical || 0;
    
    // Load recent scans
    const scans = await api('/scans/list?limit=5');
    const tbody = document.getElementById('recentScansBody');
    
    if (scans.scans && scans.scans.length > 0) {
      tbody.innerHTML = scans.scans.map(scan => `
        <tr>
          <td><strong>${scan.domain_url || 'Unknown'}</strong></td>
          <td><span class="badge badge-${getStatusClass(scan.status)}">${scan.status}</span></td>
          <td>
            ${scan.critical_count || 0} critical, 
            ${scan.high_count || 0} high, 
            ${scan.medium_count || 0} medium
          </td>
          <td><strong>${scan.security_score || '—'}</strong></td>
          <td>${formatDate(scan.started_at)}</td>
          <td>
            ${scan.status === 'completed' ? 
              `<button class="btn btn-sm btn-secondary" onclick="downloadReport(${scan.id})">
                <i class="fa-solid fa-download"></i> PDF
              </button>` : 
              `<span class="badge badge-info">Running...</span>`
            }
          </td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = `
        <tr><td colspan="6">
          <div class="empty-state">
            <i class="fa-solid fa-inbox"></i>
            <div>No scans yet</div>
            <button class="btn btn-primary btn-sm" onclick="showModal('newScan')" style="margin-top:1rem">
              <i class="fa-solid fa-plus"></i> Start First Scan
            </button>
          </div>
        </td></tr>
      `;
    }
    
    // Load domains for scan modal
    const domains = await api('/domains');
    const select = document.getElementById('scanDomainSelect');
    if (domains.domains && domains.domains.length > 0) {
      select.innerHTML = `<option value="">Choose a domain...</option>` +
        domains.domains.map(d => `<option value="${d.id}">${d.name || d.url}</option>`).join('');
    } else {
      select.innerHTML = `<option value="">No domains - Add one first</option>`;
    }
  } catch (error) {
    console.error('Error loading overview:', error);
  }
}

// DOMAINS PAGE
async function loadDomains() {
  try {
    const data = await api('/domains');
    const tbody = document.getElementById('domainsBody');
    
    if (data.domains && data.domains.length > 0) {
      tbody.innerHTML = data.domains.map(domain => `
        <tr>
          <td>
            <div style="display:flex;align-items:center;gap:.5rem">
              <i class="fa-solid fa-globe" style="color:var(--primary)"></i>
              <div>
                <div style="font-weight:600">${domain.name || domain.url}</div>
                <div style="font-size:.85rem;color:var(--text-muted)">${domain.url}</div>
              </div>
            </div>
          </td>
          <td>
            ${domain.security_score ? 
              `<strong style="color:${getScoreColor(domain.security_score)}">${domain.security_score}</strong>` : 
              '<span style="color:var(--text-muted)">Not scanned</span>'
            }
          </td>
          <td>${formatDate(domain.last_scan_at) || 'Never'}</td>
          <td>
            ${domain.last_scan_at ? 
              '<span class="badge badge-success">Active</span>' : 
              '<span class="badge badge-warning">Pending</span>'
            }
          </td>
          <td>
            <button class="btn btn-sm btn-primary" onclick="scanDomain(${domain.id})">
              <i class="fa-solid fa-magnifying-glass"></i> Scan Now
            </button>
            <button class="btn btn-sm btn-secondary" onclick="deleteDomain(${domain.id})">
              <i class="fa-solid fa-trash"></i>
            </button>
          </td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = `
        <tr><td colspan="5">
          <div class="empty-state">
            <i class="fa-solid fa-globe"></i>
            <div>No domains yet</div>
            <button class="btn btn-primary btn-sm" onclick="showModal('addDomain')" style="margin-top:1rem">
              <i class="fa-solid fa-plus"></i> Add Your First Domain
            </button>
          </div>
        </td></tr>
      `;
    }
  } catch (error) {
    console.error('Error loading domains:', error);
  }
}

// SCANS PAGE
async function loadScans() {
  try {
    const data = await api('/scans/list');
    const tbody = document.getElementById('scansBody');
    
    if (data.scans && data.scans.length > 0) {
      tbody.innerHTML = data.scans.map(scan => `
        <tr>
          <td><strong>${scan.domain_url || 'Unknown'}</strong></td>
          <td><span class="badge badge-${getStatusClass(scan.status)}">${scan.status}</span></td>
          <td>
            <span class="badge badge-danger">${scan.critical_count || 0} Critical</span>
            <span class="badge badge-warning">${scan.high_count || 0} High</span>
          </td>
          <td>${scan.security_score || '—'}</td>
          <td>${formatDate(scan.started_at)}</td>
          <td>${formatDate(scan.completed_at) || '—'}</td>
          <td>
            ${scan.status === 'completed' ? 
              `<button class="btn btn-sm btn-secondary" onclick="downloadReport(${scan.id})">
                <i class="fa-solid fa-file-pdf"></i>
              </button>` : 
              '<span class="badge badge-info">In Progress</span>'
            }
          </td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = `
        <tr><td colspan="7">
          <div class="empty-state">
            <i class="fa-solid fa-magnifying-glass-chart"></i>
            <div>No scans yet</div>
          </div>
        </td></tr>
      `;
    }
  } catch (error) {
    console.error('Error loading scans:', error);
  }
}

// VULNERABILITIES PAGE
async function loadVulnerabilities() {
  try {
    // Get latest scan and its vulnerabilities
    const scans = await api('/scans/list?limit=1');
    const tbody = document.getElementById('vulnBody');
    
    if (scans.scans && scans.scans.length > 0 && scans.scans[0].total_vulns > 0) {
      const scanId = scans.scans[0].id;
      // Note: We'd need a vulnerabilities endpoint, but for now show message
      tbody.innerHTML = `
        <tr><td colspan="6">
          <div class="empty-state">
            <i class="fa-solid fa-bug"></i>
            <div>Vulnerability details available in scan reports</div>
            <button class="btn btn-primary btn-sm" onclick="downloadReport(${scanId})" style="margin-top:1rem">
              <i class="fa-solid fa-download"></i> Download Report
            </button>
          </div>
        </td></tr>
      `;
    } else {
      tbody.innerHTML = `
        <tr><td colspan="6">
          <div class="empty-state">
            <i class="fa-solid fa-shield-check"></i>
            <div style="color:var(--success);font-size:1.1rem;font-weight:600">No vulnerabilities found!</div>
            <div>Your domains are secure</div>
          </div>
        </td></tr>
      `;
    }
  } catch (error) {
    console.error('Error loading vulnerabilities:', error);
  }
}

// REPORTS PAGE
async function loadReports() {
  try {
    const scans = await api('/scans/list');
    const content = document.getElementById('reportsContent');
    
    if (scans.scans && scans.scans.length > 0) {
      const completedScans = scans.scans.filter(s => s.status === 'completed');
      
      if (completedScans.length > 0) {
        content.innerHTML = `
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Scan Date</th>
                  <th>Score</th>
                  <th>Vulnerabilities</th>
                  <th>Download</th>
                </tr>
              </thead>
              <tbody>
                ${completedScans.map(scan => `
                  <tr>
                    <td><strong>${scan.domain_url}</strong></td>
                    <td>${formatDate(scan.completed_at)}</td>
                    <td>${scan.security_score || '—'}</td>
                    <td>${scan.total_vulns || 0}</td>
                    <td>
                      <button class="btn btn-sm btn-primary" onclick="downloadReport(${scan.id}, 'pdf')">
                        <i class="fa-solid fa-file-pdf"></i> PDF
                      </button>
                      <button class="btn btn-sm btn-secondary" onclick="downloadReport(${scan.id}, 'csv')">
                        <i class="fa-solid fa-file-csv"></i> CSV
                      </button>
                      <button class="btn btn-sm btn-secondary" onclick="downloadReport(${scan.id}, 'json')">
                        <i class="fa-solid fa-file-code"></i> JSON
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `;
      } else {
        content.innerHTML = `
          <div class="empty-state">
            <i class="fa-solid fa-file-pdf"></i>
            <div>No completed scans yet</div>
          </div>
        `;
      }
    } else {
      content.innerHTML = `
        <div class="empty-state">
          <i class="fa-solid fa-inbox"></i>
          <div>No reports available</div>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error loading reports:', error);
  }
}

// SETTINGS PAGE
async function loadSettings() {
  try {
    const profile = await api('/auth/profile');
    if (profile.user) {
      document.getElementById('settingsName').value = profile.user.name || '';
      document.getElementById('settingsEmail').value = profile.user.email || '';
    }
  } catch (error) {
    console.error('Error loading settings:', error);
  }
}

// MODALS
function showModal(name) {
  document.getElementById(`${name}Modal`).classList.add('open');
}

function closeModal(name) {
  document.getElementById(`${name}Modal`).classList.remove('open');
}

// FORMS
document.getElementById('addDomainForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const url = document.getElementById('domainUrl').value;
  const name = document.getElementById('domainName').value;
  
  try {
    await api('/domains', {
      method: 'POST',
      body: JSON.stringify({ url, name: name || url })
    });
    
    closeModal('addDomain');
    alert('Domain added successfully!');
    loadDomains();
    loadOverview();
    
    // Reset form
    document.getElementById('addDomainForm').reset();
  } catch (error) {
    alert('Error adding domain: ' + error.message);
  }
});

document.getElementById('newScanForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const domainId = document.getElementById('scanDomainSelect').value;
  
  if (!domainId) {
    alert('Please select a domain');
    return;
  }
  
  try {
    await api('/scans/start', {
      method: 'POST',
      body: JSON.stringify({ domain_id: parseInt(domainId) })
    });
    
    closeModal('newScan');
    alert('Scan started! It will take about 1-2 minutes to complete.');
    
    // Refresh data
    setTimeout(() => {
      loadOverview();
      loadScans();
    }, 2000);
  } catch (error) {
    alert('Error starting scan: ' + error.message);
  }
});

// ACTIONS
async function scanDomain(domainId) {
  if (confirm('Start a new security scan for this domain?')) {
    try {
      await api('/scans/start', {
        method: 'POST',
        body: JSON.stringify({ domain_id: domainId })
      });
      alert('Scan started!');
      loadOverview();
    } catch (error) {
      alert('Error: ' + error.message);
    }
  }
}

async function deleteDomain(domainId) {
  if (confirm('Are you sure you want to delete this domain?')) {
    try {
      await api(`/domains/${domainId}`, { method: 'DELETE' });
      alert('Domain deleted');
      loadDomains();
      loadOverview();
    } catch (error) {
      alert('Error: ' + error.message);
    }
  }
}

function downloadReport(scanId, format = 'pdf') {
  window.open(`/api/reports/${scanId}/${format}`, '_blank');
}

async function updateProfile() {
  const name = document.getElementById('settingsName').value;
  
  try {
    await api('/auth/profile', {
      method: 'PUT',
      body: JSON.stringify({ name })
    });
    alert('Profile updated!');
    
    // Update local storage
    const user = JSON.parse(localStorage.getItem('nexus_user'));
    user.name = name;
    localStorage.setItem('nexus_user', JSON.stringify(user));
    
    // Update UI
    document.getElementById('userName').textContent = name;
  } catch (error) {
    alert('Error: ' + error.message);
  }
}

async function changePassword() {
  const current = document.getElementById('currentPassword').value;
  const newPass = document.getElementById('newPassword').value;
  
  if (!current || !newPass) {
    alert('Please fill in both password fields');
    return;
  }
  
  if (newPass.length < 8) {
    alert('New password must be at least 8 characters');
    return;
  }
  
  try {
    await api('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ 
        currentPassword: current,
        newPassword: newPass
      })
    });
    alert('Password updated successfully!');
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
  } catch (error) {
    alert('Error: ' + error.message);
  }
}

// HELPERS
function getStatusClass(status) {
  const map = {
    completed: 'success',
    running: 'info',
    pending: 'warning',
    failed: 'danger'
  };
  return map[status] || 'info';
}

function getScoreColor(score) {
  if (score >= 800) return 'var(--success)';
  if (score >= 600) return 'var(--warning)';
  return 'var(--danger)';
}

function formatDate(timestamp) {
  if (!timestamp) return null;
  const date = new Date(timestamp * 1000);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

// AUTO REFRESH
setInterval(() => {
  const currentPage = document.querySelector('.nav-item.active')?.dataset.page;
  if (currentPage === 'overview') loadOverview();
}, 10000);

// INIT
loadOverview();
