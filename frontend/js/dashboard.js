/**
 * WEBSECURITY SAAS PRO v2.0
 * Dashboard Ultra-Avancé avec fonctionnalités innovantes
 */

class Dashboard {
  constructor() {
    this.user = null;
    this.currentPage = 'overview';
    this.charts = {};
    this.refreshIntervals = {};
    this.scanPolling = {};
    this.init();
  }

  async init() {
    if (!this.checkAuth()) {
      window.location.href = 'login.html';
      return;
    }

    await this.loadUser();
    this.initUI();
    this.initNavigation();
    await this.loadPage('overview');
    this.startGlobalRefresh();
  }

  // === AUTH ===
  checkAuth() {
    return !!localStorage.getItem(CONFIG.STORAGE_KEYS.TOKEN);
  }

  async loadUser() {
    try {
      const response = await api.get(CONFIG.ENDPOINTS.AUTH.ME);
      this.user = response.user;
      document.getElementById('userEmail').textContent = this.user.email;
    } catch (error) {
      this.logout();
    }
  }

  logout() {
    localStorage.clear();
    window.location.href = 'login.html';
  }

  // === UI INIT ===
  initUI() {
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    const mobileToggle = document.getElementById('mobileToggle');

    if (sidebarToggle) {
      sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar_collapsed', sidebar.classList.contains('collapsed'));
      });

      // Restore sidebar state
      if (localStorage.getItem('sidebar_collapsed') === 'true') {
        sidebar.classList.add('collapsed');
      }
    }

    if (mobileToggle) {
      mobileToggle.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
      });
    }

    const userButton = document.getElementById('userButton');
    const userDropdown = document.getElementById('userDropdown');
    if (userButton) {
      userButton.addEventListener('click', (e) => {
        e.stopPropagation();
        userDropdown.classList.toggle('show');
      });
      document.addEventListener('click', () => userDropdown.classList.remove('show'));
    }

    lucide.createIcons();
  }

  initNavigation() {
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
      item.addEventListener('click', async (e) => {
        e.preventDefault();
        const page = item.dataset.page;
        
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        await this.loadPage(page);
      });
    });

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', (e) => {
        e.preventDefault();
        this.logout();
      });
    }
  }

  startGlobalRefresh() {
    // Refresh alerts every 30s
    this.refreshIntervals.alerts = setInterval(() => {
      this.updateNotificationBadge();
    }, 30000);
  }

  async updateNotificationBadge() {
    try {
      const summary = await api.get(CONFIG.ENDPOINTS.ANALYTICS.ALERTS);
      const badge = document.querySelector('.btn-icon .badge');
      if (badge && summary.unread) {
        badge.textContent = summary.unread;
        badge.style.display = summary.unread > 0 ? 'block' : 'none';
      }
    } catch (error) {
      console.error('Failed to update notification badge:', error);
    }
  }

  // === PAGE LOADING ===
  async loadPage(pageName) {
    this.currentPage = pageName;
    this.stopRefresh();

    const container = document.getElementById('pageContainer');
    container.innerHTML = '<div class="loading-state"><div class="spinner"></div><p>Chargement...</p></div>';

    try {
      const methodName = `render${this.capitalize(pageName)}Page`;
      if (typeof this[methodName] === 'function') {
        container.innerHTML = await this[methodName]();
        lucide.createIcons();
        
        const initMethod = `init${this.capitalize(pageName)}`;
        if (typeof this[initMethod] === 'function') {
          await this[initMethod]();
        }
      } else {
        container.innerHTML = '<div class="empty-state"><i data-lucide="construction"></i><p>Page en construction</p></div>';
        lucide.createIcons();
      }
    } catch (error) {
      console.error('Page load error:', error);
      container.innerHTML = `
        <div class="error-state">
          <i data-lucide="alert-circle"></i>
          <h3>Erreur de chargement</h3>
          <p>${error.message}</p>
          <button class="btn btn-primary" onclick="dashboard.loadPage('${pageName}')">
            <i data-lucide="refresh-cw"></i>
            <span>Réessayer</span>
          </button>
        </div>
      `;
      lucide.createIcons();
    }
  }

  // === OVERVIEW PAGE - ULTRA ENHANCED ===
  async renderOverviewPage() {
    let analytics = { stats: {}, trends: [] };
    let domains = { domains: [] };
    let scans = { scans: [] };
    let topVulns = { vulnerabilities: [] };
    let benchmark = { user: {}, industry: {} };

    try {
      [analytics, domains, scans, topVulns, benchmark] = await Promise.all([
        api.get(CONFIG.ENDPOINTS.ANALYTICS.OVERVIEW).catch(() => ({ stats: {}, trends: [] })),
        api.get(CONFIG.ENDPOINTS.DOMAINS.LIST).catch(() => ({ domains: [] })),
        api.get(CONFIG.ENDPOINTS.SCANS.LIST + '?limit=5').catch(() => ({ scans: [] })),
        api.get(CONFIG.ENDPOINTS.ANALYTICS.TOP_VULNS + '?limit=5').catch(() => ({ vulnerabilities: [] })),
        api.get(CONFIG.ENDPOINTS.ANALYTICS.BENCHMARK).catch(() => ({ user: {}, industry: {} }))
      ]);
    } catch (e) {
      console.warn('Overview data fetch error:', e);
    }

    const stats = analytics.stats || {};
    const vulnStats = stats.vulnerabilities || { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    const domainStats = stats.domains || { total: 0, avg_score: 0 };
    const scanStats = stats.scans || { total: 0, last_30_days: 0 };
    
    const score = Math.round(domainStats.avg_score || utils.calculateSecurityScore(vulnStats));
    const scoreLabel = utils.getScoreLabel(score);
    const scoreColor = utils.getScoreColor(score);

    return `
      <!-- Global Score Hero -->
      <div class="card" style="background: linear-gradient(135deg, #1e293b, #0f172a); border-color: ${scoreColor}40; margin-bottom: 2rem;">
        <div class="card-body" style="padding: 2rem;">
          <div style="display: grid; grid-template-columns: auto 1fr; gap: 2rem; align-items: center;">
            <div style="text-align: center;">
              <div style="width: 140px; height: 140px; position: relative; margin: 0 auto;">
                <svg viewBox="0 0 100 100" style="transform: rotate(-90deg);">
                  <circle cx="50" cy="50" r="40" fill="none" stroke="#334155" stroke-width="8"/>
                  <circle cx="50" cy="50" r="40" fill="none" stroke="${scoreColor}" stroke-width="8"
                          stroke-dasharray="${score * 2.51} 251" stroke-linecap="round"
                          style="transition: stroke-dasharray 1s ease;"/>
                </svg>
                <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center;">
                  <div style="font-size: 2.5rem; font-weight: 800; color: ${scoreColor};">${score}</div>
                  <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em;">${scoreLabel}</div>
                </div>
              </div>
            </div>
            <div>
              <h2 style="font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem;">
                Score de Sécurité Globale
              </h2>
              <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                Votre posture de sécurité est <strong style="color: ${scoreColor};">${scoreLabel.toLowerCase()}</strong>.
                ${score < 70 ? 'Des actions sont recommandées pour améliorer votre score.' : 'Continuez à maintenir ce niveau de sécurité !'}
              </p>
              <div style="display: flex; gap: 2rem;">
                <div>
                  <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.25rem;">Domaines</div>
                  <div style="font-size: 1.5rem; font-weight: 700;">${domainStats.total || 0}</div>
                </div>
                <div>
                  <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.25rem;">Scans (30j)</div>
                  <div style="font-size: 1.5rem; font-weight: 700;">${scanStats.last_30_days || 0}</div>
                </div>
                <div>
                  <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.25rem;">Vulnérabilités</div>
                  <div style="font-size: 1.5rem; font-weight: 700; color: var(--danger);">${vulnStats.total || 0}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="page-header">
        <div>
          <h1 class="page-title">Tableau de Bord</h1>
          <p class="page-subtitle">Vue d'ensemble de votre sécurité</p>
        </div>
        <button class="btn btn-primary" onclick="dashboard.openAddDomainModal()">
          <i data-lucide="plus"></i>
          <span>Ajouter un domaine</span>
        </button>
      </div>

      <!-- KPIs Enhanced -->
      <div class="kpi-grid">
        <div class="kpi-card">
          <div class="kpi-header">
            <div class="kpi-icon" style="background: linear-gradient(135deg, #ef4444, #dc2626);">
              <i data-lucide="alert-triangle"></i>
            </div>
          </div>
          <div class="kpi-body">
            <div class="kpi-value text-danger">${vulnStats.critical || 0}</div>
            <div class="kpi-label">Critiques</div>
            <div class="kpi-sublabel">Action immédiate requise</div>
            ${vulnStats.critical > 0 ? `
              <div style="margin-top: 1rem;">
                <button class="btn btn-sm btn-danger" onclick="dashboard.loadPage('vulnerabilities')" style="width: 100%;">
                  <i data-lucide="shield-alert"></i>
                  <span>Voir les détails</span>
                </button>
              </div>
            ` : ''}
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <div class="kpi-icon" style="background: linear-gradient(135deg, #f59e0b, #d97706);">
              <i data-lucide="alert-octagon"></i>
            </div>
          </div>
          <div class="kpi-body">
            <div class="kpi-value" style="color: #f59e0b;">${vulnStats.high || 0}</div>
            <div class="kpi-label">Élevées</div>
            <div class="kpi-sublabel">Correction prioritaire</div>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <div class="kpi-icon" style="background: linear-gradient(135deg, #eab308, #ca8a04);">
              <i data-lucide="alert-circle"></i>
            </div>
          </div>
          <div class="kpi-body">
            <div class="kpi-value" style="color: #eab308;">${vulnStats.medium || 0}</div>
            <div class="kpi-label">Moyennes</div>
            <div class="kpi-sublabel">À traiter rapidement</div>
          </div>
        </div>

        <div class="kpi-card">
          <div class="kpi-header">
            <div class="kpi-icon" style="background: linear-gradient(135deg, #06b6d4, #0891b2);">
              <i data-lucide="info"></i>
            </div>
          </div>
          <div class="kpi-body">
            <div class="kpi-value" style="color: #06b6d4;">${vulnStats.low || 0}</div>
            <div class="kpi-label">Faibles</div>
            <div class="kpi-sublabel">Surveillance continue</div>
          </div>
        </div>
      </div>

      <div class="grid grid-2">
        <!-- Vulnerability Trend Chart -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="trending-up"></i>
              Évolution des Vulnérabilités
            </h3>
          </div>
          <div class="card-body">
            <canvas id="trendChart" height="250"></canvas>
          </div>
        </div>

        <!-- Vulnerability Distribution -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="pie-chart"></i>
              Répartition par Sévérité
            </h3>
          </div>
          <div class="card-body">
            <canvas id="vulnChart" height="250"></canvas>
          </div>
        </div>
      </div>

      <!-- Top Vulnerabilities -->
      ${topVulns.vulnerabilities && topVulns.vulnerabilities.length > 0 ? `
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="flame"></i>
              Top 5 Vulnérabilités Critiques
            </h3>
            <button class="btn btn-sm btn-secondary" onclick="dashboard.loadPage('vulnerabilities')">
              <span>Voir tout</span>
              <i data-lucide="arrow-right"></i>
            </button>
          </div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table">
                <thead>
                  <tr>
                    <th>Sévérité</th>
                    <th>Vulnérabilité</th>
                    <th>Domaine</th>
                    <th>CVSS</th>
                    <th>Découverte</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${topVulns.vulnerabilities.map(v => `
                    <tr>
                      <td>
                        <span class="badge" style="background: ${CONFIG.SEVERITY_COLORS[v.severity]};">
                          ${v.severity.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <strong>${utils.truncate(v.title, 50)}</strong>
                        <div style="font-size: 0.75rem; color: var(--text-secondary);">
                          ${v.category}
                        </div>
                      </td>
                      <td>${utils.truncate(v.domain_url, 30)}</td>
                      <td>
                        <strong style="color: ${utils.getScoreColor(100 - (v.cvss_score * 10))};">
                          ${v.cvss_score?.toFixed(1) || 'N/A'}
                        </strong>
                      </td>
                      <td>${utils.formatRelativeTime(v.discovered_at)}</td>
                      <td>
                        <button class="btn btn-sm btn-primary" onclick="dashboard.viewVulnerability(${v.id})">
                          <i data-lucide="eye"></i>
                        </button>
                      </td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ` : ''}

      <div class="grid grid-2">
        <!-- Recent Domains -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="globe"></i>
              Domaines Récents
            </h3>
            <button class="btn btn-sm btn-primary" onclick="dashboard.openAddDomainModal()">
              <i data-lucide="plus"></i>
              <span>Ajouter</span>
            </button>
          </div>
          <div class="card-body">
            ${domains.domains && domains.domains.length > 0 ? `
              <div class="list-group">
                ${domains.domains.slice(0, 5).map(d => {
                  const riskConfig = CONFIG.RISK_LEVELS[d.risk_level] || CONFIG.RISK_LEVELS.low;
                  return `
                    <div class="list-item">
                      <div class="list-item-content">
                        <div class="list-item-title">${d.url}</div>
                        <div class="list-item-subtitle">
                          Score: <strong style="color: ${utils.getScoreColor(d.security_score)};">${d.security_score}</strong>
                          · Risque: <span style="color: ${riskConfig.color};">${riskConfig.label}</span>
                          · ${utils.formatRelativeTime(d.created_at)}
                        </div>
                      </div>
                      <div class="list-item-actions">
                        <button class="btn btn-sm btn-primary" onclick="dashboard.startScan(${d.id})" title="Lancer un scan">
                          <i data-lucide="scan"></i>
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="dashboard.viewDomainDetails(${d.id})" title="Détails">
                          <i data-lucide="eye"></i>
                        </button>
                      </div>
                    </div>
                  `;
                }).join('')}
              </div>
            ` : `
              <div class="empty-state">
                <i data-lucide="globe"></i>
                <p>Aucun domaine configuré</p>
                <button class="btn btn-primary" onclick="dashboard.openAddDomainModal()">
                  <i data-lucide="plus"></i>
                  <span>Ajouter un domaine</span>
                </button>
              </div>
            `}
          </div>
        </div>

        <!-- Recent Scans -->
        <div class="card">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="activity"></i>
              Scans Récents
            </h3>
            <button class="btn btn-sm btn-secondary" onclick="dashboard.loadPage('scans')">
              <span>Historique</span>
              <i data-lucide="arrow-right"></i>
            </button>
          </div>
          <div class="card-body">
            ${scans.scans && scans.scans.length > 0 ? `
              <div class="list-group">
                ${scans.scans.map(s => {
                  const status = CONFIG.SCAN_STATUS[s.status] || CONFIG.SCAN_STATUS.pending;
                  return `
                    <div class="list-item">
                      <div class="list-item-content">
                        <div class="list-item-title">${utils.truncate(s.domain_url, 40)}</div>
                        <div class="list-item-subtitle">
                          ${utils.formatRelativeTime(s.started_at)}
                          ${s.status === 'running' ? `· Progression: ${s.progress}%` : ''}
                          ${s.status === 'completed' ? `· Score: ${s.security_score} · ${s.vulnerabilities_found} vulns` : ''}
                        </div>
                      </div>
                      <span class="badge" style="background: ${status.color};">
                        <i data-lucide="${status.icon}"></i>
                        ${status.label}
                      </span>
                    </div>
                  `;
                }).join('')}
              </div>
            ` : `
              <div class="empty-state">
                <i data-lucide="scan"></i>
                <p>Aucun scan effectué</p>
              </div>
            `}
          </div>
        </div>
      </div>

      <!-- Benchmark Comparison -->
      ${benchmark.industry.avg_score ? `
        <div class="card" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
          <div class="card-header">
            <h3 class="card-title">
              <i data-lucide="bar-chart-3"></i>
              Comparaison Industrie
            </h3>
          </div>
          <div class="card-body">
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 2rem; text-align: center;">
              <div>
                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.5rem;">Votre Score</div>
                <div style="font-size: 2rem; font-weight: 800; color: ${utils.getScoreColor(benchmark.user.avg_score)};">
                  ${Math.round(benchmark.user.avg_score || 0)}
                </div>
              </div>
              <div>
                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.5rem;">Moyenne Industrie</div>
                <div style="font-size: 2rem; font-weight: 800; color: var(--text-secondary);">
                  ${Math.round(benchmark.industry.avg_score)}
                </div>
              </div>
              <div>
                <div style="font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 0.5rem;">Percentile</div>
                <div style="font-size: 2rem; font-weight: 800; color: var(--primary);">
                  ${Math.round(benchmark.industry.percentile)}%
                </div>
              </div>
            </div>
          </div>
        </div>
      ` : ''}
    `;
  }

  async initOverview() {
    await this.createCharts();
    this.startAutoRefresh('overview');
  }

  async createCharts() {
    try {
      const analytics = await api.get(CONFIG.ENDPOINTS.ANALYTICS.OVERVIEW);
      
      // Vulnerability Distribution Pie Chart
      if (document.getElementById('vulnChart')) {
        const vulnStats = analytics.stats?.vulnerabilities || {};
        this.charts.vulnChart = new Chart(document.getElementById('vulnChart'), {
          type: 'doughnut',
          data: {
            labels: ['Critiques', 'Élevées', 'Moyennes', 'Faibles'],
            datasets: [{
              data: [
                vulnStats.critical || 0,
                vulnStats.high || 0,
                vulnStats.medium || 0,
                vulnStats.low || 0
              ],
              backgroundColor: [
                CONFIG.SEVERITY_COLORS.critical,
                CONFIG.SEVERITY_COLORS.high,
                CONFIG.SEVERITY_COLORS.medium,
                CONFIG.SEVERITY_COLORS.low
              ],
              borderWidth: 0
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: '#94a3b8', padding: 15, font: { size: 12 } }
              }
            }
          }
        });
      }

      // Trend Line Chart
      if (document.getElementById('trendChart') && analytics.trends) {
        const sortedTrends = [...analytics.trends].reverse();
        this.charts.trendChart = new Chart(document.getElementById('trendChart'), {
          type: 'line',
          data: {
            labels: sortedTrends.map(t => new Date(t.date).toLocaleDateString('fr-FR', { month: 'short', day: 'numeric' })),
            datasets: [
              {
                label: 'Critiques',
                data: sortedTrends.map(t => t.critical || 0),
                borderColor: CONFIG.SEVERITY_COLORS.critical,
                backgroundColor: CONFIG.SEVERITY_COLORS.critical + '20',
                fill: true,
                tension: 0.4
              },
              {
                label: 'Élevées',
                data: sortedTrends.map(t => t.high || 0),
                borderColor: CONFIG.SEVERITY_COLORS.high,
                backgroundColor: CONFIG.SEVERITY_COLORS.high + '20',
                fill: true,
                tension: 0.4
              },
              {
                label: 'Moyennes',
                data: sortedTrends.map(t => t.medium || 0),
                borderColor: CONFIG.SEVERITY_COLORS.medium,
                backgroundColor: CONFIG.SEVERITY_COLORS.medium + '20',
                fill: true,
                tension: 0.4
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: { color: '#94a3b8', padding: 15, font: { size: 12 } }
              }
            },
            scales: {
              y: {
                beginAtZero: true,
                ticks: { color: '#94a3b8' },
                grid: { color: '#334155' }
              },
              x: {
                ticks: { color: '#94a3b8' },
                grid: { color: '#334155' }
              }
            }
          }
        });
      }
    } catch (error) {
      console.error('Chart creation error:', error);
    }
  }

  // === DOMAINS PAGE ===
  async renderDomainsPage() {
    let domains = { domains: [] };
    
    try {
      domains = await api.get(CONFIG.ENDPOINTS.DOMAINS.LIST);
    } catch (e) {
      console.warn('Domains error:', e);
    }

    return `
      <div class="page-header">
        <div>
          <h1 class="page-title">Gestion des Domaines</h1>
          <p class="page-subtitle">${domains.domains?.length || 0} domaine(s) sous surveillance</p>
        </div>
        <button class="btn btn-primary" onclick="dashboard.openAddDomainModal()">
          <i data-lucide="plus"></i>
          <span>Ajouter un domaine</span>
        </button>
      </div>

      ${domains.domains && domains.domains.length > 0 ? `
        <div class="grid grid-3">
          ${domains.domains.map(d => {
            const riskConfig = CONFIG.RISK_LEVELS[d.risk_level] || CONFIG.RISK_LEVELS.low;
            const scoreColor = utils.getScoreColor(d.security_score);
            return `
              <div class="card">
                <div class="card-header">
                  <div style="display: flex; align-items: center; gap: 0.5rem; flex: 1; min-width: 0;">
                    <i data-lucide="globe" style="width: 20px; height: 20px; flex-shrink: 0;"></i>
                    <h3 class="card-title" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${d.url}">
                      ${d.url.replace(/^https?:\/\//, '').replace(/\/$/, '')}
                    </h3>
                  </div>
                  <span class="badge" style="background: ${riskConfig.color};">
                    ${riskConfig.label}
                  </span>
                </div>
                <div class="card-body">
                  <div style="text-align: center; margin-bottom: 1.5rem;">
                    <div style="font-size: 3rem; font-weight: 800; color: ${scoreColor}; margin-bottom: 0.25rem;">
                      ${d.security_score}
                    </div>
                    <div style="font-size: 0.875rem; color: var(--text-secondary);">
                      Score de sécurité
                    </div>
                  </div>

                  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
                    <div style="text-align: center; padding: 0.75rem; background: var(--bg-darker); border-radius: 0.5rem;">
                      <div style="font-size: 1.5rem; font-weight: 700;">${d.total_scans || 0}</div>
                      <div style="font-size: 0.75rem; color: var(--text-secondary);">Scans</div>
                    </div>
                    <div style="text-align: center; padding: 0.75rem; background: var(--bg-darker); border-radius: 0.5rem;">
                      <div style="font-size: 1.5rem; font-weight: 700; color: var(--danger);">${d.critical_vulns || 0}</div>
                      <div style="font-size: 0.75rem; color: var(--text-secondary);">Critiques</div>
                    </div>
                  </div>

                  <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 1rem;">
                    Ajouté ${utils.formatRelativeTime(d.created_at)}
                    ${d.last_scan ? ` · Dernier scan ${utils.formatRelativeTime(d.last_scan)}` : ''}
                  </div>

                  <div class="card-actions">
                    <button class="btn btn-primary" onclick="dashboard.startScan(${d.id})" style="flex: 1;">
                      <i data-lucide="scan"></i>
                      <span>Scanner</span>
                    </button>
                    <button class="btn btn-secondary" onclick="dashboard.viewDomainDetails(${d.id})">
                      <i data-lucide="eye"></i>
                    </button>
                    <button class="btn btn-secondary" onclick="dashboard.deleteDomain(${d.id})">
                      <i data-lucide="trash-2"></i>
                    </button>
                  </div>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      ` : `
        <div class="empty-state">
          <i data-lucide="globe"></i>
          <h3>Aucun domaine configuré</h3>
          <p>Ajoutez votre premier domaine pour commencer l'analyse de sécurité</p>
          <button class="btn btn-primary" onclick="dashboard.openAddDomainModal()">
            <i data-lucide="plus"></i>
            <span>Ajouter un domaine</span>
          </button>
        </div>
      `}
    `;
  }

  // Continue dans la partie 2...
  capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  stopRefresh() {
    Object.values(this.refreshIntervals).forEach(clearInterval);
    this.refreshIntervals = {};
    Object.values(this.scanPolling).forEach(clearInterval);
    this.scanPolling = {};
    Object.values(this.charts).forEach(chart => chart?.destroy());
    this.charts = {};
  }

  startAutoRefresh(page) {
    if (page === 'overview') {
      this.refreshIntervals.overview = setInterval(() => {
        this.loadPage('overview');
      }, 60000); // Refresh every 60s
    }
  }
}

// Initialize dashboard
let dashboard;
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    dashboard = new Dashboard();
  });
} else {
  dashboard = new Dashboard();
}
