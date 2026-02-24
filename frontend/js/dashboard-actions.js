/**
 * DASHBOARD PARTIE 2 - Pages additionnelles et Actions
 */

// Ajouter ces méthodes à la classe Dashboard

Dashboard.prototype.renderScansPage = async function() {
  let scans = { scans: [] };
  
  try {
    scans = await api.get(CONFIG.ENDPOINTS.SCANS.LIST);
  } catch (e) {
    console.warn('Scans error:', e);
  }

  return `
    <div class="page-header">
      <div>
        <h1 class="page-title">Historique des Scans</h1>
        <p class="page-subtitle">${scans.scans?.length || 0} scan(s) effectué(s)</p>
      </div>
    </div>

    ${scans.scans && scans.scans.length > 0 ? `
      <div class="card">
        <div class="card-body">
          <div class="table-responsive">
            <table class="table">
              <thead>
                <tr>
                  <th>Domaine</th>
                  <th>Type</th>
                  <th>Statut</th>
                  <th>Progression</th>
                  <th>Score</th>
                  <th>Vulnérabilités</th>
                  <th>Date</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${scans.scans.map(s => {
                  const status = CONFIG.SCAN_STATUS[s.status] || CONFIG.SCAN_STATUS.pending;
                  const score = s.security_score || 0;
                  return `
                    <tr>
                      <td>
                        <strong>${utils.truncate(s.domain_url, 40)}</strong>
                      </td>
                      <td>
                        <span class="badge badge-secondary">
                          <i data-lucide="scan"></i>
                          ${s.scan_type || 'Full'}
                        </span>
                      </td>
                      <td>
                        <span class="badge" style="background: ${status.color};">
                          <i data-lucide="${status.icon}"></i>
                          ${status.label}
                        </span>
                      </td>
                      <td>
                        ${s.status === 'running' ? `
                          <div style="width: 100px;">
                            <div style="background: var(--bg-darker); height: 6px; border-radius: 999px; overflow: hidden;">
                              <div style="width: ${s.progress}%; height: 100%; background: var(--primary); transition: width 0.5s;"></div>
                            </div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
                              ${s.progress}%
                            </div>
                          </div>
                        ` : '-'}
                      </td>
                      <td>
                        ${s.status === 'completed' ? `
                          <span style="color: ${utils.getScoreColor(score)}; font-weight: 700;">${score}</span>
                        ` : '-'}
                      </td>
                      <td>
                        ${s.status === 'completed' ? `
                          <span class="badge" style="background: ${s.vulnerabilities_found > 10 ? 'var(--danger)' : s.vulnerabilities_found > 5 ? 'var(--warning)' : 'var(--info)'};">
                            ${s.vulnerabilities_found}
                          </span>
                        ` : '-'}
                      </td>
                      <td>${utils.formatRelativeTime(s.started_at)}</td>
                      <td>
                        <div style="display: flex; gap: 0.5rem;">
                          ${s.status === 'completed' ? `
                            <button class="btn btn-sm btn-primary" onclick="dashboard.viewScanDetails(${s.id})" title="Voir les détails">
                              <i data-lucide="eye"></i>
                            </button>
                          ` : ''}
                          ${s.status === 'running' ? `
                            <button class="btn btn-sm btn-secondary" onclick="dashboard.pollScanProgress(${s.id})" title="Actualiser">
                              <i data-lucide="refresh-cw"></i>
                            </button>
                          ` : ''}
                        </div>
                      </td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    ` : `
      <div class="empty-state">
        <i data-lucide="scan"></i>
        <h3>Aucun scan effectué</h3>
        <p>Lancez votre premier scan sur un domaine pour commencer</p>
        <button class="btn btn-primary" onclick="dashboard.loadPage('domains')">
          <i data-lucide="globe"></i>
          <span>Voir les domaines</span>
        </button>
      </div>
    `}
  `;
};

Dashboard.prototype.renderVulnerabilitiesPage = async function() {
  let topVulns = { vulnerabilities: [] };
  let breakdown = { breakdown: [] };
  
  try {
    [topVulns, breakdown] = await Promise.all([
      api.get(CONFIG.ENDPOINTS.ANALYTICS.TOP_VULNS + '?limit=50'),
      api.get(CONFIG.ENDPOINTS.ANALYTICS.BREAKDOWN)
    ]);
  } catch (e) {
    console.warn('Vulnerabilities error:', e);
  }

  // Group by severity
  const grouped = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };

  topVulns.vulnerabilities.forEach(v => {
    if (grouped[v.severity]) {
      grouped[v.severity].push(v);
    }
  });

  return `
    <div class="page-header">
      <div>
        <h1 class="page-title">Gestion des Vulnérabilités</h1>
        <p class="page-subtitle">${topVulns.vulnerabilities?.length || 0} vulnérabilité(s) active(s)</p>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="kpi-grid">
      ${Object.entries(CONFIG.SEVERITY_COLORS).map(([severity, color]) => {
        const count = grouped[severity]?.length || 0;
        const label = severity.charAt(0).toUpperCase() + severity.slice(1);
        return `
          <div class="kpi-card">
            <div class="kpi-header">
              <div class="kpi-icon" style="background: ${color};">
                <i data-lucide="shield-alert"></i>
              </div>
            </div>
            <div class="kpi-body">
              <div class="kpi-value" style="color: ${color};">${count}</div>
              <div class="kpi-label">${label}s</div>
            </div>
          </div>
        `;
      }).join('')}
    </div>

    ${topVulns.vulnerabilities && topVulns.vulnerabilities.length > 0 ? `
      <!-- Critical First -->
      ${Object.entries(grouped).map(([severity, vulns]) => {
        if (vulns.length === 0) return '';
        const color = CONFIG.SEVERITY_COLORS[severity];
        return `
          <div class="card" style="border-left: 4px solid ${color};">
            <div class="card-header">
              <h3 class="card-title" style="color: ${color};">
                <i data-lucide="alert-triangle"></i>
                Vulnérabilités ${severity.toUpperCase()} (${vulns.length})
              </h3>
            </div>
            <div class="card-body">
              <div style="display: flex; flex-direction: column; gap: 1rem;">
                ${vulns.map(v => `
                  <div class="list-item" style="border-left: 3px solid ${color};">
                    <div style="flex: 1;">
                      <div style="display: flex; align-items: start; gap: 1rem; margin-bottom: 0.75rem;">
                        <div style="flex: 1;">
                          <div style="font-weight: 700; font-size: 1.rem; margin-bottom: 0.5rem;">
                            ${v.title}
                          </div>
                          <div style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.5rem;">
                            ${v.description || 'Aucune description disponible'}
                          </div>
                          <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center;">
                            <span class="badge badge-secondary">
                              <i data-lucide="tag"></i>
                              ${v.category}
                            </span>
                            <span class="badge badge-secondary">
                              <i data-lucide="globe"></i>
                              ${utils.truncate(v.domain_url, 30)}
                            </span>
                            ${v.cvss_score ? `
                              <span class="badge" style="background: ${utils.getScoreColor(100 - (v.cvss_score * 10))};">
                                CVSS ${v.cvss_score.toFixed(1)}
                              </span>
                            ` : ''}
                            <span style="color: var(--text-secondary); font-size: 0.75rem;">
                              <i data-lucide="clock" style="width: 14px; height: 14px;"></i>
                              ${utils.formatRelativeTime(v.discovered_at)}
                            </span>
                          </div>
                        </div>
                        <div style="text-align: right; min-width: 100px;">
                          <button class="btn btn-sm btn-primary" onclick="dashboard.viewVulnerability(${v.id})" style="width: 100%;">
                            <i data-lucide="shield-check"></i>
                            <span>Corriger</span>
                          </button>
                        </div>
                      </div>
                      ${v.remediation ? `
                        <div style="background: var(--bg-darker); padding: 0.75rem; border-radius: 0.5rem; font-size: 0.875rem;">
                          <div style="font-weight: 600; margin-bottom: 0.5rem; color: var(--success);">
                            <i data-lucide="lightbulb"></i>
                            Recommandation :
                          </div>
                          ${v.remediation}
                        </div>
                      ` : ''}
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>
        `;
      }).join('')}
    ` : `
      <div class="empty-state">
        <i data-lucide="shield-check"></i>
        <h3>Aucune vulnérabilité détectée</h3>
        <p>Excellent ! Votre infrastructure est sécurisée.</p>
      </div>
    `}
  `;
};

Dashboard.prototype.renderReportsPage = async function() {
  let reports = { reports: [] };
  
  try {
    reports = await api.get(CONFIG.ENDPOINTS.REPORTS.LIST);
  } catch (e) {
    console.warn('Reports error:', e);
  }

  return `
    <div class="page-header">
      <div>
        <h1 class="page-title">Rapports de Sécurité</h1>
        <p class="page-subtitle">Générez et téléchargez vos rapports</p>
      </div>
      <button class="btn btn-primary" onclick="dashboard.generateReport()">
        <i data-lucide="file-plus"></i>
        <span>Générer un rapport</span>
      </button>
    </div>

    ${reports.reports && reports.reports.length > 0 ? `
      <div class="grid grid-3">
        ${reports.reports.map(r => `
          <div class="card">
            <div class="card-header">
              <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i data-lucide="file-text"></i>
                <h3 class="card-title">${r.title || 'Rapport'}</h3>
              </div>
            </div>
            <div class="card-body">
              <p style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 1rem;">
                Type: ${r.report_type || 'Security'}
              </p>
              <p style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 1.5rem;">
                Créé le ${utils.formatDate(r.created_at)}
              </p>
              <div class="card-actions">
                <button class="btn btn-primary" onclick="dashboard.downloadReport(${r.id})" style="flex: 1;">
                  <i data-lucide="download"></i>
                  <span>Télécharger</span>
                </button>
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    ` : `
      <div class="empty-state">
        <i data-lucide="file-text"></i>
        <h3>Aucun rapport généré</h3>
        <p>Générez votre premier rapport pour suivre l'évolution de votre sécurité</p>
        <button class="btn btn-primary" onclick="dashboard.generateReport()">
          <i data-lucide="file-plus"></i>
          <span>Générer un rapport</span>
        </button>
      </div>
    `}
  `;
};

Dashboard.prototype.renderSettingsPage = async function() {
  return `
    <div class="page-header">
      <h1 class="page-title">Paramètres</h1>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">
            <i data-lucide="user"></i>
            Profil Utilisateur
          </h3>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label>Email</label>
            <input type="email" class="form-input" value="${this.user?.email || ''}" readonly>
            <small class="form-help">L'email ne peut pas être modifié</small>
          </div>
          <div class="form-group">
            <label>Nom</label>
            <input type="text" class="form-input" value="${this.user?.name || ''}" placeholder="Votre nom">
          </div>
          <div class="form-group">
            <label>Organisation</label>
            <input type="text" class="form-input" value="${this.user?.company || ''}" placeholder="Votre entreprise">
          </div>
          <button class="btn btn-primary">
            <i data-lucide="save"></i>
            <span>Enregistrer</span>
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">
            <i data-lucide="bell"></i>
            Notifications
          </h3>
        </div>
        <div class="card-body">
          <div style="display: flex; flex-direction: column; gap: 1rem;">
            <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
              <input type="checkbox" checked>
              <span>Alertes pour nouvelles vulnérabilités critiques</span>
            </label>
            <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
              <input type="checkbox" checked>
              <span>Notification de fin de scan</span>
            </label>
            <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
              <input type="checkbox">
              <span>Rapport hebdomadaire par email</span>
            </label>
            <label style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer;">
              <input type="checkbox">
              <span>Résumé mensuel</span>
            </label>
          </div>
          <button class="btn btn-primary" style="margin-top: 1.5rem;">
            <i data-lucide="save"></i>
            <span>Enregistrer</span>
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">
            <i data-lucide="shield"></i>
            Sécurité
          </h3>
        </div>
        <div class="card-body">
          <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
            Changez votre mot de passe régulièrement pour maintenir la sécurité de votre compte.
          </p>
          <button class="btn btn-secondary">
            <i data-lucide="key"></i>
            <span>Changer le mot de passe</span>
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">
            <i data-lucide="info"></i>
            À propos
          </h3>
        </div>
        <div class="card-body">
          <div style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div>
              <strong>Version:</strong> 2.0.0
            </div>
            <div>
              <strong>Compte créé:</strong> ${utils.formatDate(this.user?.created_at)}
            </div>
            <div>
              <strong>Dernière connexion:</strong> ${utils.formatDate(this.user?.last_login)}
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
};

// === ACTIONS ===

Dashboard.prototype.openAddDomainModal = function() {
  const modal = document.getElementById('addDomainModal');
  if (modal) modal.classList.add('show');
};

Dashboard.prototype.closeAddDomainModal = function() {
  const modal = document.getElementById('addDomainModal');
  if (modal) modal.classList.remove('show');
};

Dashboard.prototype.addDomain = async function(url) {
  if (!url) {
    utils.showToast('Veuillez entrer une URL', 'error');
    return;
  }

  try {
    await api.post(CONFIG.ENDPOINTS.DOMAINS.ADD, { url });
    utils.showToast('Domaine ajouté avec succès !', 'success');
    this.closeAddDomainModal();
    await this.loadPage(this.currentPage);
  } catch (error) {
    utils.showToast(error.message || 'Erreur lors de l\'ajout du domaine', 'error');
  }
};

Dashboard.prototype.deleteDomain = async function(id) {
  if (!confirm('Êtes-vous sûr de vouloir supprimer ce domaine ? Cette action est irréversible.')) {
    return;
  }
  
  try {
    await api.delete(`${CONFIG.ENDPOINTS.DOMAINS.DELETE}/${id}`);
    utils.showToast('Domaine supprimé', 'success');
    await this.loadPage(this.currentPage);
  } catch (error) {
    utils.showToast(error.message || 'Erreur lors de la suppression', 'error');
  }
};

Dashboard.prototype.startScan = async function(domainId) {
  try {
    const result = await api.post(CONFIG.ENDPOINTS.SCANS.START, { domain_id: domainId });
    utils.showToast('Scan lancé avec succès ! Progression en temps réel...', 'success');
    
    // Start polling for this scan
    this.pollScanProgress(result.scan.id);
    
    // Redirect to scans page
    setTimeout(() => this.loadPage('scans'), 1000);
  } catch (error) {
    utils.showToast(error.message || 'Erreur lors du lancement du scan', 'error');
  }
};

Dashboard.prototype.pollScanProgress = function(scanId) {
  // Clear existing polling for this scan
  if (this.scanPolling[scanId]) {
    clearInterval(this.scanPolling[scanId]);
  }

  // Start new polling
  this.scanPolling[scanId] = setInterval(async () => {
    try {
      const scan = await api.get(`${CONFIG.ENDPOINTS.SCANS.PROGRESS}/${scanId}/progress`);
      
      // Update UI if we're on the scans page
      if (this.currentPage === 'scans') {
        const progressBar = document.querySelector(`[data-scan-id="${scanId}"] .progress-bar`);
        if (progressBar) {
          progressBar.style.width = `${scan.progress}%`;
        }
      }

      // Stop polling if completed or failed
      if (scan.status === 'completed' || scan.status === 'failed') {
        clearInterval(this.scanPolling[scanId]);
        delete this.scanPolling[scanId];
        
        if (scan.status === 'completed') {
          utils.showToast('Scan terminé avec succès !', 'success');
          this.loadPage(this.currentPage);
        } else {
          utils.showToast('Le scan a échoué', 'error');
        }
      }
    } catch (error) {
      console.error('Polling error:', error);
      clearInterval(this.scanPolling[scanId]);
      delete this.scanPolling[scanId];
    }
  }, 3000); // Poll every 3 seconds
};

Dashboard.prototype.viewScanDetails = async function(scanId) {
  try {
    const data = await api.get(`${CONFIG.ENDPOINTS.SCANS.GET}/${scanId}`);
    // TODO: Show modal with scan details
    utils.showToast('Fonctionnalité de détails en cours de développement', 'info');
  } catch (error) {
    utils.showToast('Erreur lors du chargement des détails', 'error');
  }
};

Dashboard.prototype.viewDomainDetails = async function(domainId) {
  try {
    const data = await api.get(`${CONFIG.ENDPOINTS.DOMAINS.GET}/${domainId}`);
    // TODO: Show modal with domain details and history
    utils.showToast('Fonctionnalité de détails en cours de développement', 'info');
  } catch (error) {
    utils.showToast('Erreur lors du chargement des détails', 'error');
  }
};

Dashboard.prototype.viewVulnerability = function(vulnId) {
  // TODO: Show vulnerability details modal with remediation steps
  utils.showToast('Modal de détails de vulnérabilité en cours de développement', 'info');
};

Dashboard.prototype.generateReport = async function() {
  try {
    utils.showToast('Génération du rapport en cours...', 'info');
    await api.post(CONFIG.ENDPOINTS.REPORTS.GENERATE, {
      title: `Rapport de sécurité - ${new Date().toLocaleDateString('fr-FR')}`,
      report_type: 'security'
    });
    utils.showToast('Rapport généré avec succès !', 'success');
    await this.loadPage('reports');
  } catch (error) {
    utils.showToast(error.message || 'Erreur lors de la génération du rapport', 'error');
  }
};

Dashboard.prototype.downloadReport = function(reportId) {
  window.open(`${CONFIG.API_URL}${CONFIG.ENDPOINTS.REPORTS.DOWNLOAD}/${reportId}`, '_blank');
  utils.showToast('Téléchargement du rapport...', 'info');
};
