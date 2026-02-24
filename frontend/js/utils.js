const utils = {
  // Format date
  formatDate(date) {
    if (!date) return 'N/A';
    return new Date(date).toLocaleDateString('fr-FR', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  },

  // Format relative time
  formatRelativeTime(date) {
    if (!date) return 'Jamais';
    const now = new Date();
    const past = new Date(date);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'À l\'instant';
    if (diffMins < 60) return `Il y a ${diffMins} min`;
    if (diffHours < 24) return `Il y a ${diffHours}h`;
    if (diffDays < 7) return `Il y a ${diffDays}j`;
    return this.formatDate(date);
  },

  // Calculate security score
  calculateSecurityScore(vulns) {
    if (!vulns) return 100;
    const weights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3
    };
    
    let deduction = 0;
    Object.keys(weights).forEach(severity => {
      deduction += (vulns[severity] || 0) * weights[severity];
    });
    
    return Math.max(0, 100 - deduction);
  },

  // Get score color
  getScoreColor(score) {
    if (score >= 80) return '#10b981';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f59e0b';
    return '#ef4444';
  },

  // Get score label
  getScoreLabel(score) {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Bon';
    if (score >= 40) return 'Moyen';
    return 'Critique';
  },

  // Show toast notification
  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div style="flex: 1;">${message}</div>
      <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer;">
        <i data-lucide="x" style="width: 18px; height: 18px;"></i>
      </button>
    `;

    container.appendChild(toast);
    lucide.createIcons();

    setTimeout(() => {
      toast.style.animation = 'toastSlideIn 0.3s ease reverse';
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  },

  // Truncate text
  truncate(text, length = 50) {
    if (!text) return '';
    return text.length > length ? text.substring(0, length) + '...' : text;
  },

  // Escape HTML
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
};
