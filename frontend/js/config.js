const CONFIG = {
  API_URL: window.location.origin,
  
  ENDPOINTS: {
    AUTH: {
      LOGIN: '/api/auth/login',
      REGISTER: '/api/auth/register',
      ME: '/api/auth/me'
    },
    DOMAINS: {
      LIST: '/api/domains/list',
      ADD: '/api/domains/add',
      GET: '/api/domains',
      DELETE: '/api/domains'
    },
    SCANS: {
      LIST: '/api/scans/list',
      START: '/api/scans/start',
      GET: '/api/scans',
      PROGRESS: '/api/scans'
    },
    ANALYTICS: {
      OVERVIEW: '/api/analytics/overview',
      BREAKDOWN: '/api/analytics/vulnerabilities/breakdown',
      HISTORY: '/api/analytics/domain',
      TOP_VULNS: '/api/analytics/vulnerabilities/top',
      ALERTS: '/api/analytics/alerts/summary',
      BENCHMARK: '/api/analytics/benchmark'
    },
    REPORTS: {
      LIST: '/api/reports/list',
      GENERATE: '/api/reports/generate',
      DOWNLOAD: '/api/reports/download'
    },
    NOTIFICATIONS: {
      ALERTS: '/api/notifications/alerts',
      READ: '/api/notifications/alerts',
      READ_ALL: '/api/notifications/alerts/read-all'
    }
  },

  STORAGE_KEYS: {
    TOKEN: 'websecurity_token',
    USER: 'websecurity_user'
  },

  SCAN_STATUS: {
    pending: { label: 'En attente', color: '#94a3b8', icon: 'clock' },
    running: { label: 'En cours', color: '#3b82f6', icon: 'loader' },
    completed: { label: 'Terminé', color: '#10b981', icon: 'check-circle' },
    failed: { label: 'Échoué', color: '#ef4444', icon: 'x-circle' }
  },

  SEVERITY_COLORS: {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#eab308',
    low: '#06b6d4'
  },

  RISK_LEVELS: {
    critical: { label: 'Critique', color: '#ef4444' },
    high: { label: 'Élevé', color: '#f59e0b' },
    medium: { label: 'Moyen', color: '#eab308' },
    low: { label: 'Faible', color: '#10b981' }
  }
};
