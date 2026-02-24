/**
 * SECURE HTTP CLIENT
 * Protection contre les réponses malveillantes et attaques sur le scanner
 */

const axios = require('axios');
const { URL } = require('url');

class SecureHttpClient {
  constructor(options = {}) {
    // Configuration sécurisée par défaut
    this.config = {
      // Timeouts stricts
      timeout: options.timeout || 10000, // 10 secondes max
      connectTimeout: options.connectTimeout || 5000, // 5 secondes pour connexion
      
      // Limites de taille
      maxContentLength: options.maxContentLength || 10 * 1024 * 1024, // 10MB max
      maxBodyLength: options.maxBodyLength || 10 * 1024 * 1024,
      
      // Limites de redirections
      maxRedirects: options.maxRedirects || 5,
      
      // User agent
      headers: {
        'User-Agent': options.userAgent || 'NEXUS-Security-Scanner/2.0',
        'Accept': 'text/html,application/json,application/xml,*/*',
        'Accept-Encoding': 'gzip, deflate', // Pas br pour éviter decompression bombs
        'Connection': 'close', // Pas de keep-alive pour éviter connection exhaustion
        ...options.headers
      },
      
      // Validation SSL (configurable)
      rejectUnauthorized: options.rejectUnauthorized !== false,
      
      // Suivre redirections mais avec limite
      followRedirect: true,
      
      // Ne pas throw sur codes d'erreur HTTP
      validateStatus: () => true
    };
    
    // Blacklist d'IPs privées (protection SSRF)
    this.privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./, // Link-local
      /^::1$/, // IPv6 localhost
      /^fe80:/, // IPv6 link-local
      /^fc00:/, // IPv6 unique local
      /^fd00:/ // IPv6 unique local
    ];
    
    // Limite de requêtes concurrentes
    this.maxConcurrent = options.maxConcurrent || 5;
    this.currentRequests = 0;
  }

  /**
   * Valide une URL avant de faire la requête
   */
  validateUrl(url) {
    try {
      const parsed = new URL(url);
      
      // Protocoles autorisés seulement
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error(`Protocol not allowed: ${parsed.protocol}`);
      }
      
      // Vérifier si IP privée (protection SSRF)
      const hostname = parsed.hostname;
      
      // Check si c'est une IP directe
      if (this.isPrivateIP(hostname)) {
        throw new Error(`Private IP address not allowed: ${hostname}`);
      }
      
      // Check localhost
      if (hostname === 'localhost' || hostname.endsWith('.local')) {
        throw new Error(`Localhost not allowed: ${hostname}`);
      }
      
      return parsed;
    } catch (error) {
      throw new Error(`Invalid URL: ${error.message}`);
    }
  }

  /**
   * Vérifie si une IP est privée
   */
  isPrivateIP(hostname) {
    // Check IPv4 private ranges
    for (const range of this.privateRanges) {
      if (range.test(hostname)) {
        return true;
      }
    }
    
    // Check si c'est une IP dans les ranges interdits
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      const parts = hostname.split('.').map(Number);
      // 0.0.0.0/8
      if (parts[0] === 0) return true;
      // 224.0.0.0/4 (multicast)
      if (parts[0] >= 224) return true;
    }
    
    return false;
  }

  /**
   * Effectue une requête GET sécurisée
   */
  async get(url, options = {}) {
    return this.request('GET', url, null, options);
  }

  /**
   * Effectue une requête POST sécurisée
   */
  async post(url, data, options = {}) {
    return this.request('POST', url, data, options);
  }

  /**
   * Effectue une requête sécurisée avec toutes les validations
   */
  async request(method, url, data = null, options = {}) {
    // Limite de concurrence
    if (this.currentRequests >= this.maxConcurrent) {
      throw new Error(`Too many concurrent requests (max: ${this.maxConcurrent})`);
    }

    this.currentRequests++;

    try {
      // Valider l'URL
      this.validateUrl(url);

      // Merge config
      const config = {
        method,
        url,
        ...this.config,
        ...options,
        headers: {
          ...this.config.headers,
          ...options.headers
        }
      };

      // Ajouter data si POST
      if (data && method === 'POST') {
        config.data = data;
      }

      // Timeout avec AbortController (plus fiable)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

      try {
        config.signal = controller.signal;
        
        const response = await axios(config);
        clearTimeout(timeoutId);

        // Valider la réponse
        return this.validateResponse(response);
        
      } catch (error) {
        clearTimeout(timeoutId);
        
        if (error.name === 'AbortError' || error.code === 'ECONNABORTED') {
          throw new Error(`Request timeout after ${this.config.timeout}ms`);
        }
        throw error;
      }

    } finally {
      this.currentRequests--;
    }
  }

  /**
   * Valide une réponse HTTP
   */
  validateResponse(response) {
    // Vérifier la taille de la réponse
    const contentLength = response.headers['content-length'];
    if (contentLength && parseInt(contentLength) > this.config.maxContentLength) {
      throw new Error(`Response too large: ${contentLength} bytes`);
    }

    // Vérifier le Content-Type pour détecter les types dangereux
    const contentType = response.headers['content-type'] || '';
    
    // Protection contre les fichiers exécutables
    const dangerousTypes = [
      'application/x-msdownload',
      'application/x-msdos-program',
      'application/x-executable',
      'application/x-dosexec'
    ];
    
    if (dangerousTypes.some(type => contentType.includes(type))) {
      throw new Error(`Dangerous content type: ${contentType}`);
    }

    // Vérifier que la réponse n'est pas compressée de manière suspecte
    const encoding = response.headers['content-encoding'] || '';
    if (encoding.includes('br')) {
      // Brotli peut être utilisé pour decompression bombs
      throw new Error('Brotli encoding not supported for security reasons');
    }

    // Retourner une réponse sécurisée
    return {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: response.data,
      // Métadonnées utiles
      url: response.config.url,
      method: response.config.method,
      // Timing pour détection time-based attacks
      timing: {
        duration: response.config.metadata?.duration || 0
      }
    };
  }

  /**
   * Effectue plusieurs requêtes en parallèle avec limite de concurrence
   */
  async requestBatch(requests, options = {}) {
    const maxParallel = options.maxParallel || 3;
    const results = [];
    const errors = [];

    // Traiter par batch
    for (let i = 0; i < requests.length; i += maxParallel) {
      const batch = requests.slice(i, i + maxParallel);
      
      const promises = batch.map(async (req) => {
        try {
          const result = await this.request(
            req.method || 'GET',
            req.url,
            req.data,
            req.options
          );
          return { success: true, result, request: req };
        } catch (error) {
          return { success: false, error: error.message, request: req };
        }
      });

      const batchResults = await Promise.all(promises);
      
      batchResults.forEach(item => {
        if (item.success) {
          results.push(item.result);
        } else {
          errors.push(item);
        }
      });
    }

    return { results, errors };
  }

  /**
   * Test si une URL est accessible (HEAD request)
   */
  async isReachable(url, options = {}) {
    try {
      const response = await this.request('HEAD', url, null, {
        ...options,
        timeout: options.timeout || 5000
      });
      return response.status < 500;
    } catch (error) {
      return false;
    }
  }

  /**
   * Détecte si une URL redirige vers une IP privée (SSRF protection)
   */
  async checkRedirectSafety(url) {
    try {
      const response = await this.request('GET', url, null, {
        maxRedirects: 0, // Ne pas suivre les redirections
        validateStatus: (status) => status < 400 || (status >= 300 && status < 400)
      });

      // Si redirection
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers['location'];
        if (location) {
          this.validateUrl(location); // Va throw si IP privée
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }
}

// Créer une instance globale avec config par défaut
const defaultClient = new SecureHttpClient();

// Export
module.exports = {
  SecureHttpClient,
  // Instance par défaut
  secureGet: (url, options) => defaultClient.get(url, options),
  securePost: (url, data, options) => defaultClient.post(url, data, options),
  secureRequest: (method, url, data, options) => defaultClient.request(method, url, data, options),
  // Utilitaires
  isReachable: (url, options) => defaultClient.isReachable(url, options),
  checkRedirectSafety: (url) => defaultClient.checkRedirectSafety(url),
  requestBatch: (requests, options) => defaultClient.requestBatch(requests, options)
};
