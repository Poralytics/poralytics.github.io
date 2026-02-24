# 🚀 NEXUS ULTIMATE PRO - Installation Production

## ⚡ Installation Rapide (5 minutes)

### 1. Prérequis
```bash
- Node.js 18+ (vérifier: node --version)
- npm (vérifier: npm --version)
- (Optionnel) Redis pour performance maximale
```

### 2. Installation
```bash
cd backend
npm install
```

### 3. Lancement
```bash
# Option A: Lancement direct
npm start

# Option B: Mode développement (auto-reload)
npm run dev

# Option C: Avec worker séparé pour les scans
npm start & npm run worker
```

### 4. Test du système
```bash
# Dans un nouveau terminal, une fois le serveur lancé:
node test-system.js
```

## 📡 Accès

- **Frontend**: http://localhost:3000
- **Dashboard**: http://localhost:3000/dashboard.html
- **Login**: http://localhost:3000/login.html
- **API**: http://localhost:3000/api
- **Health**: http://localhost:3000/health
- **WebSocket**: ws://localhost:3000/ws

## 🔐 Comptes de Test

### Compte Demo
- **Email**: demo@nexus.com
- **Password**: demo123
- **Tier**: Pro

### Compte Admin
- **Email**: admin@nexus.com
- **Password**: admin123
- **Tier**: Enterprise

## ✅ Validation de l'Installation

Après le lancement, vous devriez voir:

```
============================================================
   🚀 NEXUS ULTIMATE PRO - v5.3 REAL
============================================================
📡 API Server:    http://localhost:3000/api
🌐 Frontend:      http://localhost:3000/
🔒 Auth:          http://localhost:3000/login.html
📊 Dashboard:     http://localhost:3000/dashboard.html
✅ Health:        http://localhost:3000/health
🔌 WebSocket:     ws://localhost:3000/ws
============================================================

💎 REAL Features Active:
  ✅ REAL SQL & XSS Scanners
  ✅ REAL Scan Orchestrator
  ✅ REAL WebSocket Updates
  ✅ REAL Stripe Billing
  ✅ REAL Job Queue
============================================================

✅ WebSocket server initialized on /ws
ℹ️  Using in-memory queue (REDIS_URL not set)
```

## 🧪 Test Rapide

### Via l'interface web:
1. Ouvrir http://localhost:3000/login.html
2. Se connecter avec demo@nexus.com / demo123
3. Aller au Dashboard
4. Ajouter un domaine (ex: https://httpbin.org)
5. Lancer un scan
6. Observer les mises à jour temps réel

### Via le script de test:
```bash
node test-system.js
```

Le script teste automatiquement:
- ✅ Health Check
- ✅ Authentification
- ✅ Création de domaine
- ✅ Lancement de scan
- ✅ Job Queue
- ✅ WebSocket real-time
- ✅ Progression du scan
- ✅ Récupération des résultats

## 📊 Fonctionnalités Testées

### Scans RÉELS
- ✅ Requêtes HTTP réelles
- ✅ Détection SQL Injection (vraie)
- ✅ Détection XSS (vraie)
- ✅ Analyse Security Headers (vraie)
- ✅ Vérification SSL/TLS (vraie)

### Job Queue
- ✅ Queue en mémoire (sans Redis)
- ✅ Queue Redis (si configuré)
- ✅ Retry automatique sur échec
- ✅ Gestion de concurrence (max 3 scans simultanés)

### WebSocket Real-time
- ✅ Authentification JWT
- ✅ Mises à jour de progression
- ✅ Notifications de complétion
- ✅ Gestion de déconnexion

### Base de Données
- ✅ SQLite avec WAL mode
- ✅ Toutes les tables créées automatiquement
- ✅ Indexes de performance
- ✅ Données demo pré-chargées

## 🔧 Configuration Avancée

### Redis (Optionnel mais recommandé pour production)
```bash
# Installer Redis
# macOS: brew install redis
# Ubuntu: sudo apt install redis
# Windows: https://redis.io/docs/getting-started/installation/install-redis-on-windows/

# Lancer Redis
redis-server

# Configurer dans .env
REDIS_URL=redis://localhost:6379
```

### Stripe (Pour facturation)
```bash
# 1. Créer compte sur https://stripe.com
# 2. Obtenir les clés de test: https://dashboard.stripe.com/test/apikeys
# 3. Configurer dans .env
STRIPE_SECRET_KEY=sk_test_votre_cle
STRIPE_PUBLISHABLE_KEY=pk_test_votre_cle

# 4. Pour webhooks locaux, installer Stripe CLI
stripe listen --forward-to localhost:3000/api/billing/webhook
```

## 🚨 Troubleshooting

### Le serveur ne démarre pas
```bash
# Vérifier Node.js
node --version  # Doit être 18+

# Réinstaller les dépendances
rm -rf node_modules package-lock.json
npm install

# Vérifier les logs
npm start
```

### Redis n'est pas disponible
```
ℹ️  Using in-memory queue (REDIS_URL not set)
```
C'est normal! Le système fonctionne sans Redis avec une queue en mémoire.

### WebSocket ne se connecte pas
- Vérifier que le serveur est lancé
- Vérifier qu'aucun firewall ne bloque le port 3000
- Tester avec: wscat -c ws://localhost:3000/ws

### Les scans ne démarrent pas
```bash
# Vérifier les logs
npm start

# Tester la queue
node -e "const q = require('./services/real-job-queue'); q.getStats().then(console.log)"
```

## 📁 Structure des Fichiers

```
backend/
├── server.js              # Point d'entrée principal
├── test-system.js         # Script de test complet
├── config/
│   └── database.js        # Configuration DB + init
├── services/
│   ├── real-scan-orchestrator.js   # Coordonne les scans
│   ├── real-job-queue.js           # Gestion des jobs
│   ├── real-websocket-server.js    # WebSocket temps réel
│   └── real-stripe-billing.js      # Facturation Stripe
├── scanners/
│   ├── real-sql-scanner.js         # Scanner SQL Injection
│   └── real-xss-scanner.js         # Scanner XSS
└── routes/
    ├── auth.js            # Authentification
    ├── domains.js         # Gestion domaines
    └── scans.js           # Gestion scans
```

## 🎯 Prochaines Étapes

1. **Tester le système complet**
   ```bash
   node test-system.js
   ```

2. **Lancer un scan réel**
   - Login sur le dashboard
   - Ajouter un domaine
   - Lancer un scan
   - Observer les résultats en temps réel

3. **Configurer pour production**
   - Changer JWT_SECRET dans .env
   - Configurer Redis
   - Configurer Stripe production
   - Configurer HTTPS

4. **Déploiement**
   - Voir DEPLOYMENT-PRODUCTION.md

## 💬 Support

Si vous rencontrez des problèmes:
1. Vérifier les logs du serveur
2. Exécuter `node test-system.js`
3. Vérifier les prérequis (Node.js 18+)
4. Consulter la documentation complète

## ✨ Fonctionnalités Clés Validées

✅ Scans de sécurité RÉELS (pas simulés)
✅ Job queue fonctionnelle (avec ou sans Redis)
✅ WebSocket temps réel
✅ Authentification JWT
✅ Base de données SQLite optimisée
✅ Gestion d'erreurs robuste
✅ Retry automatique
✅ Support multi-utilisateurs
✅ Dashboard interactif
✅ API RESTful complète

---

**🎉 Vous êtes prêt! Le système est 100% fonctionnel et prêt pour des scans réels.**
