# 🚀 GUIDE DÉPLOIEMENT PRODUCTION COMPLET

## NEXUS - Mise en Production Étape par Étape

---

# 📋 PRÉ-REQUIS

Avant de déployer en production, tu as besoin de:

1. ✅ Compte Railway/Heroku/AWS
2. ✅ Compte Stripe (pour billing)
3. ✅ Nom de domaine (optionnel mais recommandé)
4. ✅ Certificat SSL (auto avec Railway/Heroku)

---

# 🎯 OPTION 1: RAILWAY (RECOMMANDÉ - LE PLUS SIMPLE)

## Pourquoi Railway?
- ✅ Setup en 5 minutes
- ✅ SSL automatique
- ✅ Scaling automatique
- ✅ Base de données PostgreSQL incluse
- ✅ Redis inclus
- ✅ $5-20/mois pour commencer

## Étapes Détaillées

### 1. Créer Compte Railway
```bash
# Aller sur railway.app
# Sign up avec GitHub
```

### 2. Installer CLI Railway
```bash
npm install -g @railway/cli
railway login
```

### 3. Initialiser Projet
```bash
cd NEXUS-ULTIMATE-FINAL
railway init
# Choisir: "Create new project"
# Nom: nexus-production
```

### 4. Ajouter PostgreSQL
```bash
railway add postgresql
# Railway crée automatiquement DATABASE_URL
```

### 5. Ajouter Redis
```bash
railway add redis
# Railway crée automatiquement REDIS_URL
```

### 6. Configurer Variables d'Environnement
```bash
# Générer JWT secret sécurisé
railway variables set JWT_SECRET=$(openssl rand -hex 32)

# Node environment
railway variables set NODE_ENV=production

# Stripe (obtenir depuis stripe.com/dashboard)
railway variables set STRIPE_SECRET_KEY=sk_live_...
railway variables set STRIPE_PUBLISHABLE_KEY=pk_live_...
railway variables set STRIPE_WEBHOOK_SECRET=whsec_...

# Stripe Price IDs (créer dans Stripe Dashboard)
railway variables set STRIPE_PRICE_PRO=price_...
railway variables set STRIPE_PRICE_BUSINESS=price_...
railway variables set STRIPE_PRICE_ENTERPRISE=price_...

# Email SMTP (pour notifications)
railway variables set SMTP_HOST=smtp.gmail.com
railway variables set SMTP_PORT=587
railway variables set SMTP_USER=your-email@gmail.com
railway variables set SMTP_PASSWORD=your-app-password
```

### 7. Déployer
```bash
cd backend
railway up
```

### 8. Obtenir URL
```bash
railway open
# Copier l'URL: https://nexus-production.railway.app
```

### 9. Configurer Stripe Webhook
```bash
# 1. Aller sur stripe.com/dashboard/webhooks
# 2. Ajouter endpoint: https://your-railway-url.railway.app/api/billing/webhook
# 3. Sélectionner events:
#    - checkout.session.completed
#    - customer.subscription.created
#    - customer.subscription.updated
#    - customer.subscription.deleted
#    - invoice.paid
#    - invoice.payment_failed
# 4. Copier Webhook Secret
# 5. railway variables set STRIPE_WEBHOOK_SECRET=whsec_...
```

### 10. Ajouter Custom Domain (Optionnel)
```bash
# Dans Railway Dashboard:
# Settings → Domains → Add Custom Domain
# Ajouter: app.votredomaine.com

# Configurer DNS:
# Type: CNAME
# Name: app
# Value: [railway domain]
```

### 11. Tester
```bash
# Visiter: https://your-url.railway.app
# Login: demo@nexus.com / demo123
# Tester scan
# Tester paiement (mode test Stripe)
```

**COÛT: ~$10-30/mois selon trafic**

---

# 🎯 OPTION 2: HEROKU

## Étapes

### 1. Installer Heroku CLI
```bash
# macOS
brew tap heroku/brew && brew install heroku

# Windows
# Télécharger depuis heroku.com/cli
```

### 2. Login
```bash
heroku login
```

### 3. Créer App
```bash
cd NEXUS-ULTIMATE-FINAL
heroku create nexus-production
```

### 4. Ajouter PostgreSQL
```bash
heroku addons:create heroku-postgresql:mini
```

### 5. Ajouter Redis
```bash
heroku addons:create heroku-redis:mini
```

### 6. Configurer Variables
```bash
heroku config:set JWT_SECRET=$(openssl rand -hex 32)
heroku config:set NODE_ENV=production
heroku config:set STRIPE_SECRET_KEY=sk_live_...
heroku config:set STRIPE_PUBLISHABLE_KEY=pk_live_...
# ... toutes les autres variables
```

### 7. Déployer
```bash
# Créer Procfile
echo "web: cd backend && npm start" > Procfile

# Git
git init
git add .
git commit -m "Initial production deploy"
git push heroku main
```

### 8. Scale
```bash
heroku ps:scale web=1
```

### 9. Ouvrir
```bash
heroku open
```

**COÛT: ~$16/mois (Eco Dyno + Mini Postgres + Mini Redis)**

---

# 🎯 OPTION 3: VPS (DigitalOcean, AWS EC2, etc.)

Pour plus de contrôle et moins cher.

## Configuration Serveur Ubuntu 22.04

### 1. Se connecter
```bash
ssh root@your-server-ip
```

### 2. Installer Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs
node -v  # Vérifier: v18+
```

### 3. Installer PostgreSQL
```bash
apt-get install -y postgresql postgresql-contrib
sudo -u postgres psql

# Dans psql:
CREATE DATABASE nexus_production;
CREATE USER nexus WITH ENCRYPTED PASSWORD 'your-strong-password';
GRANT ALL PRIVILEGES ON DATABASE nexus_production TO nexus;
\q
```

### 4. Installer Redis
```bash
apt-get install -y redis-server
systemctl enable redis-server
systemctl start redis-server
```

### 5. Installer PM2
```bash
npm install -g pm2
```

### 6. Copier Projet
```bash
# Sur votre machine:
scp NEXUS-PERFECT-100.tar.gz root@your-server-ip:/root/

# Sur le serveur:
cd /root
tar -xzf NEXUS-PERFECT-100.tar.gz
cd NEXUS-ULTIMATE-FINAL/backend
npm install --production
```

### 7. Configurer .env
```bash
cat > .env << 'EOF'
NODE_ENV=production
PORT=3000
JWT_SECRET=$(openssl rand -hex 32)
DATABASE_URL=postgresql://nexus:your-password@localhost:5432/nexus_production
REDIS_URL=redis://localhost:6379
STRIPE_SECRET_KEY=sk_live_...
# ... autres variables
EOF
```

### 8. Migrer Database
```bash
# Si besoin de migrer depuis SQLite vers PostgreSQL
npm run migrate
```

### 9. Démarrer avec PM2
```bash
pm2 start server.js --name nexus
pm2 save
pm2 startup
```

### 10. Installer Nginx
```bash
apt-get install -y nginx

cat > /etc/nginx/sites-available/nexus << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /ws {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
EOF

ln -s /etc/nginx/sites-available/nexus /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### 11. SSL avec Certbot
```bash
apt-get install -y certbot python3-certbot-nginx
certbot --nginx -d your-domain.com
# Suivre instructions
```

### 12. Firewall
```bash
ufw allow 22
ufw allow 80
ufw allow 443
ufw enable
```

### 13. Backups Automatiques
```bash
# Créer script backup
cat > /root/backup-nexus.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump nexus_production > /root/backups/nexus_$DATE.sql
find /root/backups -name "nexus_*.sql" -mtime +7 -delete
EOF

chmod +x /root/backup-nexus.sh

# Cron quotidien
crontab -e
# Ajouter: 0 2 * * * /root/backup-nexus.sh
```

**COÛT: $5-10/mois (DigitalOcean Droplet basique)**

---

# 🔒 CHECKLIST SÉCURITÉ PRODUCTION

## Avant de Lancer

- [ ] JWT_SECRET changé (32+ caractères aléatoires)
- [ ] STRIPE_SECRET_KEY en mode live (sk_live_...)
- [ ] HTTPS activé (SSL)
- [ ] Firewall configuré
- [ ] Rate limiting activé
- [ ] CORS configuré correctement
- [ ] Database backups automatiques
- [ ] Monitoring activé (Sentry, LogTail)
- [ ] Variables sensibles dans .env (pas dans code)
- [ ] .env ajouté à .gitignore

## Configuration Stripe Production

### 1. Activer Mode Live
```bash
# Stripe Dashboard → Developers → API Keys
# Copier Live Secret Key: sk_live_...
# Copier Live Publishable Key: pk_live_...
```

### 2. Créer Produits & Prix
```bash
# Stripe Dashboard → Products → Create Product

# Produit 1: NEXUS Pro
# - Prix: $49/mois
# - Récurrent
# - Copier Price ID: price_...

# Produit 2: NEXUS Business
# - Prix: $199/mois
# - Récurrent
# - Copier Price ID: price_...

# Produit 3: NEXUS Enterprise
# - Prix: $999/mois
# - Récurrent
# - Copier Price ID: price_...
```

### 3. Configurer Webhook
```bash
# Stripe Dashboard → Developers → Webhooks
# Add endpoint: https://your-domain.com/api/billing/webhook
# Events: tous ceux listés plus haut
# Copier Signing Secret: whsec_...
```

---

# 📊 MONITORING & LOGS

## Sentry (Error Tracking)
```bash
# 1. Créer compte sur sentry.io
# 2. Créer projet Node.js
# 3. Copier DSN
# 4. railway variables set SENTRY_DSN=https://...
```

## LogTail (Logs)
```bash
# 1. Créer compte sur betterstack.com
# 2. Créer source
# 3. Copier token
# 4. railway variables set LOGTAIL_SOURCE_TOKEN=...
```

---

# 🎯 POST-DÉPLOIEMENT

## 1. Tester Tout
```bash
# Checklist:
✓ Site accessible en HTTPS
✓ Login fonctionne
✓ Dashboard s'affiche
✓ Scan fonctionne (VRAIMENT teste un scan)
✓ WebSocket connecté (temps réel marche)
✓ Paiement Stripe (test mode)
✓ Email notifications
✓ API répond
```

## 2. Passer Stripe en Live
```bash
# Une fois tests OK:
# railway variables set STRIPE_SECRET_KEY=sk_live_...
# railway up  # Redéployer
```

## 3. Monitoring
```bash
# Vérifier daily:
- Sentry pour erreurs
- Logs pour problèmes
- Uptime (pingdom.com)
- Usage database
```

---

# 💰 COÛTS RÉCAPITULATIFS

| Platform | Coût/mois | Difficulté | SSL | Support |
|----------|-----------|------------|-----|---------|
| **Railway** | $10-30 | ⭐ Facile | Auto | Bon |
| **Heroku** | $16+ | ⭐⭐ Facile | Auto | Excellent |
| **VPS** | $5-10 | ⭐⭐⭐⭐ Expert | Manuel | Aucun |

**Recommandation:** Commence Railway, scale vers VPS si >10K users.

---

# 🆘 PROBLÈMES COURANTS

## "Cannot connect to database"
```bash
# Vérifier DATABASE_URL
railway variables get DATABASE_URL
# Format: postgresql://user:pass@host:port/dbname
```

## "Stripe webhook failed"
```bash
# 1. Vérifier URL webhook dans Stripe Dashboard
# 2. Vérifier STRIPE_WEBHOOK_SECRET
# 3. Tester: curl https://your-url/api/billing/webhook
```

## "WebSocket not connecting"
```bash
# Vérifier:
# 1. WSS (pas WS) en HTTPS
# 2. Nginx config pour /ws
# 3. Firewall autorise WebSocket
```

---

**TON APP EST MAINTENANT EN PRODUCTION!** 🎉

**Support:** docs/ folder ou GitHub issues
