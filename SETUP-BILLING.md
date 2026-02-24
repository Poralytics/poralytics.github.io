# 🚀 SETUP BILLING SYSTEM — Guide Complet

## ⚠️ POURQUOI RIEN N'A CHANGÉ

Les fichiers ont été créés mais **pas intégrés au serveur**. Il faut:
1. Monter les routes dans server.js
2. Ajouter les variables d'environnement Stripe
3. Créer les tables de paiement
4. Redémarrer le serveur

## ✅ ÉTAPES D'INSTALLATION

### 1. Configurer Stripe

```bash
# Dans backend/.env, ajouter:
STRIPE_SECRET_KEY=sk_test_votre_cle_stripe
STRIPE_WEBHOOK_SECRET=whsec_votre_secret_webhook
```

**Obtenir les clés**:
- Aller sur https://dashboard.stripe.com/test/apikeys
- Copier "Secret key" → STRIPE_SECRET_KEY
- Pour webhook secret: https://dashboard.stripe.com/test/webhooks

### 2. Installer Stripe SDK

```bash
cd backend
npm install stripe
```

### 3. Créer Table Payments

```sql
-- Dans votre DB
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stripe_invoice_id TEXT,
  amount INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL,
  paid_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Ajouter colonnes manquantes à users
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'free';
ALTER TABLE users ADD COLUMN subscription_starts_at INTEGER;
ALTER TABLE users ADD COLUMN subscription_ends_at INTEGER;
ALTER TABLE users ADD COLUMN trial_ends_at INTEGER;
ALTER TABLE users ADD COLUMN trial_used INTEGER DEFAULT 0;
```

### 4. Monter les Routes Billing

Le fichier `routes/billing.js` existe mais il faut le charger dans server.js.

**Vérifier dans server.js**:
```javascript
// Ajouter cette ligne après les autres routes
const billingRoutes = require('./routes/billing');
app.use('/api/billing', billingRoutes);
```

### 5. Redémarrer le Serveur

```bash
cd backend
npm start
```

### 6. Tester l'Installation

```bash
# 1. Vérifier que la route existe
curl http://localhost:3000/api/billing/plans

# Devrait retourner la liste des plans

# 2. Tester avec authentification
TOKEN="votre_jwt_token"
curl -X POST http://localhost:3000/api/billing/checkout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"planId":"price_starter_monthly"}'

# Devrait retourner une URL Stripe Checkout
```

## 🔧 SCRIPT D'INSTALLATION AUTOMATIQUE

Créer `backend/setup-billing.js`:

```javascript
const db = require('./config/database');

console.log('🚀 Setting up billing system...');

// Créer table payments
db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    stripe_invoice_id TEXT,
    amount INTEGER NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT NOT NULL,
    paid_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// Ajouter colonnes Stripe à users (si pas déjà présentes)
const columns = [
  'stripe_customer_id TEXT',
  'stripe_subscription_id TEXT',
  'subscription_status TEXT DEFAULT "free"',
  'subscription_starts_at INTEGER',
  'subscription_ends_at INTEGER',
  'trial_ends_at INTEGER',
  'trial_used INTEGER DEFAULT 0'
];

columns.forEach(col => {
  const columnName = col.split(' ')[0];
  try {
    db.exec(`ALTER TABLE users ADD COLUMN ${col}`);
    console.log(`✅ Added column: ${columnName}`);
  } catch (err) {
    if (err.message.includes('duplicate column')) {
      console.log(`⏭️  Column already exists: ${columnName}`);
    } else {
      console.error(`❌ Error adding column ${columnName}:`, err.message);
    }
  }
});

console.log('✅ Billing system setup complete!');
process.exit(0);
```

**Exécuter**:
```bash
cd backend
node setup-billing.js
```

## 📊 VÉRIFICATION FINALE

### Checklist:
- [ ] Stripe keys dans .env
- [ ] npm install stripe fait
- [ ] Table payments créée
- [ ] Colonnes users ajoutées
- [ ] Routes montées dans server.js
- [ ] Serveur redémarré
- [ ] Route /api/billing/plans répond
- [ ] Page /pricing.html charge

### Si ça marche:
```bash
# Vous devriez voir:
curl http://localhost:3000/api/billing/plans
# {"plans":{"free":{...},"starter":{...},...}}

# Et:
open http://localhost:3000/pricing.html
# → Page avec 5 cards de prix
```

## 🐛 TROUBLESHOOTING

### Erreur: "Cannot find module 'stripe'"
```bash
cd backend && npm install stripe
```

### Erreur: "No such table: payments"
```bash
node setup-billing.js
```

### Erreur: 404 sur /api/billing
Vérifier que server.js contient:
```javascript
app.use('/api/billing', require('./routes/billing'));
```

### Routes Stripe ne répondent pas
Redémarrer le serveur:
```bash
# Ctrl+C puis
npm start
```

---

## 🎯 APRÈS LE SETUP

Une fois que tout est configuré, vous devriez pouvoir:

1. ✅ Voir la page pricing
2. ✅ Cliquer sur "Start Trial"
3. ✅ Être redirigé vers Stripe Checkout
4. ✅ Compléter un paiement (mode test)
5. ✅ Recevoir un webhook
6. ✅ Avoir l'abonnement activé

---

**Questions? Écrivez "setup ok" quand tout est configuré et je continue!**
