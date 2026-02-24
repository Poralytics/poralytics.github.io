# 🧪 NEXUS — TESTS COMPLETS

## ✅ TEST 1: Installation
```bash
cd backend
npm install
```
**Résultat attendu**: 728 packages installés

---

## ✅ TEST 2: Initialisation DB
```bash
npm run init
```
**Résultat attendu**: 
```
✅ users
✅ domains
✅ scans
✅ vulnerabilities
✅ Admin user created
Email: admin@nexus.local
Password: Admin123!@#NexusChange
```

---

## ✅ TEST 3: Démarrage Serveur
```bash
npm start
```
**Résultat attendu**:
```
✅ NEXUS Database initialized successfully!
📊 Tables: 39
🔍 Indexes: 44
[INFO] Stripe initialized successfully

🛡️  NEXUS Security Scanner v2.1.0
📡  Listening on http://localhost:3000
🔌  WebSocket on ws://localhost:3000/ws
❤️  Health: http://localhost:3000/health
```

**⚠️  Si vous ne voyez PAS ce message, il y a un problème!**

---

## ✅ TEST 4: Health Check
Ouvrir un nouveau terminal et tester:
```bash
curl http://localhost:3000/health
```
**Résultat attendu**:
```json
{"status":"OK","version":"2.1.0","uptime":123.4,"timestamp":"..."}
```

---

## ✅ TEST 5: Page d'Accueil
Ouvrir le navigateur:
```
http://localhost:3000
```
**Résultat attendu**: Page d'accueil NEXUS s'affiche

---

## ✅ TEST 6: Inscription (CRITIQUE)

### 6.1 Ouvrir la page d'inscription
```
http://localhost:3000/register.html
```

### 6.2 Remplir le formulaire
- **Name**: `Test User`
- **Email**: `test@example.com`
- **Password**: `testpass123`

### 6.3 Cliquer sur "Create Account"

### 6.4 Vérifier dans la console du navigateur (F12)
Ouvrir la console (F12 → Console) et vérifier qu'il n'y a PAS d'erreurs.

**Si vous voyez des erreurs en rouge**, noter l'erreur exacte.

### 6.5 Résultat attendu
- ✅ Le bouton affiche "Creating account..."
- ✅ Redirection vers `/dashboard.html`
- ✅ Dashboard s'affiche

**Si ça ne marche pas**:
1. Ouvrir la console (F12)
2. Onglet "Network" 
3. Cliquer "Create Account"
4. Chercher la requête `/api/auth/register`
5. Cliquer dessus → Voir "Response"
6. Noter l'erreur exacte

---

## ✅ TEST 7: Login Admin
```
http://localhost:3000/login.html
```
- Email: `admin@nexus.local`
- Password: `Admin123!@#NexusChange`

**Résultat attendu**: Redirection vers dashboard

---

## ✅ TEST 8: Dashboard
```
http://localhost:3000/dashboard-ultimate.html
```
**Vérifier**:
- ✅ Stats affichées (Domains, Scans, etc.)
- ✅ Menu latéral fonctionne
- ✅ Status "Live" affiché (WebSocket connecté)

---

## ✅ TEST 9: Ajouter un Domaine
1. Dashboard → **Domains**
2. Cliquer **+ Add Domain**
3. URL: `https://example.com`
4. Name: `Test Domain`
5. Cliquer **Add**

**Résultat attendu**: Domain ajouté, visible dans la liste

---

## ✅ TEST 10: Lancer un Scan
1. Dashboard → Cliquer **+ New Scan**
2. Sélectionner le domaine
3. Type: **Full Security Scan**
4. Cliquer **Start Scan**

**Résultat attendu**: 
- Notification "Scan started"
- Badge scan actif (1)
- Après 60-90 secondes: scan terminé

---

## 🚨 DÉPANNAGE

### Problème: "Create Account" ne fait rien

**Cause possible 1: Route non accessible**
Tester manuellement:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test1234","name":"Test"}'
```

**Si erreur 404**: Route non chargée  
**Si erreur 500**: Erreur serveur (voir logs)  
**Si succès**: Le problème est dans le frontend

**Cause possible 2: CORS**
Vérifier dans la console (F12) s'il y a une erreur CORS.

**Cause possible 3: Database**
Vérifier que la DB existe:
```bash
ls backend/nexus-ultimate.db
```

**Cause possible 4: Colonne manquante**
Vérifier les logs du serveur pour des erreurs SQL.

---

## 📋 CHECKLIST FINALE

Avant de dire "ça ne marche pas", vérifier:

- [ ] `npm start` démarre SANS erreur
- [ ] Message "Listening on http://localhost:3000" affiché
- [ ] `curl http://localhost:3000/health` retourne 200 OK
- [ ] Page d'accueil s'affiche
- [ ] Console navigateur (F12) sans erreur rouge
- [ ] Onglet Network montre la requête POST vers `/api/auth/register`
- [ ] La réponse de l'API contient `{"success":true,"token":"..."}`

**Si TOUS ces points sont OK mais ça ne marche toujours pas**, il y a un bug frontend dans le JavaScript.
