# 🚀 NEXUS - Guide de Démarrage Immédiat

## ⚡ Lancement en 1-Click (Windows)

1. **Double-cliquez** sur `START.bat`
2. **Attendez** 30-60 secondes (installation auto)
3. **Ouvrez** http://localhost:3000/login.html
4. **Connectez-vous** :
   - Email: `demo@nexus.security`
   - Password: `nexus2024`

✅ **C'EST TOUT.** Le serveur tourne, la DB est prête, le compte démo existe.

---

## 🐧 Linux/Mac

```bash
cd backend
npm install
node init-nexus.js
node server.js
```

Puis: http://localhost:3000/login.html

---

## 🎯 Premier Test

Une fois connecté au dashboard:

### Test 1: Ajouter un Domaine
1. Cliquez "**+ Ajouter un domaine**"
2. Entrez: `https://example.com`
3. Cliquez "Ajouter"

### Test 2: Lancer un Scan
1. Sur le domaine ajouté, cliquez "**Scanner**"
2. Observez la **progression en temps réel**
3. Attendez la fin (30-60 secondes)

### Test 3: Explorer les Résultats
- **Score de sécurité**: Circulaire animé
- **Vulnérabilités**: Par sévérité avec €
- **Prédictions d'attaque**: ML-based
- **Auto-corrections**: Ce qui a été fixé automatiquement

---

## 📊 Dashboard Explained

### Vue d'Ensemble
- **Score Global**: Votre posture de sécurité (0-100)
- **Risque en €**: Exposition financière totale
- **KPIs**: Critical, High, Medium, Low vulns
- **Graphiques**: Tendances et répartition

### Domaines
- **Cartes visuelles**: Score, risque, stats par domaine
- **Actions rapides**: Scanner, Voir détails, Supprimer

### Scans
- **Historique complet**: Tous les scans effectués
- **Progression**: Barre de progression temps réel
- **Résultats**: Score final, vulns trouvées, auto-fixées

### Vulnérabilités
- **Priorisées par $$$**: Plus gros risque financier en haut
- **Détails complets**: Impact €, probabilité, CVSS, MITRE
- **Recommandations**: Comment corriger

---

## 🔥 Fonctionnalités à Essayer

### 1. Business Impact
Chaque vulnérabilité affiche:
- **Impact Business (€)**: Coût potentiel
- **Exploit Probability**: Chance d'exploitation
- **Expected Loss (€)**: Impact × Probabilité

### 2. Attack Predictions
Après un scan, consultez les prédictions:
- **Type d'attaque** prévu
- **Probabilité** (ML-based)
- **Timeframe** (24h, 7j, 30j)
- **Impact estimé en €**

### 3. Auto-Remediation
Voyez ce qui a été corrigé automatiquement:
- Headers de sécurité ajoutés
- Versions TLS mises à jour
- Configs optimisées

### 4. Graphiques Temps Réel
- **Répartition**: Donut chart des vulns par sévérité
- **Évolution**: Line chart des tendances 30 jours
- **Comparaison**: Votre score vs industrie

---

## ❓ Problèmes Courants

### "Node.js not installed"
👉 Téléchargez: https://nodejs.org/ (version LTS)
- Installez avec options par défaut
- Redémarrez l'ordinateur
- Relancez START.bat

### "Port 3000 already in use"
👉 Une autre app utilise le port 3000
- Fermez les autres serveurs Node
- OU changez le port dans `backend/.env`:
  ```
  PORT=3001
  ```

### "npm install failed"
👉 Problème réseau ou npm
- Vérifiez connexion internet
- Essayez: `npm cache clean --force`
- Relancez START.bat

### "Database error"
👉 DB corrompue
- Supprimez `backend/nexus-ultimate.db`
- Relancez START.bat (DB recréée auto)

---

## 🎨 Personnalisation

### Changer les Données Business
Éditez un domaine et modifiez:
- **Revenue per hour**: Pour calcul downtime cost
- **Business value**: Pour impact data breach
- **Criticality**: Influence priorisation

### Ajouter Vrai Domaine
Testez avec vos propres URLs:
- `https://votresite.com`
- `https://api.votresite.com`
- Scan réel de VOTRE infrastructure

---

## 📚 Prochaines Étapes

### Approfondir
1. Lisez le **README.md** complet
2. Explorez chaque page du dashboard
3. Testez avec plusieurs domaines
4. Comparez les scores

### Déployer en Production
1. Utilisez PostgreSQL au lieu de SQLite
2. Configurez HTTPS (reverse proxy)
3. Rate limiting production
4. Backups automatiques

### Contribuer
- GitHub: Issues & PRs bienvenues
- Discord: Rejoignez la communauté
- Feedback: Dites-nous ce qui manque

---

## 🎯 Objectif

**NEXUS doit vous faire dire "WOW" dans les 5 premières minutes.**

Si ce n'est pas le cas, contactez-nous: support@nexus.security

---

## 🌟 Enjoy NEXUS!

Vous avez maintenant une plateforme de sécurité **prédictive**, **autonome**, et **business-first**.

**Bienvenue dans le futur de la cybersécurité.** 🚀

---

*NEXUS Security - Protecting the future, today.*
