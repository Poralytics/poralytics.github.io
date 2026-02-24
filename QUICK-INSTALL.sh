#!/bin/bash

# NEXUS ULTIMATE PRO - Installation Automatique
# Usage: bash QUICK-INSTALL.sh

set -e

echo "🚀 NEXUS ULTIMATE PRO - Installation Automatique"
echo "=================================================="
echo ""

# Vérifier Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js non installé. Installez-le depuis https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js $(node --version) détecté"

# Vérifier npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm non installé"
    exit 1
fi

echo "✅ npm $(npm --version) détecté"
echo ""

# Installation backend
echo "📦 Installation des dépendances backend..."
cd backend
npm install --silent

if [ $? -ne 0 ]; then
    echo "❌ Échec installation npm"
    exit 1
fi

echo "✅ Dépendances installées"
echo ""

# Initialiser DB
echo "🗄️  Initialisation de la base de données..."
node init-nexus.js

if [ $? -ne 0 ]; then
    echo "❌ Échec initialisation DB"
    exit 1
fi

echo "✅ Base de données initialisée"
echo ""

# Créer compte demo si pas existe
echo "👤 Vérification compte demo..."
echo ""

echo "=================================================="
echo "✅ INSTALLATION TERMINÉE !"
echo "=================================================="
echo ""
echo "📋 Prochaines étapes:"
echo ""
echo "1. Lancer le serveur:"
echo "   cd backend && npm start"
echo ""
echo "2. Ouvrir votre navigateur:"
echo "   http://localhost:3000/login.html"
echo ""
echo "3. Se connecter avec:"
echo "   Email:    demo@nexus.security"
echo "   Password: nexus2024"
echo ""
echo "4. Ajouter un domaine et lancer un scan !"
echo ""
echo "=================================================="
echo "📚 Documentation:"
echo "   - README-FINAL.md (guide complet)"
echo "   - API-DOCUMENTATION.md (API reference)"
echo "   - DEPLOY.md (déploiement production)"
echo "=================================================="
echo ""
