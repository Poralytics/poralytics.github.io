#!/bin/bash

echo "🔍 NEXUS — VERIFICATION COMPLETE"
echo "================================"
echo ""

cd backend

echo "1️⃣ Vérification des fichiers critiques..."
FILES=(
  "server.js"
  "init-db.js"
  "package.json"
  "config/database.js"
  "middleware/auth.js"
  "utils/error-handler.js"
  "utils/secure-http-client.js"
  "services/complete-scan-orchestrator.js"
)

for file in "${FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "  ✅ $file"
  else
    echo "  ❌ $file MANQUANT"
  fi
done

echo ""
echo "2️⃣ Vérification de la syntaxe JavaScript..."
if command -v node &> /dev/null; then
  node -e "require('./services/complete-scan-orchestrator.js'); console.log('  ✅ Orchestrator syntax OK')" 2>/dev/null || echo "  ❌ Orchestrator syntax ERROR"
  node -e "require('./config/database.js'); console.log('  ✅ Database config syntax OK')" 2>/dev/null || echo "  ⚠️  Database config (needs npm install first)"
else
  echo "  ⚠️  Node.js not found, skipping syntax check"
fi

echo ""
echo "3️⃣ Vérification structure des dossiers..."
DIRS=(
  "config"
  "middleware"
  "routes"
  "scanners"
  "services"
  "tests"
  "utils"
  "workers"
)

for dir in "${DIRS[@]}"; do
  if [ -d "$dir" ]; then
    count=$(find "$dir" -name "*.js" | wc -l)
    echo "  ✅ $dir/ ($count fichiers)"
  else
    echo "  ❌ $dir/ MANQUANT"
  fi
done

echo ""
echo "4️⃣ Statistiques du projet..."
echo "  📁 Fichiers JS backend: $(find . -name '*.js' -not -path '*/node_modules/*' | wc -l)"
echo "  🔍 Scanners: $(ls scanners/*.js 2>/dev/null | wc -l)"
echo "  🛣️  Routes: $(ls routes/*.js 2>/dev/null | wc -l)"
echo "  ⚙️  Services: $(ls services/*.js 2>/dev/null | wc -l)"
echo "  🧪 Tests: $(find tests -name '*.test.js' 2>/dev/null | wc -l)"

cd ..
echo "  📄 Pages HTML frontend: $(ls frontend/*.html 2>/dev/null | wc -l)"
echo "  📖 Documentation: $(ls *.md 2>/dev/null | wc -l)"

echo ""
echo "================================"
echo "✅ VERIFICATION TERMINEE"
echo ""
echo "📋 PROCHAINES ETAPES:"
echo "  1. cd backend"
echo "  2. npm install"
echo "  3. npm run init"
echo "  4. npm start"
echo "  5. Ouvrir http://localhost:3000/dashboard-ultimate.html"
