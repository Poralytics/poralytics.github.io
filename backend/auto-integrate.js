#!/usr/bin/env node
/**
 * AUTO-INTEGRATE ALL ROUTES
 * Monte automatiquement toutes les routes dans server.js
 */

const fs = require('fs');
const path = require('path');

console.log('🔧 AUTO-INTEGRATION — Mounting all routes in server.js\n');

const serverPath = path.join(__dirname, 'server.js');

if (!fs.existsSync(serverPath)) {
  console.error('❌ server.js not found!');
  process.exit(1);
}

let serverContent = fs.readFileSync(serverPath, 'utf8');

// Routes à ajouter
const routes = [
  { path: '/api/billing', file: './routes/billing', name: 'Billing & Subscriptions' },
  { path: '/api/usage', file: './routes/usage', name: 'Usage & Quotas' },
  { path: '/api/score', file: './routes/score', name: 'Security Health Score' },
  { path: '/api/visualizations', file: './routes/visualizations', name: 'Visualizations (Heatmap, Timeline)' },
  { path: '/api/executive', file: './routes/executive', name: 'Executive Reporting' },
  { path: '/api/ai', file: './routes/ai', name: 'AI-Powered Features' }
];

let routesAdded = 0;
let routesAlreadyPresent = 0;

// Trouver où insérer les routes (après les routes existantes)
const insertMarker = "// ===== ROUTES =====";
let insertPosition = serverContent.indexOf(insertMarker);

if (insertPosition === -1) {
  // Si pas de marker, chercher après app.use('/api/
  const lastRouteMatch = serverContent.match(/app\.use\('\/api\/[^']+',\s*require\('[^']+'\)\);/g);
  if (lastRouteMatch && lastRouteMatch.length > 0) {
    const lastRoute = lastRouteMatch[lastRouteMatch.length - 1];
    insertPosition = serverContent.indexOf(lastRoute) + lastRoute.length;
  } else {
    console.error('❌ Could not find where to insert routes in server.js');
    console.log('ℹ️  Please manually add routes or add "// ===== ROUTES =====" marker');
    process.exit(1);
  }
}

// Construire le code des nouvelles routes
let routeCode = '\n\n// Auto-integrated routes (added by auto-integrate.js)\n';

for (const route of routes) {
  // Vérifier si déjà présent
  if (serverContent.includes(route.path) && serverContent.includes(route.file)) {
    console.log(`⏭️  ${route.name} already integrated`);
    routesAlreadyPresent++;
    continue;
  }

  // Vérifier si le fichier existe
  const routeFilePath = path.join(__dirname, route.file.replace('./', '') + '.js');
  if (!fs.existsSync(routeFilePath)) {
    console.log(`⚠️  ${route.name} file not found, skipping: ${routeFilePath}`);
    continue;
  }

  routeCode += `app.use('${route.path}', require('${route.file}')); // ${route.name}\n`;
  routesAdded++;
  console.log(`✅ Added: ${route.name}`);
}

if (routesAdded > 0) {
  // Insérer le code
  const before = serverContent.substring(0, insertPosition);
  const after = serverContent.substring(insertPosition);
  serverContent = before + routeCode + after;

  // Sauvegarder
  fs.writeFileSync(serverPath, serverContent);
  
  console.log(`\n✅ Successfully integrated ${routesAdded} route(s)!`);
  console.log(`ℹ️  ${routesAlreadyPresent} route(s) were already present`);
  console.log('\n🎯 server.js updated. Restart your server to apply changes:');
  console.log('   npm start\n');
} else {
  if (routesAlreadyPresent > 0) {
    console.log(`\n✅ All routes already integrated (${routesAlreadyPresent} routes)`);
    console.log('ℹ️  No changes needed to server.js\n');
  } else {
    console.log('\n⚠️  No routes were added. Check that route files exist.\n');
  }
}

process.exit(0);
