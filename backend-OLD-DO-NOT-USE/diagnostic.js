#!/usr/bin/env node
/**
 * DIAGNOSTIC COMPLET NEXUS
 * Teste TOUT pour trouver le problème
 */

console.log('🔍 NEXUS DIAGNOSTIC COMPLET\n');

// Test 1: Database
console.log('1️⃣ TEST DATABASE');
try {
  const Database = require('better-sqlite3');
  const db = new Database('./nexus-ultimate.db');
  
  // Vérifier que la table users existe
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  console.log(`   ✅ Database ouverte: ${tables.length} tables`);
  
  // Vérifier la structure de users
  const userCols = db.pragma("table_info('users')");
  console.log(`   ✅ Table users: ${userCols.length} colonnes`);
  
  const hasPasswordHash = userCols.some(c => c.name === 'password_hash');
  if (hasPasswordHash) {
    console.log('   ✅ Colonne password_hash existe');
  } else {
    console.log('   ❌ Colonne password_hash MANQUANTE!');
  }
  
  // Compter les users
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get();
  console.log(`   ✅ Utilisateurs existants: ${userCount.c}`);
  
  db.close();
} catch (e) {
  console.log(`   ❌ Erreur database: ${e.message}`);
}

console.log('\n2️⃣ TEST ROUTE AUTH');
try {
  const express = require('express');
  const app = express();
  app.use(express.json());
  
  // Charger la route
  const authRoute = require('./routes/auth');
  app.use('/api/auth', authRoute);
  
  console.log('   ✅ Route auth chargée');
  
  // Vérifier que les routes existent
  const routes = [];
  app._router.stack.forEach(middleware => {
    if (middleware.route) {
      routes.push(middleware.route.path);
    } else if (middleware.name === 'router') {
      middleware.handle.stack.forEach(handler => {
        if (handler.route) {
          routes.push(handler.route.path);
        }
      });
    }
  });
  
  if (routes.length > 0) {
    console.log(`   ✅ Routes trouvées: ${routes.length}`);
  }
  
} catch (e) {
  console.log(`   ❌ Erreur route: ${e.message}`);
  console.log(`   Stack: ${e.stack.split('\n').slice(0, 3).join('\n')}`);
}

console.log('\n3️⃣ TEST BCRYPT');
try {
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync('test123', 12);
  const valid = bcrypt.compareSync('test123', hash);
  if (valid) {
    console.log('   ✅ Bcrypt fonctionne');
  } else {
    console.log('   ❌ Bcrypt ne fonctionne pas');
  }
} catch (e) {
  console.log(`   ❌ Erreur bcrypt: ${e.message}`);
}

console.log('\n4️⃣ TEST JWT');
try {
  const jwt = require('jsonwebtoken');
  const token = jwt.sign({ test: true }, 'secret', { expiresIn: '1h' });
  const decoded = jwt.verify(token, 'secret');
  if (decoded.test) {
    console.log('   ✅ JWT fonctionne');
  }
} catch (e) {
  console.log(`   ❌ Erreur JWT: ${e.message}`);
}

console.log('\n5️⃣ TEST INSCRIPTION COMPLETE');
try {
  const Database = require('better-sqlite3');
  const bcrypt = require('bcryptjs');
  const db = new Database('./nexus-ultimate.db');
  
  const testEmail = 'diagnostic@test.com';
  
  // Supprimer si existe déjà
  db.prepare('DELETE FROM users WHERE email = ?').run(testEmail);
  
  // Créer un utilisateur
  const hash = bcrypt.hashSync('password123', 12);
  const result = db.prepare(`
    INSERT INTO users (email, password_hash, name, role, plan, created_at)
    VALUES (?, ?, ?, 'user', 'free', ?)
  `).run(testEmail, hash, 'Test User', Math.floor(Date.now() / 1000));
  
  console.log(`   ✅ Utilisateur créé: ID ${result.lastInsertRowid}`);
  
  // Vérifier qu'on peut le lire
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(testEmail);
  if (user && user.password_hash) {
    console.log(`   ✅ Utilisateur lu: ${user.email}`);
    
    // Vérifier le password
    const valid = bcrypt.compareSync('password123', user.password_hash);
    if (valid) {
      console.log('   ✅ Mot de passe valide');
    } else {
      console.log('   ❌ Mot de passe invalide');
    }
  } else {
    console.log('   ❌ Utilisateur non trouvé ou password_hash manquant');
  }
  
  // Nettoyer
  db.prepare('DELETE FROM users WHERE email = ?').run(testEmail);
  db.close();
  
} catch (e) {
  console.log(`   ❌ Erreur inscription: ${e.message}`);
  console.log(`   Stack: ${e.stack.split('\n').slice(0, 3).join('\n')}`);
}

console.log('\n6️⃣ TEST SERVER');
try {
  const fs = require('fs');
  const serverContent = fs.readFileSync('./server.js', 'utf8');
  
  if (serverContent.includes("app.use('/api/auth'")) {
    console.log('   ✅ Route /api/auth montée dans server.js');
  } else {
    console.log('   ❌ Route /api/auth NON montée dans server.js');
  }
  
  if (serverContent.includes('app.listen')) {
    console.log('   ✅ Server.listen() présent');
  }
  
} catch (e) {
  console.log(`   ❌ Erreur server: ${e.message}`);
}

console.log('\n════════════════════════════════════════');
console.log('📋 RÉSUMÉ');
console.log('════════════════════════════════════════');
console.log('Si TOUS les tests sont ✅, le problème est ailleurs.');
console.log('Si UN test est ❌, c\'est là le problème.');
console.log('\nPour tester manuellement avec curl:');
console.log('\ncurl -X POST http://localhost:3000/api/auth/register \\');
console.log('  -H "Content-Type: application/json" \\');
console.log('  -d \'{"email":"test@test.com","password":"password123","name":"Test"}\'');
console.log('\nOuvrir F12 dans le navigateur et regarder la console + Network!');
