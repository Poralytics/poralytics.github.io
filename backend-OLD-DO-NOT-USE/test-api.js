#!/usr/bin/env node
/**
 * TEST API DIRECT
 * Teste l'API sans passer par le navigateur
 */

const http = require('http');

console.log('🧪 TEST API DIRECT - INSCRIPTION\n');

const testData = {
  email: 'apitest@example.com',
  password: 'password123',
  name: 'API Test User'
};

const postData = JSON.stringify(testData);

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/api/auth/register',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(postData)
  }
};

console.log('📋 Configuration:');
console.log(`   URL: http://${options.hostname}:${options.port}${options.path}`);
console.log(`   Method: ${options.method}`);
console.log(`   Data: ${postData}\n`);

console.log('📡 Envoi de la requête...\n');

const req = http.request(options, (res) => {
  console.log(`✅ Status: ${res.statusCode} ${res.statusMessage}`);
  console.log(`📋 Headers:`);
  Object.keys(res.headers).forEach(key => {
    console.log(`   ${key}: ${res.headers[key]}`);
  });
  console.log('');

  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('📄 Response body:');
    console.log(data);
    console.log('');
    
    try {
      const json = JSON.parse(data);
      console.log('✅ JSON valide');
      console.log('📦 Parsed:');
      console.log(JSON.stringify(json, null, 2));
      
      if (json.success && json.token) {
        console.log('\n🎉 TEST RÉUSSI!');
        console.log('   ✅ Token reçu');
        console.log('   ✅ User créé:', json.user.email);
      } else if (json.error) {
        console.log('\n⚠️  Erreur API:', json.error);
      }
    } catch (e) {
      console.log('❌ Réponse non-JSON:', e.message);
    }
  });
});

req.on('error', (e) => {
  console.error(`❌ Erreur requête: ${e.message}`);
  console.error('\n🔍 Vérifications:');
  console.error('   1. Le serveur est-il démarré? (npm start)');
  console.error('   2. Le serveur écoute-t-il sur le port 3000?');
  console.error('   3. Y a-t-il un firewall qui bloque?');
});

req.write(postData);
req.end();
