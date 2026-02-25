/**
 * Database Migration Runner
 * Applique toutes les migrations v5.0
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, '..', 'nexus-ultimate.db');
const db = new Database(dbPath);

// Enable foreign keys and WAL mode
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

console.log('🔄 Starting NEXUS v5.0 database migrations...\n');

// Read migration file
const migrationFile = path.join(__dirname, 'v5.0-complete.sql');
const migrationSQL = fs.readFileSync(migrationFile, 'utf8');

try {
  // Execute migration in a transaction
  db.exec('BEGIN TRANSACTION');
  
  // Split by semicolon and execute each statement
  const statements = migrationSQL
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0 && !s.startsWith('--'));

  let executed = 0;
  let skipped = 0;

  for (const statement of statements) {
    try {
      db.exec(statement + ';');
      executed++;
      
      // Log table creation
      if (statement.includes('CREATE TABLE')) {
        const tableName = statement.match(/CREATE TABLE IF NOT EXISTS (\w+)/)?.[1];
        if (tableName) {
          console.log(`✅ Created table: ${tableName}`);
        }
      }
      
      // Log index creation
      if (statement.includes('CREATE INDEX')) {
        const indexName = statement.match(/CREATE INDEX IF NOT EXISTS (\w+)/)?.[1];
        if (indexName) {
          console.log(`✅ Created index: ${indexName}`);
        }
      }
    } catch (error) {
      // Skip if table already exists
      if (error.message.includes('already exists')) {
        skipped++;
      } else {
        console.error(`❌ Error executing statement: ${error.message}`);
        console.error(`   Statement: ${statement.substring(0, 100)}...`);
        throw error;
      }
    }
  }

  db.exec('COMMIT');

  console.log(`\n✅ Migration complete!`);
  console.log(`   Statements executed: ${executed}`);
  console.log(`   Statements skipped: ${skipped}`);

  // Verify tables
  console.log('\n📊 Database Statistics:');
  
  const tables = db.prepare(`
    SELECT COUNT(*) as count 
    FROM sqlite_master 
    WHERE type='table' AND name NOT LIKE 'sqlite_%'
  `).get();
  
  const indexes = db.prepare(`
    SELECT COUNT(*) as count 
    FROM sqlite_master 
    WHERE type='index' AND name NOT LIKE 'sqlite_%'
  `).get();

  console.log(`   Total tables: ${tables.count}`);
  console.log(`   Total indexes: ${indexes.count}`);

  // List all tables
  console.log('\n📋 All Tables:');
  const allTables = db.prepare(`
    SELECT name FROM sqlite_master 
    WHERE type='table' AND name NOT LIKE 'sqlite_%'
    ORDER BY name
  `).all();

  allTables.forEach((table, index) => {
    console.log(`   ${index + 1}. ${table.name}`);
  });

  console.log('\n✅ NEXUS v5.0 database is ready!');

} catch (error) {
  db.exec('ROLLBACK');
  console.error('\n❌ Migration failed:', error.message);
  process.exit(1);
}

db.close();
