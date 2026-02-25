#!/usr/bin/env node

/**
 * NEXUS DATABASE BACKUP SCRIPT
 * Backup automatique avec rotation et compression
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

const config = {
  dbPath: path.join(__dirname, '..', 'nexus-ultimate.db'),
  backupDir: path.join(__dirname, '..', 'backups'),
  maxBackups: 30, // Garder 30 derniers backups
  compression: true
};

// Colors
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

async function backup() {
  try {
    log('\n🔄 Starting database backup...', 'cyan');

    // Check if database exists
    if (!fs.existsSync(config.dbPath)) {
      log('❌ Database file not found!', 'red');
      log(`   Expected at: ${config.dbPath}`, 'yellow');
      process.exit(1);
    }

    // Create backup directory if not exists
    if (!fs.existsSync(config.backupDir)) {
      fs.mkdirSync(config.backupDir, { recursive: true });
      log(`✅ Created backup directory: ${config.backupDir}`, 'green');
    }

    // Generate backup filename with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFilename = `nexus-backup-${timestamp}.db`;
    const backupPath = path.join(config.backupDir, backupFilename);

    // Get database size
    const dbStats = fs.statSync(config.dbPath);
    log(`📊 Database size: ${formatBytes(dbStats.size)}`, 'cyan');

    // Copy database file
    log('📦 Creating backup...', 'cyan');
    fs.copyFileSync(config.dbPath, backupPath);

    // Calculate checksum
    const hash = crypto.createHash('sha256');
    const fileBuffer = fs.readFileSync(backupPath);
    hash.update(fileBuffer);
    const checksum = hash.digest('hex');

    log(`✅ Backup created: ${backupFilename}`, 'green');
    log(`   Checksum: ${checksum.substring(0, 16)}...`, 'cyan');

    // Compress if enabled
    if (config.compression) {
      log('🗜️  Compressing backup...', 'cyan');
      
      const compressedPath = `${backupPath}.gz`;
      
      try {
        execSync(`gzip -c "${backupPath}" > "${compressedPath}"`, {
          stdio: 'pipe'
        });
        
        fs.unlinkSync(backupPath); // Remove uncompressed file
        
        const compressedStats = fs.statSync(compressedPath);
        const compressionRatio = ((1 - compressedStats.size / dbStats.size) * 100).toFixed(1);
        
        log(`✅ Compressed to: ${formatBytes(compressedStats.size)} (${compressionRatio}% reduction)`, 'green');
        
      } catch (error) {
        log(`⚠️  Compression failed: ${error.message}`, 'yellow');
        log('   Keeping uncompressed backup', 'yellow');
      }
    }

    // Rotation: Delete old backups
    log('\n🧹 Checking backup rotation...', 'cyan');
    
    const backupFiles = fs.readdirSync(config.backupDir)
      .filter(f => f.startsWith('nexus-backup-'))
      .map(f => ({
        name: f,
        path: path.join(config.backupDir, f),
        time: fs.statSync(path.join(config.backupDir, f)).mtime.getTime()
      }))
      .sort((a, b) => b.time - a.time); // Sort by newest first

    if (backupFiles.length > config.maxBackups) {
      const toDelete = backupFiles.slice(config.maxBackups);
      
      log(`   Found ${backupFiles.length} backups, removing ${toDelete.length} old ones...`, 'yellow');
      
      toDelete.forEach(file => {
        fs.unlinkSync(file.path);
        log(`   Deleted: ${file.name}`, 'yellow');
      });
      
      log(`✅ Kept ${config.maxBackups} most recent backups`, 'green');
    } else {
      log(`   ${backupFiles.length} backups total (max: ${config.maxBackups})`, 'cyan');
    }

    // Summary
    log('\n✅ Backup completed successfully!', 'green');
    log(`   Location: ${config.backupDir}`, 'cyan');
    log(`   Total backups: ${Math.min(backupFiles.length, config.maxBackups)}`, 'cyan');

    // Backup metadata
    const metadata = {
      timestamp: new Date().toISOString(),
      originalSize: dbStats.size,
      checksum: checksum,
      compressed: config.compression
    };

    const metadataPath = backupPath.replace('.db', '.json').replace('.gz', '') + '.json';
    fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));

    return true;

  } catch (error) {
    log(`\n❌ Backup failed: ${error.message}`, 'red');
    console.error(error);
    process.exit(1);
  }
}

// Run backup
backup().then(() => {
  log('\n💾 Database backup complete!\n', 'green');
  process.exit(0);
});
