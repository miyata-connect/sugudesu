#!/usr/bin/env node

/**
 * Auto Backup Script
 * Usage: node backup/auto-backup.js
 * 
 * This script:
 * 1. Commits all changes
 * 2. Pushes to GitHub
 * 3. Creates timestamped backup
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const BACKUP_DIR = path.join(__dirname, '../backups');
const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);

// Ensure backup directory exists
if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function log(message) {
    console.log(`[${new Date().toISOString()}] ${message}`);
}

function exec(command, options = {}) {
    try {
        return execSync(command, {
            encoding: 'utf8',
            stdio: 'pipe',
            ...options
        });
    } catch (error) {
        if (!options.ignoreError) {
            log(`Error executing: ${command}`);
            log(error.message);
            throw error;
        }
        return null;
    }
}

function main() {
    log('=== Starting Auto Backup ===');

    // Check if git is initialized
    if (!fs.existsSync('.git')) {
        log('❌ Git repository not initialized');
        log('Run: git init && git remote add origin YOUR_REPO_URL');
        process.exit(1);
    }

    // Check for changes
    const status = exec('git status --porcelain');
    if (!status || status.trim() === '') {
        log('✅ No changes to commit');
        return;
    }

    log(`📝 Changes detected:\n${status}`);

    // Stage all changes
    log('📦 Staging changes...');
    exec('git add .');

    // Commit
    const commitMessage = `Auto backup: ${TIMESTAMP}`;
    log(`💾 Committing: ${commitMessage}`);
    exec(`git commit -m "${commitMessage}"`);

    // Push to remote
    log('⬆️  Pushing to GitHub...');
    const pushResult = exec('git push origin main', { ignoreError: true });
    
    if (pushResult === null) {
        log('⚠️  Push failed - checking if remote exists...');
        const remotes = exec('git remote -v');
        if (!remotes || !remotes.includes('origin')) {
            log('❌ No remote repository configured');
            log('Run: git remote add origin YOUR_REPO_URL');
        } else {
            log('⚠️  Push failed - may need to pull first');
            log('Run: git pull origin main --rebase');
        }
    } else {
        log('✅ Successfully pushed to GitHub');
    }

    // Create local timestamped backup
    log('📂 Creating local backup...');
    const backupPath = path.join(BACKUP_DIR, `backup-${TIMESTAMP}`);
    fs.mkdirSync(backupPath, { recursive: true });

    // Copy files
    const filesToBackup = [
        'index.html',
        'css/style.css',
        'js/',
        'README.md'
    ];

    filesToBackup.forEach(file => {
        const src = path.join(process.cwd(), file);
        const dest = path.join(backupPath, file);
        
        if (fs.existsSync(src)) {
            if (fs.statSync(src).isDirectory()) {
                fs.cpSync(src, dest, { recursive: true });
            } else {
                fs.mkdirSync(path.dirname(dest), { recursive: true });
                fs.copyFileSync(src, dest);
            }
            log(`  ✓ ${file}`);
        }
    });

    log(`✅ Local backup created: ${backupPath}`);
    log('=== Backup Complete ===');
}

// Run
try {
    main();
} catch (error) {
    log('❌ Backup failed:');
    log(error.message);
    process.exit(1);
}
