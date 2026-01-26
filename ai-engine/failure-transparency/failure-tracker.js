// /ai-engine/failure-transparency/failure-tracker.js
// 行数: 128行

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs').promises;

class FailureTracker {
  constructor(dbPath = null) {
    this.dbPath = dbPath || path.join(__dirname, 'db', 'failures.sqlite');
    this.db = null;
  }

  async initialize() {
    await this.ensureDbDirectory();
    
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, async (err) => {
        if (err) {
          reject(err);
        } else {
          await this.createTables();
          console.log('✓ Failure Tracker初期化完了');
          resolve();
        }
      });
    });
  }

  async ensureDbDirectory() {
    const dbDir = path.dirname(this.dbPath);
    try {
      await fs.mkdir(dbDir, { recursive: true });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }

  async createTables() {
    const createTableSQL = `
      CREATE TABLE IF NOT EXISTS agent_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        execution_id TEXT UNIQUE NOT NULL,
        agent_name TEXT NOT NULL,
        role TEXT NOT NULL,
        task_description TEXT,
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        status TEXT NOT NULL,
        error_message TEXT,
        error_type TEXT,
        recovery_attempted BOOLEAN DEFAULT 0,
        recovery_successful BOOLEAN DEFAULT 0,
        token_used INTEGER,
        cost_usd REAL,
        user_visible BOOLEAN DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS failure_categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        execution_id TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        auto_recoverable BOOLEAN DEFAULT 0,
        FOREIGN KEY (execution_id) REFERENCES agent_executions(execution_id)
      );

      CREATE TABLE IF NOT EXISTS improvement_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        failure_category TEXT NOT NULL,
        action_taken TEXT NOT NULL,
        implemented_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        effectiveness_score REAL
      );

      CREATE TABLE IF NOT EXISTS skill_acquisitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        failure_type TEXT NOT NULL,
        role_id TEXT NOT NULL,
        skill_name TEXT NOT NULL,
        skill_source TEXT,
        priority REAL,
        acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_execution_status ON agent_executions(status);
      CREATE INDEX IF NOT EXISTS idx_execution_date ON agent_executions(started_at);
      CREATE INDEX IF NOT EXISTS idx_agent_name ON agent_executions(agent_name);
    `;

    return new Promise((resolve, reject) => {
      this.db.exec(createTableSQL, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async recordExecution(executionData) {
    const {
      executionId,
      agentName,
      role,
      taskDescription,
      status,
      errorMessage = null,
      errorType = null,
      tokenUsed = 0,
      costUsd = 0
    } = executionData;

    const sql = `
      INSERT INTO agent_executions 
      (execution_id, agent_name, role, task_description, status, error_message, error_type, token_used, cost_usd)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    return new Promise((resolve, reject) => {
      this.db.run(sql, [
        executionId,
        agentName,
        role,
        taskDescription,
        status,
        errorMessage,
        errorType,
        tokenUsed,
        costUsd
      ], function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });
  }

  async updateExecution(executionId, updates) {
    const {
      completedAt = new Date().toISOString(),
      status,
      errorMessage = null,
      errorType = null,
      recoveryAttempted = false,
      recoverySuccessful = false
    } = updates;

    const sql = `
      UPDATE agent_executions 
      SET completed_at = ?, status = ?, error_message = ?, error_type = ?,
          recovery_attempted = ?, recovery_successful = ?
      WHERE execution_id = ?
    `;

    return new Promise((resolve, reject) => {
      this.db.run(sql, [
        completedAt,
        status,
        errorMessage,
        errorType,
        recoveryAttempted ? 1 : 0,
        recoverySuccessful ? 1 : 0,
        executionId
      ], function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });
  }

  async categorizeFailure(executionId, category, severity, autoRecoverable = false) {
    const sql = `
      INSERT INTO failure_categories (execution_id, category, severity, auto_recoverable)
      VALUES (?, ?, ?, ?)
    `;

    return new Promise((resolve, reject) => {
      this.db.run(sql, [executionId, category, severity, autoRecoverable ? 1 : 0], function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });
  }

  async recordImprovementAction(failureCategory, actionTaken, effectivenessScore = null) {
    const sql = `
      INSERT INTO improvement_actions (failure_category, action_taken, effectiveness_score)
      VALUES (?, ?, ?)
    `;

    return new Promise((resolve, reject) => {
      this.db.run(sql, [failureCategory, actionTaken, effectivenessScore], function(err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });
  }

  async getFailureRate(periodHours = 24) {
    const sql = `
      SELECT 
        COUNT(*) as total_executions,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_executions,
        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_executions,
        SUM(CASE WHEN recovery_attempted = 1 THEN 1 ELSE 0 END) as recovery_attempts,
        SUM(CASE WHEN recovery_successful = 1 THEN 1 ELSE 0 END) as successful_recoveries
      FROM agent_executions
      WHERE started_at >= datetime('now', '-${periodHours} hours')
    `;

    return new Promise((resolve, reject) => {
      this.db.get(sql, (err, row) => {
        if (err) {
          reject(err);
        } else {
          const failureRate = row.total_executions > 0 
            ? (row.failed_executions / row.total_executions * 100).toFixed(2)
            : 0;
          
          resolve({
            totalExecutions: row.total_executions,
            failedExecutions: row.failed_executions,
            successfulExecutions: row.successful_executions,
            failureRate: parseFloat(failureRate),
            recoveryAttempts: row.recovery_attempts,
            successfulRecoveries: row.successful_recoveries,
            recoverySuccessRate: row.recovery_attempts > 0
              ? (row.successful_recoveries / row.recovery_attempts * 100).toFixed(2)
              : 0
          });
        }
      });
    });
  }

  async close() {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      } else {
        resolve();
      }
    });
  }
}

module.exports = FailureTracker;
