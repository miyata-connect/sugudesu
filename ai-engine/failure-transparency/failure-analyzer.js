// /ai-engine/failure-transparency/failure-analyzer.js
// 行数: 156行

const FailureTracker = require('./failure-tracker');

class FailureAnalyzer {
  constructor(tracker = null) {
    this.tracker = tracker || new FailureTracker();
  }

  async initialize() {
    if (!this.tracker.db) {
      await this.tracker.initialize();
    }
  }

  async analyzeTrends(days = 7) {
    const dailyStats = [];
    
    for (let i = 0; i < days; i++) {
      const stats = await this.tracker.getFailureRate(24);
      const date = new Date();
      date.setDate(date.getDate() - i);
      
      dailyStats.push({
        date: date.toISOString().split('T')[0],
        ...stats
      });
    }

    return dailyStats.reverse();
  }

  async getTopFailureReasons(limit = 5) {
    const sql = `
      SELECT 
        error_type,
        COUNT(*) as occurrence_count,
        AVG(recovery_successful) as avg_recovery_rate,
        GROUP_CONCAT(DISTINCT agent_name) as affected_agents
      FROM agent_executions
      WHERE status = 'failed' AND error_type IS NOT NULL
      GROUP BY error_type
      ORDER BY occurrence_count DESC
      LIMIT ?
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, [limit], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows.map(row => ({
            errorType: row.error_type,
            occurrenceCount: row.occurrence_count,
            avgRecoveryRate: (row.avg_recovery_rate * 100).toFixed(2),
            affectedAgents: row.affected_agents ? row.affected_agents.split(',') : []
          })));
        }
      });
    });
  }

  async getAgentPerformance() {
    const sql = `
      SELECT 
        agent_name,
        role,
        COUNT(*) as total_tasks,
        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_tasks,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_tasks,
        AVG(token_used) as avg_tokens,
        SUM(cost_usd) as total_cost
      FROM agent_executions
      WHERE started_at >= datetime('now', '-7 days')
      GROUP BY agent_name, role
      ORDER BY total_tasks DESC
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows.map(row => ({
            agentName: row.agent_name,
            role: row.role,
            totalTasks: row.total_tasks,
            successfulTasks: row.successful_tasks,
            failedTasks: row.failed_tasks,
            successRate: ((row.successful_tasks / row.total_tasks) * 100).toFixed(2),
            avgTokens: Math.round(row.avg_tokens),
            totalCost: parseFloat(row.total_cost.toFixed(4))
          })));
        }
      });
    });
  }

  async detectPatterns() {
    const patterns = {
      timeBasedFailures: await this.analyzeTimeBasedPatterns(),
      taskTypeFailures: await this.analyzeTaskTypePatterns(),
      recoveryPatterns: await this.analyzeRecoveryPatterns()
    };

    return patterns;
  }

  async analyzeTimeBasedPatterns() {
    const sql = `
      SELECT 
        strftime('%H', started_at) as hour,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failures
      FROM agent_executions
      WHERE started_at >= datetime('now', '-7 days')
      GROUP BY hour
      ORDER BY failures DESC
      LIMIT 3
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows.map(row => ({
            hour: `${row.hour}:00`,
            totalExecutions: row.total,
            failures: row.failures,
            failureRate: ((row.failures / row.total) * 100).toFixed(2)
          })));
        }
      });
    });
  }

  async analyzeTaskTypePatterns() {
    const sql = `
      SELECT 
        role,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failures
      FROM agent_executions
      WHERE started_at >= datetime('now', '-7 days')
      GROUP BY role
      HAVING failures > 0
      ORDER BY failures DESC
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows.map(row => ({
            role: row.role,
            totalTasks: row.total,
            failures: row.failures,
            failureRate: ((row.failures / row.total) * 100).toFixed(2)
          })));
        }
      });
    });
  }

  async analyzeRecoveryPatterns() {
    const sql = `
      SELECT 
        error_type,
        COUNT(*) as total_failures,
        SUM(CASE WHEN recovery_attempted = 1 THEN 1 ELSE 0 END) as recovery_attempts,
        SUM(CASE WHEN recovery_successful = 1 THEN 1 ELSE 0 END) as successful_recoveries
      FROM agent_executions
      WHERE status = 'failed' AND started_at >= datetime('now', '-7 days')
      GROUP BY error_type
      HAVING recovery_attempts > 0
      ORDER BY successful_recoveries DESC
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows.map(row => ({
            errorType: row.error_type,
            totalFailures: row.total_failures,
            recoveryAttempts: row.recovery_attempts,
            successfulRecoveries: row.successful_recoveries,
            recoverySuccessRate: ((row.successful_recoveries / row.recovery_attempts) * 100).toFixed(2)
          })));
        }
      });
    });
  }

  async getImprovementHistory() {
    const sql = `
      SELECT 
        failure_category,
        action_taken,
        implemented_at,
        effectiveness_score
      FROM improvement_actions
      ORDER BY implemented_at DESC
      LIMIT 10
    `;

    return new Promise((resolve, reject) => {
      this.tracker.db.all(sql, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }
}

module.exports = FailureAnalyzer;
