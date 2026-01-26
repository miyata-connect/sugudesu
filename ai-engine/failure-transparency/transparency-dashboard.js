// /ai-engine/failure-transparency/transparency-dashboard.js
// 行数: 185行

const FailureAnalyzer = require('./failure-analyzer');
const FailureTracker = require('./failure-tracker');

class TransparencyDashboard {
  constructor() {
    this.tracker = new FailureTracker();
    this.analyzer = new FailureAnalyzer(this.tracker);
  }

  async initialize() {
    await this.tracker.initialize();
    await this.analyzer.initialize();
  }

  async generateDailyReport() {
    const todayStats = await this.tracker.getFailureRate(24);
    const yesterdayStats = await this.tracker.getFailureRate(48);
    const weeklyStats = await this.tracker.getFailureRate(168);

    const report = this.formatDailyReport(todayStats, yesterdayStats, weeklyStats);
    
    return report;
  }

  formatDailyReport(today, yesterday, weekly) {
    const todayRate = today.failureRate;
    const yesterdayRate = yesterday.failureRate;
    const weeklyRate = weekly.failureRate;

    const improvement = yesterdayRate - todayRate;
    const trendEmoji = improvement > 0 ? '📈' : improvement < 0 ? '📉' : '➡️';
    const trendText = improvement > 0 
      ? `改善中（-${improvement.toFixed(1)}%）` 
      : improvement < 0 
      ? `要注意（+${Math.abs(improvement).toFixed(1)}%）`
      : '横ばい';

    return `
╔════════════════════════════════════════════════════════════╗
║           Multi-Agent System 透明性レポート                ║
╚════════════════════════════════════════════════════════════╝

📊 今日の失敗率: ${todayRate}%
📊 昨日の失敗率: ${yesterdayRate}%
📊 今週の平均: ${weeklyRate}%

${trendEmoji} トレンド: ${trendText}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 実行統計（過去24時間）
・総実行回数: ${today.totalExecutions}回
・成功: ${today.successfulExecutions}回
・失敗: ${today.failedExecutions}回
・リカバリー試行: ${today.recoveryAttempts}回
・リカバリー成功: ${today.successfulRecoveries}回
・リカバリー成功率: ${today.recoverySuccessRate}%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💬 ユーザーの皆様へ

${this.generateUserMessage(todayRate, improvement)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 改善中です！一緒に育てましょう
    `;
  }

  generateUserMessage(failureRate, improvement) {
    if (failureRate < 5) {
      return '✨ 素晴らしい！システムは非常に安定しています。\n   引き続き高品質なサービスを提供します。';
    } else if (failureRate < 10) {
      return '👍 良好な状態です。小さな失敗から学びながら\n   日々改善を続けています。';
    } else if (failureRate < 15) {
      if (improvement > 0) {
        return '🔧 改善傾向にあります！ご不便をおかけしていますが、\n   確実に良くなっています。ご協力感謝します。';
      } else {
        return '⚠️  現在、品質改善に取り組んでいます。\n   ご不便をおかけして申し訳ございません。';
      }
    } else {
      return '🚧 重点的に改善作業中です。\n   一時的にご不便をおかけしますが、より良いシステムを\n   目指して全力で取り組んでいます。';
    }
  }

  async generateWeeklyReport() {
    const trends = await this.analyzer.analyzeTrends(7);
    const topFailures = await this.analyzer.getTopFailureReasons(5);
    const agentPerformance = await this.analyzer.getAgentPerformance();
    const patterns = await this.analyzer.detectPatterns();
    const improvements = await this.analyzer.getImprovementHistory();

    return this.formatWeeklyReport(trends, topFailures, agentPerformance, patterns, improvements);
  }

  formatWeeklyReport(trends, topFailures, agentPerformance, patterns, improvements) {
    const trendLines = trends.map(day => 
      `${day.date}: ${day.failureRate}% (${day.totalExecutions}回実行)`
    ).join('\n');

    const failureLines = topFailures.map((f, i) => 
      `${i + 1}. ${f.errorType}: ${f.occurrenceCount}回 (リカバリー率: ${f.avgRecoveryRate}%)`
    ).join('\n');

    const agentLines = agentPerformance.slice(0, 5).map((a, i) => 
      `${i + 1}. ${a.agentName} (${a.role})
   - 成功率: ${a.successRate}%
   - タスク数: ${a.totalTasks}回
   - コスト: $${a.totalCost}`
    ).join('\n\n');

    const improvementLines = improvements.slice(0, 5).map((imp, i) => 
      `${i + 1}. [${imp.failure_category}] ${imp.action_taken}
   実施日: ${new Date(imp.implemented_at).toLocaleDateString()}
   効果: ${imp.effectiveness_score ? imp.effectiveness_score + '点' : '評価中'}`
    ).join('\n\n');

    return `
╔════════════════════════════════════════════════════════════╗
║         Multi-Agent System 週次透明性レポート              ║
╚════════════════════════════════════════════════════════════╝

📊 過去7日間のトレンド
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${trendLines}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 主な失敗原因 TOP5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${failureLines}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Agent別パフォーマンス
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${agentLines}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 検出されたパターン
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【時間帯別の傾向】
${patterns.timeBasedFailures.map(p => `${p.hour}: 失敗率 ${p.failureRate}%`).join('\n')}

【タスク種別の傾向】
${patterns.taskTypeFailures.map(p => `${p.role}: 失敗率 ${p.failureRate}%`).join('\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ 実施した改善アクション
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
${improvementLines}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💬 来週の改善目標
・失敗率を${this.calculateTargetRate(trends)}%以下に削減
・リカバリー成功率を90%以上に向上
・新たなパターン検出と対策実施

🔧 改善は継続中です！ご協力ありがとうございます。
    `;
  }

  calculateTargetRate(trends) {
    const latestRate = trends[trends.length - 1].failureRate;
    const targetRate = Math.max(latestRate * 0.8, 5);
    return targetRate.toFixed(1);
  }

  async generateRealtimeStatus() {
    const last1Hour = await this.tracker.getFailureRate(1);
    const last24Hours = await this.tracker.getFailureRate(24);

    const status = {
      timestamp: new Date().toISOString(),
      last1Hour: {
        failureRate: last1Hour.failureRate,
        totalExecutions: last1Hour.totalExecutions,
        status: this.getStatusLevel(last1Hour.failureRate)
      },
      last24Hours: {
        failureRate: last24Hours.failureRate,
        totalExecutions: last24Hours.totalExecutions,
        status: this.getStatusLevel(last24Hours.failureRate)
      },
      message: this.generateStatusMessage(last1Hour.failureRate, last24Hours.failureRate)
    };

    return status;
  }

  getStatusLevel(failureRate) {
    if (failureRate < 5) return '優秀';
    if (failureRate < 10) return '良好';
    if (failureRate < 15) return '注意';
    return '改善中';
  }

  generateStatusMessage(currentRate, dailyRate) {
    if (currentRate > dailyRate * 1.5) {
      return '⚠️ 現在、通常より失敗率が高めです。調査中です。';
    } else if (currentRate < dailyRate * 0.5) {
      return '✨ 現在、非常に安定して動作しています！';
    } else {
      return '👍 正常に動作しています。';
    }
  }

  async exportToJson(filename) {
    const data = {
      dailyReport: await this.generateDailyReport(),
      weeklyReport: await this.generateWeeklyReport(),
      realtimeStatus: await this.generateRealtimeStatus(),
      generatedAt: new Date().toISOString()
    };

    const fs = require('fs').promises;
    const path = require('path');
    const outputPath = path.join('/Users/miyatayasuhiro/Desktop/sugudesu/ai-engine', filename);

    await fs.writeFile(outputPath, JSON.stringify(data, null, 2));
    console.log(`✓ レポート出力: ${outputPath}`);
    
    return outputPath;
  }
}

module.exports = TransparencyDashboard;
