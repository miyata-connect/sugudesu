// /ai-engine/cron-scheduler.js
// 行数: 45行
// 定期レポート自動化（将来用）

const cron = require('node-cron');
const TransparencyDashboard = require('./failure-transparency/transparency-dashboard');
const LearningSkillsIntegrator = require('./learning-skills-integrator');
const fs = require('fs').promises;
const path = require('path');

class CronScheduler {
  constructor() {
    this.dashboard = new TransparencyDashboard();
    this.integrator = new LearningSkillsIntegrator();
  }

  async initialize() {
    await this.dashboard.initialize();
    await this.integrator.initialize();
    console.log('✓ Cron Scheduler 初期化完了');
  }

  setupSchedules() {
    console.log('\n定期スケジュール設定中...\n');

    // 毎日深夜2時に日次レポート
    cron.schedule('0 2 * * *', async () => {
      console.log('\n[定期実行] 日次レポート生成開始');
      const report = await this.dashboard.generateDailyReport();
      
      // ファイルに保存
      const filename = `daily-report-${new Date().toISOString().split('T')[0]}.txt`;
      const outputPath = path.join(__dirname, 'outputs', filename);
      await fs.writeFile(outputPath, report);
      
      console.log(`✓ レポート保存: ${outputPath}`);
      
      // ここにSlack/メール通知を追加可能
      // await sendToSlack(report);
    });
    console.log('✓ 日次レポート: 毎日 02:00');

    // 毎週月曜深夜3時に週次レポート + 学習推薦
    cron.schedule('0 3 * * 1', async () => {
      console.log('\n[定期実行] 週次レポート & 学習推薦開始');
      
      const weeklyReport = await this.dashboard.generateWeeklyReport();
      const learningReport = await this.integrator.generateLearningReport();
      
      const combinedReport = weeklyReport + '\n\n' + learningReport;
      
      const filename = `weekly-report-${new Date().toISOString().split('T')[0]}.txt`;
      const outputPath = path.join(__dirname, 'outputs', filename);
      await fs.writeFile(outputPath, combinedReport);
      
      console.log(`✓ 週次レポート保存: ${outputPath}`);
    });
    console.log('✓ 週次レポート: 毎週月曜 03:00\n');
  }
}

// 使用例（コメントアウト - 必要に応じて有効化）
/*
async function main() {
  const scheduler = new CronScheduler();
  await scheduler.initialize();
  scheduler.setupSchedules();
  
  console.log('Cron Scheduler起動中...');
  console.log('Ctrl+Cで停止');
}

if (require.main === module) {
  main().catch(console.error);
}
*/

module.exports = CronScheduler;
