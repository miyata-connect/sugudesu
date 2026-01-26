// /ai-engine/quick-demo.js
// 行数: 105行
// 即時実行可能なデモスクリプト

const FailureTracker = require('./failure-transparency/failure-tracker');
const TransparencyDashboard = require('./failure-transparency/transparency-dashboard');
const LearningSkillsIntegrator = require('./learning-skills-integrator');
const { v4: uuidv4 } = require('uuid');

async function quickDemo() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║  学習型SkillsMP統合 + 失敗透明性システム クイックデモ          ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log('\n');

  try {
    // 1. 初期化
    console.log('=== Step 1: システム初期化 ===\n');
    const tracker = new FailureTracker();
    await tracker.initialize();

    const dashboard = new TransparencyDashboard();
    await dashboard.initialize();

    const integrator = new LearningSkillsIntegrator();
    await integrator.initialize();

    // 2. サンプルデータ投入
    console.log('\n=== Step 2: サンプル失敗データ投入 ===\n');
    await injectSampleData(tracker);

    // 3. 日次レポート生成
    console.log('\n=== Step 3: 透明性レポート生成 ===\n');
    const dailyReport = await dashboard.generateDailyReport();
    console.log(dailyReport);

    // 4. 学習推薦生成
    console.log('\n=== Step 4: 学習型Skills推薦 ===\n');
    const learningActions = await integrator.analyzeFailuresAndLearn();
    
    const learningReport = await integrator.generateLearningReport();
    console.log(learningReport);

    // 5. クリーンアップ
    await tracker.close();

    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║                    デモ完了！                                   ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');

    console.log('次のステップ:');
    console.log('1. SkillsMP (https://skillsmp.com) で推薦Skillsを確認');
    console.log('2. 実際のMulti-Agent Systemに統合');
    console.log('3. 継続的な学習・改善サイクルを開始\n');

  } catch (error) {
    console.error('\n❌ エラー発生:', error);
    console.error(error.stack);
    process.exit(1);
  }
}

async function injectSampleData(tracker) {
  const sampleFailures = [
    {
      agentName: 'Tracker-Agent',
      role: 'usage-tracking',
      errorType: 'rate_limit_exceeded',
      count: 15
    },
    {
      agentName: 'Analyzer-Agent',
      role: 'data-analysis',
      errorType: 'timeout',
      count: 8
    },
    {
      agentName: 'Analyzer-Agent',
      role: 'data-analysis',
      errorType: 'invalid_response',
      count: 12
    },
    {
      agentName: 'Synthesizer-Agent',
      role: 'code-synthesis',
      errorType: 'authentication_failed',
      count: 5
    }
  ];

  let totalInjected = 0;

  for (const failure of sampleFailures) {
    console.log(`投入中: ${failure.errorType} (${failure.count}回)`);
    
    for (let i = 0; i < failure.count; i++) {
      const executionId = uuidv4();
      
      await tracker.recordExecution({
        executionId: executionId,
        agentName: failure.agentName,
        role: failure.role,
        taskDescription: `サンプルタスク ${i + 1}`,
        status: 'failed',
        errorMessage: `${failure.errorType}が発生しました`,
        errorType: failure.errorType,
        tokenUsed: Math.floor(Math.random() * 1000) + 500,
        costUsd: Math.random() * 0.01
      });

      await tracker.categorizeFailure(
        executionId,
        failure.errorType,
        'medium',
        true
      );

      totalInjected++;
    }
  }

  console.log(`\n✓ ${totalInjected}件の失敗データを投入完了\n`);
}

// 実行
if (require.main === module) {
  quickDemo().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { quickDemo };
