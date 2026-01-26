// /ai-engine/learning-skills-integrator.js
// 行数: 130行（簡略版 - 即時使用可能）

const FailureAnalyzer = require('./failure-transparency/failure-analyzer');
const FailureTracker = require('./failure-transparency/failure-tracker');
const fs = require('fs').promises;
const path = require('path');

class LearningSkillsIntegrator {
  constructor() {
    this.failureAnalyzer = new FailureAnalyzer();
    this.failureTracker = new FailureTracker();
    this.learningHistory = [];
  }

  async initialize() {
    await this.failureTracker.initialize();
    await this.failureAnalyzer.initialize();
    
    console.log('✓ 学習型Skills統合システム初期化完了');
  }

  async analyzeFailuresAndLearn() {
    console.log('\n=== 失敗分析 & 学習プロセス開始 ===\n');

    const topFailures = await this.failureAnalyzer.getTopFailureReasons(10);
    console.log(`検出された失敗パターン: ${topFailures.length}件\n`);

    const learningActions = [];

    for (const failure of topFailures) {
      console.log(`[失敗分析] ${failure.errorType}`);
      console.log(`  発生回数: ${failure.occurrenceCount}回`);
      console.log(`  現在のリカバリー率: ${failure.avgRecoveryRate}%`);

      const recommendedSkills = this.generateSkillRecommendations(failure);
      
      if (recommendedSkills.length > 0) {
        console.log(`  → ${recommendedSkills.length}個の対応Skillsを推薦`);
        
        learningActions.push({
          failureType: failure.errorType,
          recommendedSkills: recommendedSkills,
          priority: this.calculatePriority(failure),
          timestamp: new Date().toISOString()
        });
      }
      
      console.log('');
    }

    learningActions.sort((a, b) => b.priority - a.priority);
    
    console.log(`\n優先度順に${learningActions.length}件の学習推薦を生成しました\n`);

    await this.saveLearningHistory(learningActions);

    console.log('\n=== 学習プロセス完了 ===\n');
    
    return learningActions;
  }

  generateSkillRecommendations(failure) {
    const errorTypeMap = {
      'rate_limit_exceeded': [
        { name: 'Rate Limiter Pro', category: 'resilience', priority: 'high' },
        { name: 'Backoff Strategy', category: 'retry-logic', priority: 'high' },
        { name: 'Queue Manager', category: 'optimization', priority: 'medium' }
      ],
      'timeout': [
        { name: 'Timeout Handler', category: 'error-handling', priority: 'high' },
        { name: 'Circuit Breaker', category: 'resilience', priority: 'high' },
        { name: 'Async Retry Logic', category: 'retry-logic', priority: 'medium' }
      ],
      'invalid_response': [
        { name: 'Response Validator', category: 'validation', priority: 'high' },
        { name: 'Schema Checker', category: 'validation', priority: 'medium' },
        { name: 'Data Sanitizer', category: 'security', priority: 'medium' }
      ],
      'authentication_failed': [
        { name: 'Auth Refresher', category: 'authentication', priority: 'critical' },
        { name: 'Token Manager', category: 'authentication', priority: 'high' }
      ]
    };

    const recommendations = errorTypeMap[failure.errorType] || [
      { name: 'Generic Error Handler', category: 'error-handling', priority: 'low' }
    ];

    return recommendations.map(skill => ({
      ...skill,
      failureContext: failure.errorType,
      affectedAgents: failure.affectedAgents
    }));
  }

  calculatePriority(failure) {
    const frequencyScore = Math.min(failure.occurrenceCount / 10, 10);
    const recoveryScore = (100 - parseFloat(failure.avgRecoveryRate)) / 10;
    
    return frequencyScore + recoveryScore;
  }

  async saveLearningHistory(actions) {
    const historyPath = path.join(__dirname, 'learning-history.json');
    
    let history = [];
    try {
      const existing = await fs.readFile(historyPath, 'utf-8');
      history = JSON.parse(existing);
    } catch (error) {
      // 新規作成
    }

    history.push({
      timestamp: new Date().toISOString(),
      actionsCount: actions.length,
      actions: actions.map(a => ({
        failureType: a.failureType,
        skillsCount: a.recommendedSkills.length,
        priority: a.priority
      }))
    });

    if (history.length > 100) {
      history = history.slice(-100);
    }

    await fs.writeFile(historyPath, JSON.stringify(history, null, 2));
    console.log(`学習履歴保存: ${history.length}件`);
  }

  async generateLearningReport() {
    const topFailures = await this.failureAnalyzer.getTopFailureReasons(5);
    const actions = [];

    for (const failure of topFailures) {
      const skills = this.generateSkillRecommendations(failure);
      actions.push({
        failureType: failure.errorType,
        occurrenceCount: failure.occurrenceCount,
        currentRecoveryRate: failure.avgRecoveryRate,
        recommendedSkills: skills.slice(0, 3).map(s => s.name)
      });
    }

    return `
╔════════════════════════════════════════════════════════════╗
║              学習型Skills推薦レポート                       ║
╚════════════════════════════════════════════════════════════╝

${actions.map((action, i) => `
${i + 1}. [${action.failureType}]
   発生回数: ${action.occurrenceCount}回
   現在のリカバリー率: ${action.currentRecoveryRate}%
   
   推薦Skills:
${action.recommendedSkills.map(s => `   - ${s}`).join('\n')}
`).join('\n')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 次のステップ:
1. SkillsMP (https://skillsmp.com) で推薦Skillsを検索
2. 適切なSkillsをダウンロード
3. システムに統合してテスト
4. 効果を測定

🔧 継続的に学習・改善していきます！
    `;
  }
}

module.exports = LearningSkillsIntegrator;
