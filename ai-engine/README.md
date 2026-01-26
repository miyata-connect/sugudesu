# SUGUDESU AI Engine
## 学習型SkillsMP統合 + 失敗透明性システム

### 🎯 特徴

1. **失敗の透明性**
   - リアルタイム失敗率表示
   - 日次/週次レポート自動生成
   - ユーザーフレンドリーなメッセージ

2. **学習型Skills推薦**
   - 失敗パターンから自動学習
   - SkillsMP対応Skills推薦
   - 優先度付き改善提案

3. **継続的改善**
   - 改善効果の測定
   - 履歴追跡
   - トレンド分析

---

## 🚀 クイックスタート

### インストール

```bash
cd /Users/miyatayasuhiro/Desktop/sugudesu/ai-engine
npm install
```

### デモ実行

```bash
npm run demo
```

---

## 📁 ファイル構成

```
ai-engine/
├── failure-transparency/          # 失敗透明性システム
│   ├── failure-tracker.js         # 失敗記録
│   ├── failure-analyzer.js        # 分析エンジン
│   ├── transparency-dashboard.js  # ダッシュボード
│   └── db/                        # SQLiteデータベース
│       └── failures.sqlite        # 自動生成
│
├── learning-skills-integrator.js  # 学習型Skills統合
├── quick-demo.js                  # クイックデモ
├── package.json                   # npm設定
└── README.md                      # このファイル
```

---

## 💡 使い方

### 基本的な使用例

```javascript
const FailureTracker = require('./failure-transparency/failure-tracker');
const TransparencyDashboard = require('./failure-transparency/transparency-dashboard');
const LearningSkillsIntegrator = require('./learning-skills-integrator');

// 初期化
const tracker = new FailureTracker();
await tracker.initialize();

// 失敗を記録
await tracker.recordExecution({
  executionId: 'exec-123',
  agentName: 'YourAgent',
  role: 'your-role',
  taskDescription: 'タスクの説明',
  status: 'failed', // または 'success'
  errorType: 'rate_limit_exceeded',
  errorMessage: 'API rate limit exceeded',
  tokenUsed: 1500,
  costUsd: 0.003
});

// レポート生成
const dashboard = new TransparencyDashboard();
await dashboard.initialize();
const report = await dashboard.generateDailyReport();
console.log(report);

// 学習推薦
const integrator = new LearningSkillsIntegrator();
await integrator.initialize();
const learningReport = await integrator.generateLearningReport();
console.log(learningReport);
```

---

## 📊 レポート例

### 日次透明性レポート

```
╔════════════════════════════════════════════════════════════╗
║           Multi-Agent System 透明性レポート                ║
╚════════════════════════════════════════════════════════════╝

📊 今日の失敗率: 12.0%
📊 昨日の失敗率: 18.0%
📊 今週の平均: 15.5%

📈 トレンド: 改善中（-6.0%）

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 実行統計（過去24時間）
・総実行回数: 40回
・成功: 35回
・失敗: 5回
・リカバリー試行: 3回
・リカバリー成功: 2回

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💬 ユーザーの皆様へ
🔧 改善傾向にあります！ご不便をおかけしていますが、
   確実に良くなっています。ご協力感謝します。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 改善中です！一緒に育てましょう
```

### 学習型Skills推薦レポート

```
╔════════════════════════════════════════════════════════════╗
║              学習型Skills推薦レポート                       ║
╚════════════════════════════════════════════════════════════╝

1. [rate_limit_exceeded]
   発生回数: 15回
   現在のリカバリー率: 33.33%
   
   推薦Skills:
   - Rate Limiter Pro
   - Backoff Strategy
   - Queue Manager

2. [timeout]
   発生回数: 8回
   現在のリカバリー率: 50.00%
   
   推薦Skills:
   - Timeout Handler
   - Circuit Breaker
   - Async Retry Logic

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 次のステップ:
1. SkillsMP (https://skillsmp.com) で推薦Skillsを検索
2. 適切なSkillsをダウンロード
3. システムに統合してテスト
4. 効果を測定

🔧 継続的に学習・改善していきます！
```

---

## 🔧 Multi-Agent Systemへの統合

### 実行記録の例

```javascript
// あなたのMulti-Agent System内で
const tracker = new FailureTracker();
await tracker.initialize();

async function executeAgent(agentName, task) {
  const executionId = generateId();
  
  try {
    // Agent実行
    const result = await agent.execute(task);
    
    // 成功を記録
    await tracker.recordExecution({
      executionId,
      agentName,
      role: agent.role,
      taskDescription: task.description,
      status: 'success',
      tokenUsed: result.tokensUsed,
      costUsd: result.cost
    });
    
    return result;
  } catch (error) {
    // 失敗を記録
    await tracker.recordExecution({
      executionId,
      agentName,
      role: agent.role,
      taskDescription: task.description,
      status: 'failed',
      errorMessage: error.message,
      errorType: error.type
    });
    
    throw error;
  }
}
```

---

## 📈 次のステップ

1. **SkillsMP探索**: https://skillsmp.com で推薦されたSkillsを検索
2. **Skills統合**: ダウンロードしたSkillsをシステムに統合
3. **効果測定**: 改善効果を定期レポートで確認
4. **継続改善**: 学習サイクルを継続

---

## 🎓 学習サイクル

```
失敗発生 → 記録 → 分析 → Skills推薦 → 統合 → 効果測定
   ↑                                              ↓
   └──────────────────────────────────────────────┘
              継続的改善サイクル
```

---

## ⚙️ 設定

### データベースパス変更

```javascript
const tracker = new FailureTracker('/custom/path/to/failures.sqlite');
```

### レポート出力先変更

```javascript
await dashboard.exportToJson('custom-report.json');
// → /Users/miyatayasuhiro/Desktop/sugudesu/ai-engine/custom-report.json
```

---

## 📝 ライセンス

MIT License

---

## 🤝 サポート

問題が発生した場合:
1. SQLiteがインストールされているか確認
2. Node.js 16以上を使用しているか確認
3. npm installが正常に完了したか確認

---

**🚀 SUGUDESU AI Engineで継続的改善を実現しましょう！**
