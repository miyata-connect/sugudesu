# 統合ガイド

## 🎯 実際のMulti-Agent Systemへの統合方法

### 1. 準備完了ファイル

以下のファイルが統合用に準備されています：

```
ai-engine/
├── integration-example.js    ← Multi-Agent統合例
├── cron-scheduler.js         ← 定期レポート自動化
└── README.md                 ← このファイル
```

---

## 📝 統合例1: 基本的な使い方

### ファイル: integration-example.js

```bash
# 実行
node integration-example.js
```

このファイルは：
- ✅ Agent実行の成功/失敗を自動記録
- ✅ 日次レポートを自動生成
- ✅ すぐに使えるサンプルコード

### カスタマイズ方法

1. **`simulateAgentExecution()` を削除**
2. **実際のAgent実行ロジックに置き換え**

```javascript
// Before (シミュレーション)
async simulateAgentExecution(task) { ... }

// After (実際のAgent)
async executeActualAgent(task) {
  // あなたのAgent実行コード
  const result = await yourAgent.execute(task);
  return result;
}
```

---

## 📝 統合例2: 定期レポート自動化

### ファイル: cron-scheduler.js

このファイルは：
- ⏰ 毎日深夜2時に日次レポート
- ⏰ 毎週月曜深夜3時に週次レポート + 学習推薦
- 📁 レポートをファイルに自動保存

### 使い方

1. **コメントアウトを解除**（ファイル最下部）
2. **実行**

```bash
node cron-scheduler.js
```

### Slack通知の追加方法

```javascript
// cron-scheduler.js内
async function sendToSlack(report) {
  const axios = require('axios');
  await axios.post(process.env.SLACK_WEBHOOK_URL, {
    text: report
  });
}

// Cronジョブ内で呼び出し
await sendToSlack(report);
```

---

## 🔧 実際のプロジェクトへの組み込み

### ステップ1: ai-engineフォルダを移動

```bash
# SUGUDESUプロジェクトのメインディレクトリへ
mv /Users/miyatayasuhiro/Desktop/sugudesu/ai-engine /path/to/your/project/
```

### ステップ2: package.jsonに依存関係追加

```json
{
  "dependencies": {
    "sqlite3": "^5.1.7",
    "uuid": "^9.0.1",
    "node-cron": "^3.0.3"
  }
}
```

### ステップ3: 既存コードに統合

```javascript
// あなたのMulti-Agent System
const FailureTracker = require('./ai-engine/failure-transparency/failure-tracker');

class YourMultiAgentSystem {
  constructor() {
    this.tracker = new FailureTracker();
    // ... 既存のコード
  }

  async initialize() {
    await this.tracker.initialize();
    // ... 既存の初期化コード
  }

  async runAgent(agent, task) {
    const executionId = generateId();
    
    try {
      const result = await agent.execute(task);
      
      // 成功記録
      await this.tracker.recordExecution({
        executionId,
        agentName: agent.name,
        role: agent.role,
        taskDescription: task.description,
        status: 'success',
        tokenUsed: result.tokensUsed,
        costUsd: result.cost
      });
      
      return result;
    } catch (error) {
      // 失敗記録
      await this.tracker.recordExecution({
        executionId,
        agentName: agent.name,
        role: agent.role,
        taskDescription: task.description,
        status: 'failed',
        errorMessage: error.message,
        errorType: error.type
      });
      
      throw error;
    }
  }
}
```

---

## 📊 レポート確認方法

### 手動でレポート生成

```javascript
const TransparencyDashboard = require('./ai-engine/failure-transparency/transparency-dashboard');

async function showReport() {
  const dashboard = new TransparencyDashboard();
  await dashboard.initialize();
  
  // 日次レポート
  const daily = await dashboard.generateDailyReport();
  console.log(daily);
  
  // 週次レポート
  const weekly = await dashboard.generateWeeklyReport();
  console.log(weekly);
  
  // リアルタイムステータス
  const status = await dashboard.generateRealtimeStatus();
  console.log(JSON.stringify(status, null, 2));
}

showReport();
```

---

## 🎓 学習推薦の活用

### Skills推薦を取得

```javascript
const LearningSkillsIntegrator = require('./ai-engine/learning-skills-integrator');

async function getSkillRecommendations() {
  const integrator = new LearningSkillsIntegrator();
  await integrator.initialize();
  
  const actions = await integrator.analyzeFailuresAndLearn();
  const report = await integrator.generateLearningReport();
  
  console.log(report);
}

getSkillRecommendations();
```

---

## ⚠️ 重要な注意事項

### データベースの場所

```
ai-engine/failure-transparency/db/failures.sqlite
```

このファイルは自動生成されます。バックアップを定期的に取ってください。

### 環境変数

```bash
# .env ファイル（オプション）
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
REPORT_EMAIL=your-email@example.com
```

---

## 🚀 クイックスタート（復習）

```bash
# 1. デモ実行（動作確認）
cd /Users/miyatayasuhiro/Desktop/sugudesu/ai-engine
npm run demo

# 2. 統合例実行
node integration-example.js

# 3. 実際のプロジェクトに組み込み
# （上記「実際のプロジェクトへの組み込み」参照）
```

---

## 📞 トラブルシューティング

### Q: データベースエラーが出る
A: `npm install sqlite3 --save` を再実行

### Q: レポートが表示されない
A: サンプルデータが必要です。`npm run demo` を実行

### Q: Cronが動かない
A: `npm install node-cron --save` を実行

---

## 💡 次のステップ

1. ✅ integration-example.js を実行して動作確認
2. ✅ 実際のAgent実行ロジックに置き換え
3. ✅ SkillsMP (https://skillsmp.com) で推薦Skills探索
4. ✅ 定期レポート自動化を設定

---

**これで実際のプロジェクトに統合できます！** 🎉
