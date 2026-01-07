# SUGUDESU - Shop & Wi-Fi Page Generator

お店のホームページとWi-Fi設定を、すぐに、簡単に。

## 📁 プロジェクト構成

```
プロジェクト/
├── index.html              # メインHTML（UI構造）
├── css/
│   └── style.css          # 全スタイルシート
├── js/
│   ├── config.js          # Firebase設定・定数
│   ├── utils.js           # 共通ユーティリティ関数
│   ├── auth.js            # 認証機能（Google/Apple/LINE/Email/Phone）
│   ├── cloudinary.js      # 画像アップロード
│   ├── ai.js              # AI機能（Gemini）
│   ├── qr.js              # QR生成・PDF出力
│   ├── generator.js       # ページ生成ロジック
│   ├── viewer.js          # ビューワー表示
│   └── receipt.js         # レシート自動保存（PRO版）
├── backup/
│   └── auto-backup.js     # 自動バックアップスクリプト
├── .github/
│   └── workflows/
│       └── backup.yml     # GitHub Actions設定
└── README.md              # このファイル
```

## 🚀 セットアップ手順

### 1. リポジトリの初期化

```bash
# プロジェクトディレクトリで実行
git init
git add .
git commit -m "Initial commit: Modular structure"
```

### 2. GitHubリポジトリの作成

1. GitHub で新しいリポジトリを作成
2. ローカルと接続

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main
```

### 3. 自動バックアップの有効化

#### GitHub Actions（推奨）

- リポジトリにプッシュすると自動的に有効化
- 毎日00:00 JST（15:00 UTC）に自動実行
- 手動実行も可能（GitHub > Actions > Auto Backup > Run workflow）

#### ローカルバックアップ

```bash
# Node.jsが必要
node backup/auto-backup.js
```

または、cronで定期実行

```bash
# crontabに追加（毎日00:00に実行）
0 0 * * * cd /path/to/project && node backup/auto-backup.js
```

## 📦 デプロイ方法

### Firebase Hosting（推奨）

```bash
# Firebase CLI インストール
npm install -g firebase-tools

# ログイン
firebase login

# 初期化
firebase init hosting

# デプロイ
firebase deploy
```

### GitHub Pages

1. GitHub > Settings > Pages
2. Source: `main` branch
3. `index.html` がルートにあることを確認

### Cloudflare Pages

1. Cloudflare Dashboard > Pages
2. Connect to Git
3. プロジェクトを選択
4. Build settings: なし（静的HTML）
5. Deploy

## 🔧 開発

### ファイル編集時の注意

各モジュールは独立しているため、以下のルールを守ってください：

1. **config.js** - 設定変更時のみ編集
2. **utils.js** - 共通関数追加時のみ編集
3. **auth.js** - 認証ロジック変更時のみ編集
4. 他のファイルも同様に、該当機能のみ編集

### 新機能追加

1. 該当するモジュールに関数を追加
2. 必要に応じて `export` で公開
3. 他のモジュールから `import` して使用

例：
```javascript
// utils.js に新機能追加
export function newUtilityFunction() {
    // ...
}

// generator.js で使用
import { newUtilityFunction } from './utils.js';
```

## 🎯 料金プラン

### Normal（無料）
**ターゲット**: 個人の趣味サイト、まずは試したい人、サブドメインで十分な人

- ✅ 簡易HP作成
- ✅ SNS・URL表示
- ✅ 基本情報掲載
- ✅ Wi-Fi QR表示
- ✅ ブラウザから印刷
- 📍 sugudesu.jp サブドメイン

### Plus（¥980/月）
**ターゲット**: 個人事業主（1店舗）、独自ドメインで信頼性向上、Web集客メイン

- ✨ AI搭載HP作成
- ✨ QRコード自動生成
- ✨ PDFダウンロード
- ✨ Googleマップ連携
- ✨ 電話・メール直接発信
- ✨ Wi-Fi自動設定
- ✨ SSIDおすすめ生成
- 📊 **レシート自動保存（NEW！）**
  - カメラでレシート撮影
  - Gemini Flash APIで自動解析
  - Googleスプレッドシートに保存
  - 経費管理を自動化
- 🌐 独自ドメイン対応

### Business（¥2,980/月）
**ターゲット**: 小規模店舗（飲食・美容・小売）、POS機能で店舗運営

- 💼 Plus の全機能
- 🏪 **POS機能**
- 📊 売上管理
- 💰 在庫管理
- 👥 顧客管理
- 📈 分析レポート
- 🌐 最大3サイト
- 🌐 最大3ドメイン

### Premium（¥3,980/月）
**ターゲット**: 複数店舗経営、チェーン展開、制作代行業者

- 🏆 Business の全機能
- ♾️ 無制限サイト
- ♾️ 無制限ドメイン
- 📧 **Gmail連携メーラー（NEW！）**
  - アプリ内で受信トレイ表示
  - メール返信機能
  - テンプレート返信
  - 自動ラベル付け
  - メール検索
  - ユーザーのGmail内で完結（サーバー保存なし）
- 💬 テンプレート返信
- 🏷️ 自動ラベル付け
- 🔍 メール検索
- 📥 CSV一括エクスポート（会計ソフト、在庫システムへの連携用）
- 🎨 カスタムブランディング
- ⚡ 優先処理

## 🔐 環境変数（不要）

このプロジェクトは **完全にクライアントサイド** で動作します。
APIキーは `js/config.js` に直接記述されています。

セキュリティ上問題ないことを確認済み：
- Firebase: 公開APIキー（制限設定済み）
- Cloudinary: アップロード署名でWorker経由
- Gemini: プロキシWorker経由

## 📊 バックアップ管理

### 自動バックアップ

- **頻度**: 毎日 00:00 JST
- **保存先**: `backups/backup-YYYY-MM-DD_HH-MM-SS/`
- **保持期間**: 最新30個（約1ヶ月分）

### 手動バックアップ

```bash
# ローカル実行
node backup/auto-backup.js

# GitHub Actions手動実行
# GitHub > Actions > Auto Backup > Run workflow
```

### バックアップからの復元

```bash
# 特定のバックアップを確認
cd backups/backup-2025-01-06_12-00-00

# ファイルをルートにコピー
cp -r * ../../
```

## 🐛 トラブルシューティング

### ログインできない

1. Firebase Console で認証メソッドが有効か確認
2. `authDomain` が正しいか確認（`js/config.js`）
3. ブラウザのCookieが有効か確認

### 画像アップロードが失敗

1. Cloudinary設定を確認
2. Workers URL が正しいか確認（`js/config.js`）
3. ファイルサイズ制限（10MB以下推奨）

### AI生成が動作しない

1. Gemini Proxy Workers が稼働しているか確認
2. タイムアウト設定を確認（`AI_TIMEOUT_MS`）
3. ネットワーク接続を確認

## 📝 ライセンス

このプロジェクトは個人利用・商用利用ともに自由です。

## 🤝 貢献

バグ報告・機能提案は GitHub Issues へ。

## 📞 サポート

質問・要望は GitHub Discussions または Issues へ。

---

**Made with ❤️ by 宮田康博**
