# SUGUDESU - Shop & Wi-Fi Page Generator

お店のホームページとWi-Fi設定を、すぐに、簡単に。

## 📌 Version
Current Version: **v1.0.0**

---

## 📁 プロジェクト構成

```
プロジェクト/
├── index.html              # メインHTML（エントリーポイント v1.0.0）
├── html/                   # HTMLパーツ（モジュール化）
│   ├── login.html         # v1.0.0 - ログイン画面・認証モーダル
│   ├── pricing.html       # v1.0.0 - 料金プラン4種
│   ├── viewer.html        # v1.0.0 - ビューワーモード
│   └── creator.html       # v1.0.0 - クリエイターモード
├── css/
│   └── style.v4.css       # 全スタイルシート（バージョン管理）
├── js/
│   ├── config.js          # Firebase設定・定数
│   ├── utils.js           # 共通ユーティリティ関数
│   ├── auth.js            # 認証機能（Google/Apple/LINE/Email/Phone）
│   ├── cloudinary.js      # 画像アップロード（Cloudinary + Workers）
│   ├── ai.js              # AI機能（Gemini Flash API）
│   ├── qr.js              # QR生成・PDF出力
│   ├── generator.js       # ページ生成ロジック
│   ├── viewer.js          # ビューワー表示・共有機能
│   └── receipt.js         # レシート自動保存（PRO版・Gemini Flash）
├── backup/
│   └── auto-backup.js     # 自動バックアップスクリプト
├── .github/
│   └── workflows/
│       └── backup.yml     # GitHub Actions設定（毎日自動実行）
└── README.md              # このファイル
```

---

## 🎨 HTMLモジュール詳細

### login.html (v1.0.0)
**内容:**
- ログインウェルカムスクリーン
- 機能紹介セクション
- スティッキーヘッダー（ログインボタン群）
- メール認証モーダル
- 電話番号認証モーダル（SMS）
- レシートスキャナーセクション（PRO版）

**主要機能:**
- Google/Apple/LINE/Email/Phone 認証対応
- レシート撮影→Gemini解析→スプレッドシート保存

### pricing.html (v1.0.0)
**内容:**
- 4つの料金プラン（Normal / Plus / Business / Premium）
- 各プランの機能詳細
- ターゲット顧客の説明

**プラン概要:**
- **Normal（無料）**: 個人趣味、サブドメイン
- **Plus（¥980/月）**: 個人事業主、独自ドメイン、AI搭載
- **Business（¥2,980/月）**: 小規模店舗、POS機能
- **Premium（¥3,980/月）**: 複数店舗、Gmail連携

### viewer.html (v1.0.0)
**内容:**
- 店舗情報カード表示
- Wi-Fi QRコード
- Googleマップリンク・ナビゲーション
- SNSリンク（Instagram/X/Web）
- SNS QRコード（PRO版）
- ページ共有QR（PRO版）

**主要機能:**
- タップでパスワードコピー
- Googleマップ案内（PRO）
- 電話発信（PRO）
- ページシェア機能

### creator.html (v1.0.0)
**内容:**
- 店舗情報入力フォーム
- カテゴリ選択（店舗/企業）
- 画像アップロード（PRO）
- 営業時間・休業日設定
- SNS情報入力
- SSID設定・おすすめ生成（PRO）
- ページ生成結果表示
- ルーター設定支援

**主要機能:**
- AIによるSSID提案（PRO）
- QRコード自動生成
- PDFダウンロード（PRO）
- ルーター設定ガイド

---

## 🚀 セットアップ手順

### 1. リポジトリの初期化

```bash
# プロジェクトディレクトリで実行
git init
git add .
git commit -m "Initial commit: Modular structure v1.0.0"
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

---

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

---

## 🔧 開発ガイド

### HTMLパーツの編集方法

各HTMLパーツにはバージョンコメントがあります：
```html
<!-- filename.html vX.X.X -->
```

**変更手順:**
1. 該当するHTMLファイルを編集
2. 必要に応じてバージョン番号を更新
3. ローカルでテスト
4. コミット・プッシュ

### 新機能の追加

1. 該当するモジュール（`js/*.js`）に関数を追加
2. 必要に応じて `export` で公開
3. 他のモジュールから `import` して使用

**例:**
```javascript
// utils.js に新機能追加
export function newUtilityFunction() {
    // ...
}

// generator.js で使用
import { newUtilityFunction } from './utils.js';
```

### HTMLパーツの動的読み込み

`index.html` では各HTMLパーツを `fetch()` で読み込みます：

```javascript
async function loadHTMLParts() {
    const loginResponse = await fetch('html/login.html');
    const loginHTML = await loginResponse.text();
    document.getElementById('login-container').innerHTML = loginHTML;
    // ...
}
```

---

## 🎯 料金プラン詳細

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

---

## 🔐 環境変数（不要）

このプロジェクトは **完全にクライアントサイド** で動作します。
APIキーは `js/config.js` に直接記述されています。

**セキュリティ上問題ない理由:**
- **Firebase**: 公開APIキー（ドメイン制限設定済み）
- **Cloudinary**: アップロード署名でWorker経由
- **Gemini**: プロキシWorker経由（APIキー非公開）

---

## 📊 バックアップ管理

### 自動バックアップ

- **頻度**: 毎日 00:00 JST（15:00 UTC）
- **保存先**: `backups/backup-YYYY-MM-DD_HH-MM-SS/`
- **保持期間**: 最新30個（約1ヶ月分）
- **対象ファイル**: `index.html`, `css/`, `js/`, `html/`

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
cd backups/backup-2025-01-08_12-00-00

# ファイルをルートにコピー
cp -r * ../../

# または個別ファイルを復元
cp index.html ../../
cp -r js/ ../../js/
```

---

## 🐛 トラブルシューティング

### ログインできない

**原因:**
- Firebase Consoleで認証メソッドが無効
- `authDomain` の設定ミス
- ブラウザのCookie無効

**解決方法:**
1. Firebase Console > Authentication > Sign-in method で各プロバイダーを有効化
2. `js/config.js` の `authDomain` を確認
   - Firebase Hosting使用: `プロジェクトID.web.app`
   - カスタムドメイン: `sugudesu.jp`
3. ブラウザのCookie設定を確認

### 画像アップロードが失敗

**原因:**
- Cloudinary設定エラー
- Workers URLが間違っている
- ファイルサイズ超過

**解決方法:**
1. Cloudinary Dashboard で設定を確認
2. `js/config.js` の `CLOUDINARY_UPLOAD_URL` を確認
3. ファイルサイズを10MB以下に制限

### AI生成が動作しない

**原因:**
- Gemini Proxy Workers が停止
- タイムアウト
- ネットワークエラー

**解決方法:**
1. Workers URL が稼働しているか確認
2. `js/config.js` の `AI_TIMEOUT_MS` を増やす（30000推奨）
3. ブラウザのコンソールでエラーを確認

### HTMLパーツが読み込まれない

**原因:**
- ファイルパスのミス
- CORSエラー（ローカル開発時）
- HTMLファイルの破損

**解決方法:**
1. `html/` ディレクトリ内のファイル名を確認
2. ローカルサーバーで実行（`python -m http.server` など）
3. ブラウザのコンソールでエラーメッセージを確認

---

## 🔄 アップデート履歴

### v1.0.0 (2025-01-08)
- HTMLモジュール化
- login.html / pricing.html / viewer.html / creator.html に分割
- 各ファイルにバージョン番号追加
- README.md 全面刷新

---

## 📝 今後の予定

- [ ] JSモジュールのさらなる細分化
- [ ] HTMLパーツの遅延読み込み（Lazy Loading）
- [ ] バージョン管理システムの強化
- [ ] ユニットテストの追加
- [ ] TypeScript化の検討

---

## 📄 ライセンス

このプロジェクトは個人利用・商用利用ともに自由です。

**Proprietary - miyata-connect**

---

## 🤝 貢献

バグ報告・機能提案は GitHub Issues へ。
プルリクエストも歓迎します。

---

## 📞 サポート

質問・要望は GitHub Discussions または Issues へ。

**Repository**: https://github.com/miyata-connect/sugudesu

---

**Made with ❤️ by 宮田康博**
