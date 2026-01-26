# SUGUDESU SKILL v3.0

**プロジェクト**: SUGUDESU - 店舗ホームページ・Wi-Fiページ生成サービス  
**最終更新**: 2026-01-12  
**管理者**: 宮田康博

---

## 📑 ドキュメント構成

このSKILL.mdは、以下のマスター情報ファイルを参照しています:

1. **[MASTER_FORBIDDEN_ACTIONS.md](./MASTER_FORBIDDEN_ACTIONS.md)** - 禁止事項・失敗パターン
2. **[MASTER_FIREBASE_CONFIG.md](./MASTER_FIREBASE_CONFIG.md)** - Firebase設定・認証フロー
3. **[MASTER_COMMUNICATION.md](./MASTER_COMMUNICATION.md)** - コミュニケーション規約

各マスターファイルは独立して参照可能です。

---

## 🎯 プロジェクト概要

### サービス内容
- 店舗向けホームページ生成
- Wi-Fi接続ページ作成
- Google/Apple/LINE/Email/電話番号 認証対応
- 無料版・PRO版（¥980/月）の2プラン

### 技術スタック
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Authentication**: Firebase Auth (複数プロバイダ)
- **Hosting**: Firebase Hosting
- **Proxy**: Cloudflare Workers
- **AI**: Gemini API (レシート解析)
- **Storage**: Google Sheets (ユーザーデータ)

---

## 📂 プロジェクト構造

```
sugudesu/
├── SKILL.md                          ← このファイル
├── MASTER_FORBIDDEN_ACTIONS.md       ← 禁止事項マスター
├── MASTER_FIREBASE_CONFIG.md         ← Firebase設定マスター
├── MASTER_COMMUNICATION.md           ← コミュニケーションマスター
├── README.md
├── firebase.json
├── .firebaserc
├── public/
│   ├── index.html
│   ├── css/
│   │   └── style.v4.css
│   └── js/
│       ├── config.js                 ← Firebase設定
│       ├── auth.js                   ← 認証ロジック
│       ├── generator.js              ← ページ生成
│       ├── viewer.js                 ← プレビュー
│       ├── cloudinary.js             ← 画像管理
│       ├── ai.js                     ← AI機能
│       ├── qr.js                     ← QRコード生成
│       ├── receipt.js                ← レシート解析
│       └── utils.js                  ← ユーティリティ
├── backup/                           ← 自動バックアップ
└── backups/                          ← タイムスタンプ付きバックアップ
```

---

## 🔧 開発ガイドライン

### コード記述規約

**CRITICAL**: 以下のルールは絶対厳守

1. **コード省略禁止**
   - 完全版のみ出力
   - 「省略」「前回と同じ」「...」等の表現禁止
   - 部分的な変更でも全体ファイルを出力

2. **Git操作**
   - `git push --force` 絶対禁止（履歴破壊の実績あり）
   - コミット前に必ず確認

3. **質問の制限**
   - CEP-001承認後は即実行
   - 「まず確認させてください」等の多用禁止
   - 必要最小限の確認のみ

4. **ファイル配置**
   - 必ず `/mnt/user-data/outputs/` に作成
   - `present_files` でリンク提供
   - 長文説明禁止（3-5行で要点のみ）

5. **Claude Code使用禁止**
   - 過去に「何一つ解決できなかった」実績
   - 通常Chatインターフェース推奨

### Firebase認証の重要設定

**authDomain設定**: 
```javascript
authDomain: "sugudesu.jp"  // カスタムドメイン使用
```

**詳細は [MASTER_FIREBASE_CONFIG.md](./MASTER_FIREBASE_CONFIG.md) を参照**

---

## 🚀 デプロイ手順

### ステップ1: ローカル確認
```bash
cd /Users/miyatayasuhiro/Desktop/sugudesu/public
python3 -m http.server 8000
```
→ http://localhost:8000 でテスト

### ステップ2: Firebase デプロイ
```bash
cd /Users/miyatayasuhiro/Desktop/sugudesu
firebase deploy
```

### ステップ3: 動作確認
- https://sugudesu.jp にアクセス
- 各認証方法をテスト
- Console エラー確認

---

## 📋 重要な参照ドキュメント

### 必読マスターファイル

1. **禁止事項・失敗パターン**  
   → [MASTER_FORBIDDEN_ACTIONS.md](./MASTER_FORBIDDEN_ACTIONS.md)
   - 過去の失敗事例
   - コード記述規約
   - Git操作注意事項

2. **Firebase設定・認証**  
   → [MASTER_FIREBASE_CONFIG.md](./MASTER_FIREBASE_CONFIG.md)
   - authDomain設定
   - 各認証プロバイダ設定
   - トラブルシューティング

3. **コミュニケーション規約**  
   → [MASTER_COMMUNICATION.md](./MASTER_COMMUNICATION.md)
   - 康博さんの要望パターン
   - 適切な応答方法
   - コマンド表示ルール

---

## 🔍 トラブルシューティング

### 認証エラー
1. Console確認: F12 → Console タブ
2. authDomain確認: `sugudesu.jp` であること
3. LINE認証: Provider ID = `"oidc.line"` 確認

### ファイルが反映されない
1. キャッシュクリア: Cmd + Shift + R
2. Firebase再デプロイ
3. バージョン番号確認（CSS/JSファイル名）

### 詳細は各マスターファイルを参照してください

---

## 📞 サポート情報

- **プロジェクトURL**: https://sugudesu.jp
- **Firebase Project**: sugudesu-jp
- **開発者**: 宮田康博

---

**v3.0 - 2026-01-12**: マスターファイル参照方式へ移行（67%サイズ削減）
