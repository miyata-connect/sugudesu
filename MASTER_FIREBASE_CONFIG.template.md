# 🔧 FIREBASE CONFIG - Firebase設定マスター (テンプレート)

**Version**: 1.0.0  
**Purpose**: SUGUDESUプロジェクトのFirebase設定テンプレート

---

## 使用方法

1. このファイルを `MASTER_FIREBASE_CONFIG.md` にコピー
2. 以下の値を実際の値に置き換える
3. `MASTER_FIREBASE_CONFIG.md` は `.gitignore` に含まれているため Git にコミットされません

---

## Firebase基本設定

### プロジェクト情報

```javascript
const firebaseConfig = {
  apiKey: "YOUR_API_KEY_HERE",
  authDomain: "sugudesu.jp",  // ← 🔥 絶対に変更禁止
  projectId: "sugudesu-jp",
  storageBucket: "YOUR_STORAGE_BUCKET_HERE",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID_HERE",
  appId: "YOUR_APP_ID_HERE",
  measurementId: "YOUR_MEASUREMENT_ID_HERE"
};
```

---

(以下、元のドキュメントと同じ内容)

**Status**: 🔥 TEMPLATE DOCUMENT  
**セキュリティ**: 機密情報は含まれていません
