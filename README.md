# sugudesu 認証メモ（Apple / LINE）

このリポジトリは `index.html` だけで動く構成で、認証は **Firebase Authentication** を使っています。

- **Appleログイン**: Firebase Authの `OAuthProvider("apple.com")` を利用（フロント完結）
- **LINEログイン**: フロント単体では **Channel Secretが必要**で安全に完結できないため、**サーバ側（Worker等）でOAuthを完了し、Firebase Custom Tokenを返す**方式

## 1) いま入っているUI要件（ログイン後は他の認証を見せない）

`index.html` の `setAuthUiLoggedIn()` で、ログイン成功後に

- Google / Apple / LINE の各ログインボタンを **非表示**
- ログアウトボタンだけ **表示**

にしています。さらに初期表示のチラつき対策として、認証状態が確定するまでボタンを隠す `setAuthUiLoading()` も入れています。

## 2) Appleログインを有効化する（Firebase側の設定）

フロント実装は既にあります（`appleLogin()`）。
動かない場合はほぼ **Firebase Console側の設定不足**です。

- Firebase Console → Authentication → Sign-in method
  - **Apple** を有効化
  - Apple Developer側で作った **Service ID / Team ID / Key / Key ID** を設定
- Firebase Console → Authentication → Settings → Authorized domains
  - `index.html` を置いているドメインを追加

## 3) LINEログインを有効化する（WorkerをデプロイしてURLを設定）

このリポジトリに Cloudflare Worker の雛形を追加しました：

- `workers/line-firebase-auth/worker.mjs`
  - `/line/start?returnTo=<戻り先URL>` を開くとLINEへリダイレクト
  - `/line/callback` で code を交換 → LINE user(sub) を取得 → Firebase Custom Token を発行
  - `returnTo` に `?firebaseCustomToken=...` を付けて戻します

### 3-1) LINE Developer側

LINE Developers コンソールで以下を設定します:

- LINE Login チャネル作成
- **Callback URL** に Worker の `https://<worker-domain>/line/callback` を登録

### 3-2) Firebase側（Custom Token用のサービスアカウント）

WorkerがFirebase Custom Tokenへ署名するためにサービスアカウント情報が必要です。

- Google Cloud / Firebase プロジェクトで **サービスアカウント鍵** を作成
- `client_email` と `private_key` を Worker の環境変数に登録

### 3-3) Worker の環境変数（wrangler secret）

Cloudflare側に以下を設定します（値はあなたの環境のもの）:

- `LINE_CHANNEL_ID`
- `LINE_CHANNEL_SECRET`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
- `APP_ORIGIN_ALLOWLIST`（推奨）: `https://あなたのサイト` をカンマ区切りで

### 3-4) フロント側の設定

`index.html` の定数 `LINE_AUTH_START_URL` を Worker のURLに変更します。

例:

```js
const LINE_AUTH_START_URL = "https://your-worker.example.com/line/start";
```

これで「LINEでログイン」ボタンが Worker に飛び、戻ってきた `firebaseCustomToken` を `signInWithCustomToken()` で受け取ってログインします。

## 4) 「上書きしたのに変わってない」対策

デプロイ先が GitHub Pages / Firebase Hosting 等の場合、ブラウザ・CDNキャッシュで「変わってないように見える」ことがあります。

- 強制リロード（`Ctrl+F5`）/ キャッシュ削除
- `index.html` のURLに `?v=日時` を付けて読み直す

が有効です。

