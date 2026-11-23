# Node.js / TypeScript 向け実装例 (Express, Next.js等)

`principles.md` の各カテゴリに対応する、このスタックでの具体的な実装パターンです。フレームワークが
異なっても考え方は流用できます。

## データベース
```ts
// NG: 文字列結合でSQLiに脆弱
await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// OK: プレースホルダ (node-postgres の例)
await db.query('SELECT * FROM users WHERE email = $1', [email]);

// OK: ORM経由 (Prisma の例、常にパラメータ化される)
await prisma.user.findUnique({ where: { email } });

// 動的にソート列を組み立てる場合は allowlist で変換する
const SORTABLE_COLUMNS = new Set(['created_at', 'name']);
const sortBy = SORTABLE_COLUMNS.has(input.sortBy) ? input.sortBy : 'created_at';
```
接続情報は `process.env.DATABASE_URL` 等から読み込み、`.env` は `.gitignore` に含める。
本番はTLS必須（Postgresは `sslmode=verify-full` で証明書も検証）。

## 入力値検証
- `zod` / `yup` / `class-validator` 等でリクエストスキーマを定義し、ハンドラの先頭で検証する。
- テンプレートエンジン（EJS/Pug/JSX）はデフォルトでHTMLエスケープされる書き方（EJSなら `<%= %>`、
  Pugなら `#{}`、Reactなら通常のJSX式）を使い、`dangerouslySetInnerHTML` や `<%- %>` は必要最小限に。

## 認証・パスワード
```ts
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12); // saltRoundsは10〜12程度
const ok = await bcrypt.compare(inputPassword, hash);
```
JWTを使う場合、有効期限(`exp`)を必ず設定し、`alg: 'none'`を許可しない設定でverifyする。

## セッション
- `express-session` を使う場合、`cookie: { httpOnly: true, secure: true, sameSite: 'lax' }` を設定。
- セッションストアは本番では `MemoryStore` ではなく Redis 等の永続ストアを使う。

## CSRF / セキュリティヘッダ
- `helmet` ミドルウェアでセキュリティヘッダを一括設定する。
- state変更を伴うAPIには `csurf` 相当のCSRFトークン検証、またはSameSite Cookie + カスタムヘッダ確認を行う。

## 秘密情報管理
- APIキー・シークレットは `process.env` 経由。`dotenv` を使う場合 `.env` は必ず `.gitignore`。
- リポジトリに秘密情報が誤コミットされていないか `git log -p` やgit-secrets等のツールで確認する。
- **環境変数が未設定の場合、既知の固定文字列へ静かにフォールバックしない（fail-fast）**。
  `NODE_ENV === 'production'` など特定の環境変数の値に依存したガードだけでは、その値が
  確実に設定される保証のない環境（ステージング等）で既知の固定値が使われてしまう。
  どの環境であっても未設定なら起動時に例外を投げて停止するのが安全:
  ```ts
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    throw new Error('JWT_SECRET is not set'); // 環境を問わず常に停止。既知の固定値へは逃げない
  }
  ```
  ローカル開発を簡便にしたい場合は、固定文字列へのフォールバックではなく、未設定時に
  `crypto.randomBytes(32).toString('hex')` 等でその場限りのランダム値を生成し、
  起動のたびに変わる値であることをログで明示する（推測可能な既知値にしないのが目的）。

## 依存関係
```bash
npm audit --audit-level=high
```

## エラー処理
```ts
app.use((err, req, res, next) => {
  logger.error(err); // 詳細はログへ
  res.status(500).json({ message: 'Internal Server Error' }); // クライアントには詳細を返さない
});
```
