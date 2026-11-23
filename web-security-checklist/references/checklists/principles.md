# セキュリティチェック項目一覧（言語非依存の原則）

> **このファイルの参照バージョン: OWASP ASVS v5.0.0（2025-05-30リリース、17章構成）、確認日: 2026-09-02**
> 各カテゴリの「参照:」行にあるASVS章番号・章名は、OWASP公式リポジトリ
> (https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en) の実ファイル内容と突き合わせてv5.0.0基準に更新済みです。
> ASVSに新しいメジャーバージョン（v5.1やv6.0等）が出た場合は、このファイルと `docs/SOURCES.md`
> 「1. references/checklists/principles.md」節を再度突き合わせて更新要否を確認してください。

このファイルは IPA「安全なウェブサイトの作り方」、OWASP ASVS (Application Security Verification Standard)、
OWASP Cheat Sheet Series、CWE Top 25 を統合した、言語やフレームワークに依存しないチェック項目集です。
各モードはここに列挙されたカテゴリ・項目を判定基準として使います。

具体的な実装コード例が必要な場合は `references/lang/<言語名>.md` を参照してください（未対応言語の場合は
このファイルの原則だけで判断してください）。

各項目には severity の目安（Critical / High / Medium / Low）を付けています。あくまで目安であり、
実際の影響範囲（認証情報が漏れるか、DoSに留まるか等）に応じて調整してください。

---

## 1. 入力値検証 (Input Validation)
参照: IPA §1（SQLインジェクション/OSコマンドインジェクション/パス名パラメータの未検証等）, OWASP ASVS v5.0 第1章(V1: Encoding and Sanitization)・第2章(V2: Validation and Business Logic)（旧v4.0系ではV5: Validation, Sanitization and Encodingに相当）, OWASP Cheat Sheet "Input Validation", CWE-20/78/79/89/94

- [ ] すべての外部入力（クエリパラメータ、フォーム値、ヘッダ、Cookie、ファイル名、JSON body等）をサーバサイドで検証している（クライアント側検証のみに依存していない）(Critical)
- [ ] SQL文はプレースホルダ／パラメータ化クエリまたはORM経由でのみ構築し、文字列結合でSQLを組み立てていない (Critical) → 詳細は `references/checklists/database/sqli.md`
- [ ] OSコマンド実行・シェル呼び出しに外部入力を直接渡していない（渡す場合は許可リスト方式で厳格に検証） (Critical)
- [ ] HTMLへの出力は自動エスケープされるテンプレートエンジン経由、または明示的にエスケープしている（XSS対策） (High)
- [ ] ファイルパスを外部入力から組み立てる際、ディレクトリトラバーサル（`../`等）を検証・正規化している (High)
- [ ] 数値・列挙値・日付等は型と範囲を検証している（想定外の値でロジックが壊れないか） (Medium)
- [ ] 許可リスト（allowlist）方式を基本とし、拒否リスト（denylist）だけに頼っていない (Medium)
- [ ] 外部URLを取得・アクセスする処理（Webhook登録、画像/PDF取得、URLプレビュー等）で、内部ネットワーク・クラウドメタデータエンドポイント(169.254.169.254等)へのアクセスを許可リストで制限している (High)
- [ ] XMLをパースする場合、外部エンティティ参照(DTD)を無効化している (High)
- [ ] 信頼できないデータを直接デシリアライズ(pickle, unserialize等)せず、安全な形式(JSON等)を優先している (High)

## 2. 認証 (Authentication)
参照: IPA §1（認証、パスワードの不備）, OWASP ASVS v5.0 第6章(V6: Authentication)・第9章(V9: Self-contained Tokens)・第10章(V10: OAuth and OIDC)・第11章(V11: Cryptography、§11.4 Hashing and Hash-based Functionsにパスワードハッシュ化要件あり)（旧v4.0系ではV2: Authentication/V6: Stored Cryptographyに相当）, OWASP Cheat Sheet "Authentication", "Password Storage", CWE-287/307/521

- [ ] パスワードは不可逆なハッシュ関数（bcrypt / scrypt / Argon2等）＋ソルトで保存し、平文・可逆暗号化で保存していない (Critical)
- [ ] ログイン試行回数の制限（レート制限・アカウントロック等）がありブルートフォースに耐性がある (High)
- [ ] パスワードの最小強度ポリシーがある（ただし過度に複雑な独自ルールを強制しすぎない） (Medium)
- [ ] 多要素認証(MFA)の余地がある、または重要操作に再認証を要求している (Medium)
- [ ] パスワードリセット・トークン発行は推測不能なランダム値かつ有効期限がある (High)
- [ ] ログイン成功・失敗時のレスポンス/エラーメッセージからアカウントの存在有無が判別できない（ユーザー列挙対策） (Medium)
- [ ] JWT等のトークンを検証する際、許可するアルゴリズムを明示的に固定している（アルゴリズム混同攻撃・`alg: none`を防ぐ） (High)
- [ ] OAuth/OIDCを利用する場合、redirect_uriの厳格な検証・state/PKCEパラメータの利用・トークンの適切な受け渡し先検証を行っている (High)

## 3. セッション管理 (Session Management)
参照: IPA §1（セッション管理の不備）, OWASP ASVS v5.0 第7章(V7: Session Management)（Cookie属性(HttpOnly/Secure/SameSite)の詳細要件はv5.0で第3章 V3: Web Frontend Securityに移動しているため併せて参照）（旧v4.0系ではV3: Session Managementに相当）, OWASP Cheat Sheet "Session Management", CWE-384/613

- [ ] セッションIDは十分なエントロピーを持つ値をサーバ側で生成している（推測可能なIDを自前生成していない） (Critical)
- [ ] ログイン成功時にセッションIDを再生成している（セッション固定化対策） (High)
- [ ] Cookieに `HttpOnly`, `Secure`, `SameSite` 属性を設定している (High) → 出典タグ付け時はOWASP ASVS
  **第3章(V3: Web Frontend Security)** を使う（カテゴリ全体の参照行にある第7章ではなく、この項目に
  固有の章）
- [ ] セッションに有効期限（アイドルタイムアウト・絶対タイムアウト）があり、ログアウト時にサーバ側でも無効化している (Medium)
- [ ] 重要操作（パスワード変更・退会等）の前にセッションが正当かを再確認している (Medium)

## 4. アクセス制御・認可 (Access Control / Authorization)
参照: IPA §1（1章「ウェブアプリケーションのセキュリティ実装」内の11脆弱性の1つ「アクセス制御や認可制御の不備」）, OWASP ASVS v5.0 第8章(V8: Authorization、§8.2にIDOR/BOLA/BOPLA対策の要件あり)（旧v4.0系ではV4: Access Controlに相当）, OWASP Cheat Sheet "Authorization", CWE-284/285/639 (IDOR)

- [ ] オブジェクトIDをリクエストから受け取る箇所すべてで「そのユーザーがそのリソースにアクセスする権限があるか」をサーバ側で確認している（IDOR対策） (Critical)
- [ ] 管理者専用・内部専用のエンドポイントに適切な権限チェックがある（URLを知っていればアクセスできる状態になっていない） (Critical)
- [ ] ロール・権限の判定はサーバ側で行い、クライアントから送られた role/権限フラグを信用していない (Critical)
- [ ] デフォルトで最小権限（deny by default）になっている (Medium)

## 5. データベース (Database)
参照: IPA §1（SQLインジェクション、1.入力値検証カテゴリと重複）, OWASP ASVS v5.0 第1章(V1: Encoding and Sanitization、SQLi対策)・第11章(V11: Cryptography、保存データの暗号化)・第13章(V13: Configuration、§13.3 Secret Management、接続情報管理), OWASP Cheat Sheet "SQL Injection Prevention", "Database Security", CWE-89/798

詳細は `references/checklists/database/_index.md` を参照。ここでは概要のみ。

- [ ] SQLインジェクション対策（1.入力値検証と重複するが、DB接続層としても確認） (Critical)
- [ ] アプリ用DBアカウントが最小権限になっている（不要なDROP/ALTER/管理者権限を持たせていない） (High)
- [ ] DB接続情報（ホスト・ユーザー・パスワード）がコードにハードコードされておらず、環境変数やシークレットマネージャ経由 (Critical)
- [ ] DB接続がTLSで暗号化されている（特に本番・クラウド環境） (High)
- [ ] 機密データ（個人情報等）は保存時に暗号化またはハッシュ化されている (High)
- [ ] SQLエラーメッセージやスタックトレースがクライアントに露出していない (Medium)
- [ ] マイグレーション・シードデータに本番用の機密情報やテスト用の弱い認証情報が含まれていない (Medium)

## 6. 暗号・秘密情報管理 (Cryptography & Secrets Management)
参照: OWASP ASVS v5.0 第11章(V11: Cryptography)・第13章(V13: Configuration、§13.3 Secret Management)（旧v4.0系ではV6: Stored Cryptography/V9: Communicationsに相当。V9はv5.0で第12章 Secure Communicationに再編されており、本カテゴリ(秘密情報管理)としては第13章§13.3の方が対応が近い）, OWASP Cheat Sheet "Cryptographic Storage", "Secrets Management", CWE-259/321/798

- [ ] APIキー・トークン・秘密鍵・パスワードがソースコード／リポジトリ内にハードコードされていない (Critical)
- [ ] `.env`等の秘密情報ファイルが `.gitignore` されている（誤コミット防止） (High)
- [ ] 独自の暗号アルゴリズムを実装せず、標準ライブラリ／実績のある暗号ライブラリを使っている (High)
- [ ] 乱数が必要な箇所（トークン生成等）で暗号論的に安全な乱数生成器を使っている（`Math.random()`等の非暗号論的PRNGを使っていない） (High)

## 7. エラー処理・ログ (Error Handling & Logging)
参照: IPA §1（エラーメッセージからの情報漏えい）, OWASP ASVS v5.0 第16章(V16: Security Logging and Error Handling)（旧v4.0系ではV7: Error Handling and Loggingに相当）, CWE-209/532

- [ ] 本番環境でスタックトレース・内部パス・DBエラー等の詳細情報をレスポンスに含めていない (High)
- [ ] パスワード・トークン・個人情報等の機密情報をログに出力していない (High)
- [ ] 重要操作（ログイン・権限変更・削除等）の監査ログが残る (Medium)

## 8. 通信・セキュリティ設定 (Transport & Configuration)
参照: IPA §2（HTTPS化、セキュリティ設定の不備）, OWASP ASVS v5.0 第3章(V3: Web Frontend Security、§3.4にCSP/HSTS/X-Content-Type-Options等のセキュリティヘッダー要件、§3.5にCORS/CSRF対策要件あり)・第12章(V12: Secure Communication、TLS強制)・第13章(V13: Configuration、§13.4にデバッグモード無効化等の要件あり)（旧v4.0系ではV9: Communications/V14: Configurationに相当。v5.0ではセキュリティヘッダー・CORS・CSRF関連の要件が新設の第3章(Web Frontend Security)に再編されている点に注意）, OWASP Cheat Sheet "HTTP Security Response Headers", CWE-319

- [ ] 通信はHTTPSを強制している（HTTP→HTTPSリダイレクト、HSTS） (High)
- [ ] セキュリティ関連レスポンスヘッダ（`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`等）を設定している (Medium)
- [ ] CORS設定が必要以上に緩くない（`*`を安易に許可していない、特に認証情報を伴うリクエストで） (High)
- [ ] CSRF対策（トークン検証、SameSite Cookie等）がstate変更を伴うエンドポイントにある (High)
- [ ] デバッグモード・詳細エラー表示が本番設定でOFFになっている (Medium)

## 9. ファイルアップロード・ファイル操作 (File Handling)
参照: IPA §1（ファイルアップロードの脆弱性）, OWASP ASVS v5.0 第5章(V5: File Handling、アップロード検証・
保存先・パス処理・受け渡しファイルの扱い等を規定。v4.0系のV12: Files and Resourcesが再編・新設されたもの)、
OWASP Cheat Sheet "File Upload", CWE-434/22

- [ ] アップロードファイルの拡張子・MIMEタイプ・サイズを検証している (High)
- [ ] アップロードファイルを実行可能な場所に保存していない、またはWebサーバ側でスクリプトとして実行されない設定になっている (Critical)
- [ ] アップロードファイル名を外部入力からそのまま使わず、安全な名前に変換している (Medium)

## 10. 依存関係管理 (Dependency / SCA)
参照: OWASP Cheat Sheet "Vulnerable Dependency Management", CWE-1104（IPA/OWASP ASVSには依存関係管理を
主題とした専用章がないため、この2つのみを根拠とする。実際の既知脆弱性検出はSCAスキャンツール自体の
実行結果を一次情報とする）

詳細は `references/checklists/dependency-sca.md` を参照。

- [ ] 既知の脆弱性を持つ依存パッケージがないか（`npm audit`/`pip-audit`/`osv-scanner`等）を確認している (High〜Critical、CVEの深刻度による)
- [ ] 依存パッケージのバージョンが極端に古い・メンテナンスされていないものになっていない (Medium)
- [ ] ライセンス・出所不明なパッケージを安易に追加していない (Low〜Medium)

## 11. ビジネスロジック・API設計 (Business Logic & API)
参照: OWASP API Security Top 10, CWE-841

- [ ] IP単位・アカウント単位・エンドポイント単位など適切な粒度でレート制限・スロットリングがあり、リソース枯渇（大量リクエスト・大量データ取得・クレデンシャルスタッフィング）に耐性がある (Medium)
- [ ] Mass Assignment対策（リクエストbodyの余分なフィールドでモデルの意図しない属性が更新されない） (High)
- [ ] ページネーション・一覧取得APIで他ユーザーのデータが混ざらない (High)
