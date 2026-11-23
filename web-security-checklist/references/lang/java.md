# Java / Kotlin 向け実装例 (Spring Boot等)

## データベース
```java
// NG: 文字列結合でSQLiに脆弱
String sql = "SELECT * FROM users WHERE email = '" + email + "'";

// OK: PreparedStatement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
stmt.setString(1, email);

// OK: Spring Data JPA（メソッド名クエリ・@Queryのバインドパラメータ使用）
userRepository.findByEmail(email);

@Query("SELECT u FROM User u WHERE u.email = :email")
User findByEmailCustom(@Param("email") String email);
```
`application.properties`/`application.yml` に接続情報を直書きせず、環境変数や
Spring Cloud Config / Vault 等から注入する。本番は `spring.datasource.url` にTLSオプションを付与する。

## 入力値検証
- Bean Validation（`@NotNull`, `@Size`, `@Pattern`等）をDTOに付与し、`@Valid`でコントローラ入口で検証する。
- Thymeleaf/JSPはデフォルトでHTMLエスケープされる書き方（Thymeleafの `th:text` 等）を使う。
- Javaの標準XMLパーサ（`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`等）は
  デフォルトで外部エンティティ参照(DTD)が有効なため、XXE対策として明示的に無効化する。
  ```java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setXIncludeAware(false);
  dbf.setExpandEntityReferences(false);
  ```

## 認証・パスワード
```java
PasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashed = encoder.encode(rawPassword);
boolean ok = encoder.matches(rawPassword, hashed);
```
Spring Securityの `PasswordEncoder` を必ず使い、自前ハッシュ実装をしない。

## セッション
- Spring Sessionでは `server.servlet.session.cookie.http-only=true`、`cookie.secure=true` を設定。
- セッションタイムアウトを `server.servlet.session.timeout` で適切に設定する。

## CSRF / セキュリティ設定
- Spring Securityのデフォルト設定ではCSRF保護が有効。無効化(`csrf().disable()`)は
  APIがステートレス(JWT等)で、かつCSRFの影響がないことを確認した場合のみに限定する。
- `HttpSecurity` でセキュリティヘッダ（`X-Frame-Options`, `Content-Security-Policy`等）を設定する。

## 秘密情報管理
- APIキー・DBパスワードを `application.yml` に直書きせず、環境変数やSecrets管理サービス経由にする。
- 環境変数が未設定の場合、既知の固定文字列へ静かにフォールバックしない（fail-fast）。`application.yml`側で
  デフォルト値（`${JWT_SECRET:known-fallback}`のような`:`区切りの既定値記法）を既知の固定文字列にせず、
  未設定時はBean初期化失敗等でアプリケーション起動自体を止める。詳細な考え方は
  `references/lang/nodejs-typescript.md`の「秘密情報管理」節を参照。

## 依存関係
```bash
mvn org.owasp:dependency-check-maven:check
# または Gradle: OWASP Dependency-Check Gradle Plugin
```

## エラー処理
- `@ControllerAdvice` / `@ExceptionHandler` で例外を捕捉し、クライアントには汎用メッセージのみ返す。
- スタックトレースを本番レスポンスに含めない（`server.error.include-stacktrace=never`）。
