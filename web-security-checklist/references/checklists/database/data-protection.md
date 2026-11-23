# 接続情報と保存データの保護

| ID | 証跡 | 重大度目安 | 確認内容 | 検出の手掛かり | 根拠 |
| --- | --- | --- | --- | --- | --- |
| DB-DATA-01 | SRC+CFG | Critical | 接続文字列・ユーザー名・パスワードをソース・設定ファイル・CI定義に書かない。環境変数やシークレットマネージャから注入する | `postgres://user:pass@`、`password:` の固定値、composeの `POSTGRES_PASSWORD=` 実値、CIのYAMLの平文 | CWE-798 |
| DB-DATA-02 | CFG | High | 既定の管理者パスワード・空パスワード・推測しやすい値を使わない | `root`／空、`postgres/postgres`、`trust` 認証、`MYSQL_ALLOW_EMPTY_PASSWORD` | CWE-1392、CWE-521 |
| DB-DATA-03 | CFG | Medium | サンプル設定（`.env.example`等）にはダミー値だけを置き、実値の `.env` は `.gitignore` に入れる | `.env.example` に実在しそうな接続先や鍵、`.gitignore` に `.env` が無い | CWE-798、CWE-540 |
| DB-DATA-04 | SRC | High | パスワードは一方向ハッシュ（Argon2・bcrypt・scrypt）で保存する | 平文の `password` 列、MD5・SHA-1・ソルト無しSHA-256、可逆暗号での保存 | CWE-256、CWE-916 |
| DB-DATA-05 | SRC+OPS | High | カード番号・マイナンバー等は保持しない設計を優先し、保持する場合は列単位の暗号化と鍵管理を行う | 機微な列の平文保存、鍵を同じDBやソースに置く実装 | CWE-311、CWE-312 |
| DB-DATA-06 | SRC+OPS | Medium | データを機微度で分類し、不要な個人情報は保持しない | 個人情報・決済系の列に分類のコメントや扱いの区別が無い、使わない個人情報の収集 | CWE-359。ISM-0393 |
| DB-DATA-07 | SRC+CFG+OPS | High | 本番データを非本番（開発・テスト・ステージング）へ持ち込まない。持ち込むなら本番同等に保護しマスキングする | CI・シードでの本番ダンプの復元（`pg_restore`・`mysql <`）、ダンプファイルのコミット、マスキング処理が無い | CWE-359。ISM-1274 |
| DB-DATA-08 | SRC | Medium | シードに実在しそうな個人情報や、推測しやすい固定パスワードの管理者を入れない | `admin/password123`、実名・実住所風のデータ | CWE-1392、CWE-359 |
| DB-DATA-09 | CFG+OPS | Medium | DBのデータファイル・ダンプ・バックアップにファイル単位のアクセス制御を付ける | Dockerfileの `chmod 777`、データディレクトリの共有ボリューム、ダンプの公開ディレクトリ配置 | CWE-732。ISM-1256 |
| DB-DATA-10 | CFG+OPS | Low | 本番のマイグレーション前に、バックアップとロールバックの手順がある | 破壊的なマイグレーション（`DROP`・列削除）に戻し手順が無い | ISM-1274（関連） |
