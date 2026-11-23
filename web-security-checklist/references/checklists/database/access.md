# DBの権限と絞り込み

| ID | 証跡 | 重大度目安 | 確認内容 | 検出の手掛かり | 根拠 |
| --- | --- | --- | --- | --- | --- |
| DB-ACC-01 | SRC+CFG | High | アプリの接続アカウントに、必要なCRUD以外（DROP・ALTER・GRANT・SUPERUSER等）を与えない | 接続ユーザーが `postgres`・`root`・`sa`、マイグレーションの `GRANT ALL`、`SUPERUSER`・`CREATEROLE`、DBオーナーでの接続 | CWE-250、CWE-269。ISM-1255 |
| DB-ACC-02 | CFG | Medium | マイグレーション用とアプリ実行用、読み取り専用の処理（集計・レポート）のアカウントを分ける | 全処理が1つの接続情報、バッチもアプリも同じユーザー | CWE-250。ISM-1255 |
| DB-ACC-03 | SRC+CFG+OPS | Medium | 利用者（人・ロール）が参照・追加・変更・削除できる範囲を職務で制限する。特に削除・一括更新は限られた職務だけにする | ロール定義の無いマイグレーション、全ロールへの `DELETE` 付与、管理画面の一括削除に権限確認が無い | CWE-269。ISM-1255 |
| DB-ACC-04 | SRC+CFG | Medium | 知る必要の範囲だけを返す（ビュー・列単位の権限・ロール・トークン化で機微な列を絞る） | `SELECT *` の結果をそのまま応答、パスワードハッシュや個人情報の列を含む全列返却、列単位の `GRANT` が無い | CWE-213。ISM-1268 |
| DB-ACC-05 | SRC | Critical | レコード単位の所有者確認をクエリの条件に入れる（IDだけで取得・更新しない） | `WHERE id = ?` だけで他人の行を取得・更新・削除、テナントIDの条件が無い | CWE-639。OWASP Authorization CS |
| DB-ACC-06 | SRC+CFG | Medium | 行単位セキュリティ（RLS）を使う場合、アプリの接続ユーザーがそれを迂回しない | `BYPASSRLS`、テーブル所有者での接続、`SET row_security = off` | OWASP Database Security CS |

注: ISM-1255・1268の運用面（実DBに付与済みの権限が職務と一致しているか）はリポジトリでは確かめられない。定義が見えない場合は指摘にせず `ops-requests.md` の確認依頼にする。
