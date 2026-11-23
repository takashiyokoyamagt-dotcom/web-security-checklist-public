# SQL・NoSQLインジェクション

| ID | 証跡 | 重大度目安 | 確認内容 | 検出の手掛かり | 根拠 |
| --- | --- | --- | --- | --- | --- |
| DB-SQLI-01 | SRC | Critical | SQLを文字列結合やテンプレート文字列で組み立てず、プレースホルダ（`?`・`$1`・名前付き）かクエリビルダを使う | `"SELECT ... " + x`、`` `...${x}` ``、`format`・`%`・`f"..."` で作るSQL、`query(sql)` に連結済みの文字列 | CWE-89。OWASP SQL Injection Prevention CS |
| DB-SQLI-02 | SRC | High | テーブル名・列名・ORDER BY・LIMIT等、プレースホルダにできない部分は、外部入力を許可リスト（enum・マップ）で変換してから使う | `ORDER BY ${sort}`、`sortBy` をそのまま連結、識別子のエスケープ関数だけに頼る実装 | CWE-89 |
| DB-SQLI-03 | SRC | High | ORMの生SQL・エスケープ回避のAPIに外部入力を渡さない | `sequelize.query`、`knex.raw`、`$queryRawUnsafe`、`createQuery(str)`（HQL・JPQLの連結）、`extra()`・`RawSQL` | CWE-89、CWE-564 |
| DB-SQLI-04 | SRC | High | ストアドプロシージャ・関数の中でも動的SQLを連結しない | `EXECUTE 'SELECT ...' \|\| param`、`EXEC(@sql)`、`PREPARE stmt FROM CONCAT(...)` | CWE-89 |
| DB-SQLI-05 | SRC | High | DBに保存した値を、後で別のクエリに連結しない（二次SQLi） | 読み出した名前・設定値・レポート条件をSQLへ連結、バッチ・管理画面のクエリ | CWE-89 |
| DB-SQLI-06 | SRC | High | NoSQLのクエリに、リクエストのオブジェクト・配列をそのまま渡さない（型を文字列・数値に固定する） | `find({user: req.body.user})`、`$where`、`$regex` に外部入力、`JSON.parse` した条件の直渡し | CWE-943 |
| DB-SQLI-07 | SRC | Medium | 複文の実行を許すドライバ設定を有効にしない | `multipleStatements: true`、複数クエリを1文字列で送る実装 | CWE-89 |
| DB-SQLI-08 | SRC | Medium | LIKE検索の `%`・`_` をエスケープし、件数・文字数の上限を設ける | `LIKE '%' \|\| ? \|\| '%'` で入力を未加工、上限の無い検索 | CWE-89、CWE-400 |

補足: 入力値検証（型・長さ・形式）は多層防御で、パラメータ化の代わりにはならない。エスケープ関数だけの対策は、文字コードや識別子の文脈で破られやすいので「対策済み」と扱わない。
