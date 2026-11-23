<!--split:add-->
# 指摘処理パイプライン（手順5の5d〜5f）
本ファイルは`references/pipeline/finding-arbiter.md`（手順4・5a〜5c）から分けた部分。本文中の「モード2手順N」「5a〜5f」「モード3手順N」「〜節」等の参照先のファイル（SKILL.mdを読まない委任先向け）: 手順3・出力の構造化・結果の即時ファイル永続化・Red/Blue骨子→`finding-pipeline.md`／手順4・5a〜5c→`finding-arbiter.md`／5d〜5f→本ファイル／「修正案監査レビューの厳格度」→`fix-audit-strictness.md`／「CVSSスコアの算定」概要・環境メトリクス→`cvss.md`／判定基準〜リスク分析章への反映→`cvss-scoring.md`／モード3手順0〜4→`mode3-full-audit.md`・5→`mode3-report.md`・6→`mode3-html.md`・7→`mode3-by-source.md`／共通の原則→`common-principles.md`。
GATE-TOKEN:G3F-4b7e2c
本ファイルはゲートG3（モード2はM4。`finding-arbiter.md`と一緒に）で`Read`するファイル。
<!--split:end-->
**5d. 多層解説フィールドの生成（専門知識のない読者にも伝わる報告書にするため）**: 5a〜5cで
最終確定した指摘それぞれについて、Arbiterが以下4つのフィールドを新たに執筆する。これらは
Red/Blue Teamには書かせない（両者の出力は簡潔な構造化データのまま維持し、モード2/3全体の
エージェントコスト増を防ぐ）。**採用が決まった指摘（CONFIRMED/PLAUSIBLE）のみ**に対して、
Arbiterが1回ずつ執筆する。
- `plain_explanation`（わかりやすい解説）: 専門用語・エンジニア経験を前提とせず、「何が
  起こりうるか」「なぜ問題か」をビジネス上の影響（情報漏えい・改ざん・なりすまし・サービス
  停止等）の言葉で1〜3文程度で説明する。`root_cause`・`failure_scenario`の内容を平易に
  要約する。専門用語を使う場合は括弧書きで一言補足する（例:「SQLインジェクション（データベースへの
  命令を不正に書き換える攻撃）」）。
- `technical_detail`（技術的詳細解説）: `root_cause`・`failure_scenario`・`vulnerable_code`を
  踏まえ、脆弱性が成立する処理の流れをメカニズムとして詳しく説明する（複数文でよい）。
  **`plain_explanation`の単なる専門用語版の言い換えにしないこと**（同じ内容を難しい言葉で
  書き直すだけでは不十分。処理の流れ・なぜその実装だと防げないかという技術的因果関係まで
  踏み込む）。報告書上ではこの`technical_detail`が`root_cause`の内容を包含・代替する
  （報告書には`root_cause`をそのままの形では出力しない。`root_cause`はここまでの内部的な
  作業用フィールドという位置づけになる）。
- `code_issue_annotation`（該当コードの問題点）: `vulnerable_code`内の具体的な行・箇所を指し、
  その箇所の何が問題かを箇条書きで対応付ける（例:「3行目: ユーザー入力を検証せずSQL文へ直接
  連結している」）。「チェックが存在しない」ことが問題な場合は、本来あるべき箇所を指して
  「本来ここに認可チェックが必要」のように書く。
- `fix_explanation`（修正内容の解説）: 確定した`fix_suggestion`（diff）が具体的に何を変更し、
  なぜその指摘の問題が解消するかを説明する。用いた対策手法の名称（パラメータ化クエリ、出力
  エスケープ、CSRFトークン検証 等）を明記する。

設計意図の新項目（`intent`・`behavior_change`・`compat_class`・`design_conflict`・`alternatives`・`design_refs`）は上の4フィールドと別で、Writerは内容を作らない。5a〜5c・5e確定後（再修正があれば更新後）の最終版をWriterに渡し、`assets/templates/report_template.md`の該当ブロックに従って文章化させる（内容は変えず、表現を整えるだけ）。5dの委任が5eより前に行われたときは、新項目の文章化だけを5e確定後に別途行う（または5e確定後に追記・更新する）。新項目の文章も5d補足（文体）の対象で、「である調」で書く。5eが初回に「要再検討」で、Arbiterが再修正して再監査した指摘は、「修正案の監査レビュー」の欄に最終の判定を書き、経緯は「初回: 要再検討（理由）→再修正→再監査: 検証済み」の1行にとどめる（再監査が無ければ「要再検討（残存）」と理由）。「再修正後の文言で記載」等の内部工程の説明は報告書に書かない。

<!--split:add-->
**5d補足（文体）**: 4フィールドと、`failure_scenario`（攻撃シナリオ）・6節の判定根拠（`_reason`）は、報告書の本文として「である調」で書き、です・ます調にしない。`plain_explanation`は専門用語を避けた平易さを保ちつつ、文末を「〜である」「〜できる」「〜おそれがある」とする。5d・6節の文章化を委任する指示（WRITER・CVSS-JUDGE等）にもこの文体を明記し、です・ます調を許可しない。5節の4フィールドと攻撃シナリオで、です・ます調の文が過半の指摘は`check_cvss_decisions.py --report`が警告する。
**5d補足（未執筆項目）**: 5a〜5cで最終確定した指摘（`work_id`単位）の5dの文章化（WRITER委任を含む）が安全分類器の停止またはJSON未生成の失敗（タイムアウト等）で得られないときは、試行を合計2回とする（1回目は通常の指示、2回目は攻撃の手順・入力例（ペイロード）を書かない記述レベルの指示）。2回目も得られなければ打ち切る。試行回数と記述レベルの指示は指摘単位で数え、バッチ委任で止まったときは完了済みの指摘の出力を捨てず、止まった指摘だけを通常の指示で起動し直す（これを1回目と数える）。止まった指摘の途中までの出力は使わず、言い換えを重ねた再試行はしない（分類器の回避にあたる）。打ち切った指摘は: ①「未執筆項目U1, U2…」と番号を付け、`5.N`は付けない。②重大度・CVSSは付けず、1節の件数表・3節の件数・4節・出典別レポートに含めない（3節は備考に注記する）。1節の冒頭と件数表の注記、2節メタデータ、7節（項目ごとに節を設け、事実として確認していること／行っていないこと／修正の扱い／連鎖切断の相手（`5.N`）／ユーザーの判断が必要な点）、9節の運用上の逸脱、12節に、未執筆であることと件数に含まれないことを書き、10節には修正を行動項目として載せる。連鎖切断（5b補足2）の相手の「修正内容の解説」には、未執筆項目Uxを7節参照で書く。③修正が必要なら5cの合成diffに含めてよく、含めたらその旨と5eで検証されたかを7節に書く。④Arbiterが実機再現した事実は7節に事実として書いてよい（解説・攻撃シナリオ・採点・個別の修正案監査は書かない）。⑤`delegation-log.jsonl`には停止した起動も1行記録する（note欄に「分類器停止」等）。⑥最終応答の冒頭でユーザーに伝え、再試行するかの判断を仰ぐ（再試行を選んだ場合は同じ2段の手順でやり直す）。⑦その一時IDは一時ID対応表TSVに載せず、`check_5b_clique.py`に`--unwritten ID1,ID2`で渡す（対応表に無い旨のWARNを除き、除外した連鎖切断の組を表示する。その相互言及は検査しないので目で確かめる）。
**5d補足（該当コードの行番号）**: WRITERに渡す該当コードのパケットは`{"file":…,"start_line":N,"end_line":M,"chunks":[{"start":N,"end":M},…],"code":…}`とし（`chunks`は各チャンクの実ファイルでの行範囲）、行番号はRedの`file_line`でなく実ファイルと照合した値にする（Redの断片は`...`でつなぐ・抜粋するので行がずれる）。モード3は`python3 scripts/make_packets.py --work <保存先> --target <対象> --role judge|writer --mask-file <追加の秘密値>`（writerは`--idmap`も）でCVSS-JUDGE・WRITERの入力ごと作る（手で組まない）。ほかは`scripts/locate_snippet.py --repo <対象> --file <相対パス> --code-file <断片> --hint-start <Redの行>`で照合する。`contiguous:false`は離れた箇所を省略記号でつないだ断片で、範囲はその全体。WRITERの`code_issue_annotation`の行引用は`chunks`ごとの実際の行番号で書かせる。`matched:false`は、WRITERが実ファイルを読んで実際の行番号で書き（要約的な書き換えで原文に無い断片がある）、Arbiterは報告書の「ファイル」行を照合できた範囲（`partial_chunks`・`longest_run`。無ければ行番号を書かない）に直す。
**5d補足（本文の参照の照合）**: 報告書（モード3の統合レポート。モード2でレポートを保存するときも同様）を書き出したら、確定・保存の完了の前に`python3 scripts/check_refs.py --report <報告書> --repo <対象>`を実行する（`<対象>`は、モード3では監査した対象のディレクトリ、モード2では差分を適用した後のツリー。依存を導入した複製があればそれを渡すと、依存の内部への参照が対象外になる。統合修正版〔5c補足2〕の`after/`等の修正後のツリーがあれば`--extra-root <修正後のツリー>`を足すと、修正案の部分〔推奨される修正・修正内容の解説等〕の参照は修正後のツリーでも成り立てばよくなる）。5節の本文（表のセル・解説の文。コードフェンスの中は除く）の`path:行`参照（区切りの「：」全角も含む）を実ファイルと照合する。NG（ファイルが無い・行がファイルの行数を超える。rc1）は実ファイルを開いて本文を直し、rc0になるまで保存を完了しない（修正で新設するファイルへの参照がNGになったら、`--extra-root`を足して再実行する）。WARN（同じ文・セルの識別子が参照行の前後3行に無い＝行番号のずれの疑い。最寄りの出現行が示される）は、該当の本文を実ファイルと突き合わせて目で確かめ、ずれていれば直す（識別子を使う行と定義・設定の行が離れた正しい参照もWARNになるので、示された行へ機械的に置き換えない）。「未解決」のWARN（リポジトリにも依存の置き場所にも無いファイル名、通常ファイルでないもの・リポジトリの外へのリンク）は、依存の内部なら依存を導入した対象で再実行し、ファイル名の誤りなら直す。直さずに残したWARNの件数と理由は2節「使用ツール」欄に書く。識別子の無い参照（「ファイル」行の参照の列だけ等）と前後3行以内のずれはこの検査では見つからないので、「ファイル」行は上の5d補足（`locate_snippet.py`で照合した範囲）に合わせる。
<!--split:end-->

**5e. 修正案の監査レビュー**: 実施方法の詳細は「修正案監査レビューの厳格度」節（モード2手順2/
モード3手順0で確認した設定。モード2には手順0がなく、カテゴリ確定時にエージェント数・所要時間を
ユーザーに伝える手順2に厳格度確認を統合する）を参照。5a〜5cで確定した`fix_suggestion`（5b/5cでの統合・合成後の
最終版を含む）に対し、選択された厳格度に応じた検証を行い、`fix_audit_method`（検証方式）・
`fix_audit_verdict`（検証済み／要再検討）・`fix_audit_evidence`（検証根拠）の3フィールドを
確定する。**5cで複数指摘のdiffを合成した場合、その合成diffはBlueの`fix_suggestion_check`
を経ていないため、厳格度に関わらず必ずこの手順で検証する**（標準厳格度の場合は
Arbiter自身によるセルフチェックとして、5cの(b)で確認した「構文エラーがないか」に加え、
「合成後のdiffが各指摘の脆弱性をそれぞれ解消できているか」「既存コードとの整合性」を確認し、
`fix_audit_method`には「Arbiterによるセルフチェック（5c合成diff）」と明記する。追加項目は`references/design/design-integrated.md`）。
Red/Blueに`references/design/design-fields.md`を渡したとき（モード2/3、設計書の有無によらず）に専用監査エージェントを起動するときは、プロンプトに指摘の申告項目（`intent`・`design_refs`・`behavior_change`・`compat_class`・`design_conflict`・`alternatives`。「検証対象の申告」と明記する）と設計書のパス・要点を足し（申告項目はプロンプトの末尾に置く。照合の前に自分で挙動変化を列挙させるため）、`references/design/design-audit.md`のパスを渡して固定フィールドを足させる。Arbiterも同ファイルを読み、監査人の`verdict`が要再検討なら`fix_audit_verdict`も要再検討とする。

**5f. CVSSスコアの算定**: 実施方法の詳細は「CVSSスコアの算定」節（モード2手順2/モード3手順0で
確認した環境メトリクスの反映有無）を参照。採用が決まった指摘（CONFIRMED/PLAUSIBLE）ごとに、
`technical_detail`・`failure_scenario`・`vulnerable_code`の内容を根拠にCVSS v3.1・v4.0
両方のベクターを判定し、`scripts/calculate_cvss.py`でスコアを算出する。4で暫定保持していた
重大度は、ここで算出したCVSS v3.1の重大度区分（環境メトリクスを反映した場合は環境重大度、
していない場合はベース重大度）で置き換える。
全指摘のベクター確定後、スクリプト実行の前に`references/cvss/cvss-scoring.md`の「ベクターの整合性確認」を行い、
結果を`cvss_consistency_note`に保持する。
<!--split:add-->
**並び順（未使用の指摘）**: 5節・4節・6節は、採用した重大度の帯（Critical→High→Medium→Low）の順、同じ帯では未使用でない指摘を先に、未使用の指摘を同じ帯の末尾に置き、以降は採用スコア（環境メトリクスを反映した場合は環境スコア、しない場合はベーススコア）の高い順とする（帯は未使用でも変えない。重大度はCVSSを正とするため）。「最上位」「最も重大」と述べる箇所（エグゼクティブサマリー等）は未使用の指摘を除いて述べ、未使用の件数を別に書く。表示は`assets/templates/report_template.md`の注記に従う。
<!--split:end-->
<!--split:add-->
**5f-2. 判定記録**（書式は`references/cvss/cvss-scoring.md`「判定記録」）: モード3は常に、モード2はレポートをファイル保存する予定がある場合のみ書く（保存後に求められたら`by:"post"`で再構成する。その場合は判定と別案を再度`calculate_cvss.py`で算出して`cvss-raw-output.jsonl`を作り、完成確認のため`references/modes/mode3-report.md`を読む）。順序: ①判定直後に作業メモ行を`cvss-decisions.jsonl`へ即追記（再引用しない）→②整合性確認（変更は`rev+1`メモ行）→③バッチループで主ベクターと各別案を実行し`cvss-raw-output.jsonl`（既存の生JSON Linesを`{"id":"<tmp>","raw":<出力>}`の形にしたもの）へ追記（別案は`"kind":"alt","of":"<メトリクス>"`付き）→④sbs/band/attn/grpを埋めた確定行を追記（`rev`は同じ`tmp`の既存行（メモ・確定とも）の最大rev+1以上。メモ最大rev以下では有効行がメモ行のままになる。`--append`は拒否する）→⑤最終番号確定後、対応表（JSONファイル `{"I3+U1":"5.3"}`。JSON文字列〔`{`で始まる値〕も可）で`python3 scripts/check_cvss_decisions.py --fill-ids --decisions … --raw … --idmap …`を実行（`id`と、`raw`＝`cvss-raw-output.jsonl`の当該主行の行番号を後埋め）。`tmp`・対応表のキーは、5bの一時ID（5b補足2の対応表TSVの第1列）を昇順に`+`で連結した形で、群の作業用ID（F12等）ではない。この対応表JSONと`--mapping`のTSVは手で作らず`make_idmap.py`で生成する（5b補足2）。
値を上書きした指摘は④の前に`cvss-scoring.md`「Arbiterが値を上書きしたときの再確認」を行い確定行に`rechk`を書く。未使用の指摘は確定行に`unused`・`unused_why`を書く。**全行に`seq`・`ts`を付け、①の作業メモ行は判定のたびに追記する**（`--append`・`--append-raw`が自動で付ける。並列に呼ばない。排他ロックでseqの重複とtsの逆行は防ぐが、行の順序（どの判定が先か）は不定になる。時刻の手書きや、全指摘の判定後に作業メモ行を一括生成することはしない。時刻順はメモ行→raw→確定行。保存後の再構成は`by:"post"`）。
委任時、サブエージェントは作業メモ行を戻り値で返し、Arbiterが受領直後に無加工で追記する（`by:"sub"`）。③は既存の「スクリプト実行の徹底」どおりArbiterが行う（サブエージェント実行分は再実行で検算し、追記は検算済み出力）。追記が拒否されたら回避せず、その旨を最終応答に書く。
追記の書式例（`F3`の主ベクターと別案、作業メモ行。`set -o pipefail`で`calculate_cvss.py`の失敗時に追記を止める。追記した行は標準出力に表示されるので、その場で内容を確認する。必須キーが欠けた`memo`/`final`行は追記を拒否される）:

```bash
set -o pipefail
python3 scripts/calculate_cvss.py --v3-vector "$V3" --v4-vector "$V4" \
  | python3 scripts/check_cvss_decisions.py --append-raw cvss-raw-output.jsonl --id F3
python3 scripts/calculate_cvss.py --v3-vector "$ALT_V3" \
  | python3 scripts/check_cvss_decisions.py --append-raw cvss-raw-output.jsonl --id F3 --kind alt --of AC
python3 scripts/check_cvss_decisions.py --append cvss-decisions.jsonl <<'EOF'
{"tmp":"F3","cat":"入力値検証","cwe":["CWE-89"],"type":"SQLi（SELECT・複文不可）","v3":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","v4":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N","m3":{"AV":["N","routes/search.js:8","公開GET","default"],"AC":["L","routes/search.js:12","入力をそのまま連結","default"],"PR":["N","routes/search.js:8","認証ミドルウェアなし","default"],"UI":["N","routes/search.js:8","GET1回で完結","default"],"S":["U","db.js:3","同一DBに閉じる","default"],"C":["H","routes/search.js:12","UNIONで全表を読める","表:SQLi（SELECT・複文不可）"],"I":["N","db.js:5","複文不可のドライバ","表:SQLi（SELECT・複文不可）"],"A":["N","routes/search.js:12","SELECTのみ・DoS未実証","表:SQLi（SELECT・複文不可）"]},"v4map":"std","dev":[],"borderline":[],"by":"arbiter","rev":1,"st":"memo"}
EOF
```
<!--split:end-->
