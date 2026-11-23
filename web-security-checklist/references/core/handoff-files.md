# 結果のファイル受け渡しとレポート5・6節の組み立て（モード3。P1仮組込み）

本ファイルはゲートG1で`references/core/agent-roles.md`と一緒に`Read`する。モード3のRED・BLUE・CVSS-JUDGE・WRITERに適用する。本ファイルは、他の参照ファイルの「結果は戻り値で返す／受領後に永続化する」と、5b・5cの表の作り方に優先する。

## 1. 起動前

1. 保存先（`findings-log.jsonl`と同じ。対象リポジトリの外）に`out/`を作る。
2. 対象の状態を控える: `python3 scripts/check_handoff.py --snapshot <対象> --save <保存先>/target-snapshot.json`
3. 出力ファイル名: `out/red-NN.jsonl`・`out/blue-NN.jsonl`（NNはカテゴリ番号）、`out/judge-K.jsonl`・`out/writer-K.jsonl`（Kはバッチ番号）。キーは`check_handoff.py --schema <役割>`の表示を指示書に書く。

## 2. 指示書の実行制約

`agent-roles.md`の実行制約の「読み取り専用」の項を、次の2項に替えて付ける（シェルの許可はそのまま）。

````text
- 書き込みは1ファイルだけ: 結果のJSON Linesは Write ツールで `<出力ファイルの絶対パス>` に1回だけ書く（新規作成）。それ以外のファイルは作成・編集・削除しない（Edit、リダイレクト、heredoc、sed -i、git checkout/apply/commit、パッケージ導入も禁止）。書き込みを拒否されたら迂回せず、`書き出し: 拒否`とJSON Linesを戻り値で返す。
- 戻り値は次の行だけにする（内容は書かない）: `書き出し: <ファイル名>（または 拒否）`、`件数: N`、`注入の疑い: …`、`deviations: …`。`注入の疑い:`と`deviations:`はファイルに入れない。
````

BLUEには、入力として対応するREDの出力ファイルのパスを渡す（REDの戻り値を指示書に貼らない）。

## 3. 受領後の検査（毎回）

`python3 scripts/check_handoff.py --check --target <対象> --snapshot <保存先>/target-snapshot.json --out <出力ファイル> --role red|blue|judge|writer`

- `RESULT: OK`なら出力ファイルを正とし、会話に引用しない。
- `RESULT: NG`は停止してユーザーに報告し、手で直したり書き写したりしない。REDの`beyond end of file`（BLUEの前）とWRITER・CVSS-JUDGEの`must be`（型違い）だけは、1回だけ`SendMessage`で再開し、NGの行を示して同じファイルに書き直させる（REDは1ファイルずつ読み直させる）。
- RED・BLUEの全受領とゲートG3の通過の後に`python3 scripts/aggregate_findings.py --work <保存先> --target <対象>`を1回実行する。`findings-log.jsonl`・`5b-pair-table.md`・`members.json`・`5c-components.txt`を作るので、集約・5b・5cのスクリプトは書かない。rc1はNG。
- 同梱スクリプトの本体は読まない（入出力は本書と`--help`）。
- `書き出し: 拒否`なら、戻り値のJSON Linesを無加工で同じファイル名に保存し、同じ検査を行う。
- CVSS-JUDGEの出力は、`check_cvss_decisions.py --append <出力ファイル>`でそのまま追記する（memo行。reasons行は`findings.jsonl`の作成に使う）。

## 4. WRITERの出力キー

WRITERの指示書では、1指摘＝JSON1行で次のキーを指定する（`finding-final.md`5dの各フィールドに対応）: `id`（作業ID）・`short_summary`・`summary`・`plain`・`tech`・`code_ranges`（`"file:start-end"`の配列。最大3範囲・各15行以内。該当コードはスクリプトが対象から読むので、コードを引用させない）・`annot`（文字列の配列。1要素＝1箇条）・`scenario`・`fix_expl`・`residual`（同じ形。無ければ`[]`）・`intent`・`behavior`・`compat`（`①`・`②`・`③`・`②③`・`①③`）・`compat_note`・`design_conflict`（`有り`／`無し`）・`design_refs`・`review`（修正案が要検討の指摘だけ。他は空）・`alts`（`[案名,内容,メリット,デメリット,デグレの可能性,推奨度]`の配列）・`alts_note`・`audit_method`・`audit_verdict`・`audit_evidence`。

## 5. findings.jsonl と5・6節の組み立て

1. 最終番号の確定後、`python3 scripts/build_findings.py --work <保存先> --sources <5aのタグ。JSON>`（統合diffがあれば`--integrated`・`--base`・`--base-audit`・`--not-merged`）で`findings.jsonl`（1指摘＝1行）と`sources.json`を作る。スクリプトを書かず、書き写さない。出どころは集約の結果・`cvss-raw-output.jsonl`・CVSS-JUDGEのreasons行・WRITERの出力・`5b-pair-table.md`。`fix`はSYNTHのdiff（無ければBLUEの確定diff）、統合diffを置く指摘は統合diffで、`audit`はArbiterが統合diffの確認結果で書く（`--base-audit`）。統合diffから個別の指摘のdiffを切り出さない。
2. `python3 scripts/render_findings_s56.py <保存先>/findings.jsonl --target <対象> --mask-file <追加の秘密値> --out <作業ディレクトリ>/s56.md`を実行する。対象の設定ファイルの秘密値（`check_secret_leak.py`と同じ規則）は自動で`<マスク>`になるが、それ以外は集まらないので、`<追加の秘密値>`（`check_secret_leak.py --extra-file`と同じファイル。1行1値。作業ディレクトリと保存先の外に置く。無ければ空のファイル）を必ず渡す。必須キーの欠けは`error:`で止まる。
3. 出典別レポート（手順7）を先に作り、統合レポートは`python3 scripts/assemble_report.py --work <保存先> --prose <文章のJSON> --out <レポート> --by-source-dir <保存先> --sca-raw <SCA出力>`で、HTMLは`render_html.py --work … --report <レポート> --target … --mask-file … --out …`で作る。Arbiterは文章（キーは`assemble_report.py`の説明）だけをJSONに書き、表・件数・5・6節は書かない。直すときはデータか文章を直して再実行する。
4. `mode3-report.md`の件数の検算と各checker（`check_cvss_decisions.py --report`等）は、組み立てた最終レポートに対して行う。
