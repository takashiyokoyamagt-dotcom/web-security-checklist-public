<!--split:add-->
# モード2 監査レビュー
本ファイルはSKILL.mdから移設した部分。本文中の「モード2手順N」「5a〜5f」「モード3手順N」「〜節」等の参照先のファイルは、SKILL.mdのモード2・モード3の必読一覧とゲート一覧（ファイルごとの担当）で引く。
<!--split:end-->
## モード2: マルチエージェント監査レビュー（差分単位）

単一視点のレビューでは見落としが出やすいため、Red Team（攻撃者視点で指摘を出す）と
Blue Team（実コード全体の文脈で検証・反証する）に役割を分けて行います。
最終判断はArbiter（このSKILLを実行しているあなた自身）が行います。

### 手順

1. **対象範囲の特定**: 差分に含まれる変更ファイルを確認する。あわせて`python3 scripts/check_sources.py --offline --brief`を1回実行し、出力（原典の確認日が古い旨）があれば最初の報告に1行で書いて続行する（`references/sources/source-versions.md`）。
2. **カテゴリの絞り込み**: `references/modes/category-map.md` を使い、変更内容から関連する
   `principles.md` のカテゴリを判定する。**入力値検証とアクセス制御は多くの変更に関わるため、
   他に1つでも該当カテゴリがあれば合わせて含めるのが基本方針**（見落としの方が誤検知よりコストが高い）。
   純粋な見た目変更等で影響カテゴリがなければ、その旨を報告してモード2を終了してよい。
   カテゴリ数が決まった時点で、起動予定のエージェント数（カテゴリ数×Red/Blue=2）と概算所要時間
   （目安: 1カテゴリあたり数分、合計で数分〜10分程度）を伝え、**AskUserQuestionで「この内容で
   進めてよいか（あわせて、修正案監査レビューの厳格度を標準/高/最大から選択、CVSSスコアに
   環境メトリクスを反映するか）」をユーザーに確認し、応答を待ってから次に進む**（モード3手順0と
   同様、一方的な通知で終わらせず応答待ちにする。厳格度の詳細は「修正案監査レビューの厳格度」節、
   環境メトリクスの詳細は「CVSSスコアの算定」節を参照。いずれも特に指定がなければ、厳格度は標準・
   CVSSは基本メトリクス(Base)のみを既定値として進めてよい）。数十件規模の巨大な差分等、
   通常より時間がかかりそうな場合は特に触れておく。
   該当カテゴリが5個以上など多い場合は、モード3手順1のバッチ処理（`references/modes/mode3-full-audit.md`）に準じて
   Blue Team以降をバッチに分けて処理することを推奨する（必須ではない）。あわせて、後述の
   実施メタデータ記載のため、この時点の日時を「解析開始日時」として記録する。
<!--split:add-->
3〜5. **Red Team/Blue Team起動、Arbiter集約、修正案作成(5a〜5f)**: 手順3は`references/pipeline/finding-pipeline.md`、手順4・5は`references/pipeline/finding-arbiter.md`（5a〜5c）と`references/pipeline/finding-final.md`（5d〜5f）に移設（旧手順3〜5。手順番号はそのまま）。finding-pipeline.mdは読んでから手順3に進み、finding-arbiter.md・finding-final.mdと`references/cvss/cvss-scoring.md`はゲートM4（SKILL.md。手順4の前）で読むこと。
補足: 下記「出力フォーマット」中の「手順3」= finding-pipeline.md 手順3、「リスク分析章」= references/cvss/cvss-scoring.md「リスク分析章への反映」節（約160行目）。
補足2: レポートをファイル保存する予定がある場合のみ、5fで`cvss-decisions.jsonl`を書く（手順2の確認に保存の有無を含める。保存後に求められた場合は`by:"post"`で再構成）。完成確認は`references/modes/mode3-report.md`。保存しないモード2の結果には判定記録が無い。
<!--split:end-->
6. **提示**: 指摘＋修正案をユーザーに提示する。ユーザーが明示的に自動適用（`--fix`相当の指示、
   例:「見つかった問題を直接修正して」）を求めた場合のみ、その場でファイルを編集する。
   指示がなければ提示に留める。

### 出力フォーマット
各指摘は次の形式で示す（`ReportFindings`ツールが使える文脈では、フィールド名はそちらの構成に従いつつ、
`vulnerable_code`・`sources`に加え、5dで生成した`plain_explanation`・`technical_detail`・
`code_issue_annotation`・`fix_explanation`、5eの`fix_audit_*`、5fの`cvss_v3_*`/`cvss_v4_*`の
内容も、ツールの固定フィールド内（`summary`等）に書き添えて欠落させないこと）。ユーザーが
ファイル保存を求めた場合は
`assets/templates/report_template.md`と同じ見出し語・同じ構成で保存する。ただしモード2は次の点で
モード3と異なるため、以下のとおり簡略化する:
- 「3. カテゴリ別実施状況」は全11カテゴリの網羅確認ではなく、手順2で絞り込んだ関連カテゴリの
  起動有無・Confirmed件数のみを記す。
- 指摘は重大度の帯順に並べ、同じ帯では参照0件で現状は未使用の指摘を末尾に置き、該当指摘に「現状は未使用のため実質問題なし」を明記する（`references/pipeline/finding-final.md` 5f「並び順」、`references/cvss/cvss-scoring.md`「未使用の欠陥」）。
- 「9. 自己レビュー（見落とし確認）」はモード3手順4に固有のため、モード2では
  省略してよい。
- 「2. 実施メタデータ」は省略せず記入する。値はモード3手順0/1/5と同様に取り、
  手順1着手時の日時を解析開始日時、手順3のRed Team/Blue Team起動数は数えながら記録し、
  ファイル保存直前の日時を解析終了日時とする。修正案監査レビューの厳格度・CVSS環境メトリクスの
  反映有無は手順2で確認した設定値を、使用ツールは対象範囲でSCAスキャンを実行したか（依存関係管理
  カテゴリが対象範囲に含まれる場合のみ）と`scripts/calculate_cvss.py`の実行有無を記す。
  いずれも記憶や概算で埋めない。
- SCAを実行した場合のみ、8節のEPSS・KEVの表と5節の「悪用状況（EPSS/KEV）」行を`assets/templates/report_template.md`と同じ形で使う。

````text
[重大度] 概要
- file:line
- category (CWE)
- verdict
- CVSS: v3.1 <cvss_v3_score>（<cvss_v3_severity>） / v4.0 <cvss_v4_score>（<cvss_v4_severity>）
  （メトリクス別の判定根拠はリスク分析章を参照）
- 該当コード:
  ```
  <vulnerable_codeの引用>
  ```
- 該当コードの問題点: <code_issue_annotation>
- わかりやすい解説（専門知識を前提としない説明）: <plain_explanation>
- 技術的詳細解説: <technical_detail>
- 攻撃シナリオ: <failure_scenario>
- 根拠: <sourcesから組み立てた文字列>
- 修正案:
  ```
  <fix_suggestionのコード片/diff>
  ```
- 修正内容の解説: <fix_explanation>
- 修正案の監査レビュー: <fix_audit_method>による検証・<fix_audit_verdict>（根拠: <fix_audit_evidence>）
````

REFUTEDにした指摘は、全指摘の後に「不採用（REFUTED）」節を置き、件名と理由1行（反証の根拠。あれば`file:line`）を書く（0件なら省略。保存時は12節）。すべての指摘を提示し終えたら、**出典別まとめ**を1つ追加する（詳細の重複は避け、一覧表で示す）:

```text
**CVSS整合性確認**: <cvss_consistency_note>

### 出典別まとめ
| 出典 | 該当した指摘 |
|---|---|
| IPA「安全なウェブサイトの作り方」 | [Critical] 概要A (file:line), [Medium] 概要C (file:line) |
| OWASP ASVS | ... |
| OWASP Cheat Sheet Series | ... |
| CWE Top 25 | ... |
| 依存関係SCA | ... |
```
該当指摘が0件の出典は行ごと省略してよい。ファイル成果物を
求められた場合は、モード3の出典別レポート（`references/modes/mode3-by-source.md`手順7）と同じ要領で出典ごとのMarkdownファイルを追加保存して
よい。この追加保存がWriteツールに拒否されたときもモード3手順7と同じく、
Bashのheredoc等で回避しない（全モード共通の原則）。

