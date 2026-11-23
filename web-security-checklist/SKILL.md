---
name: web-security-checklist
description: >-
  Webアプリケーションのリポジトリに対して、IPA「安全なウェブサイトの作り方」・OWASP ASVS・OWASP Cheat Sheet
  Series・CWE Top25・依存関係のSCA(既知脆弱性)チェックに基づくセキュリティ確認を行う。3つのモードを持つ:
  (1) コード生成モード — ユーザーに確認した上で、チェックリストに沿った実装を提案・生成する。
  (2) 監査レビューモード — 差分/PRに対しRed Team(攻撃者視点)とBlue Team(検証・反証)のマルチエージェントで
  厳格にレビューし、確証の取れた指摘に修正diffを添えて提示する。
  (3) 総合監査モード — リポジトリ全体をカテゴリ別マルチエージェント(Red/Blue/Arbiter)で監査し、
  Markdown・HTML Artifact両方のレポートを作成する。モード2/3とも、指摘ごとにCVSS v3.1/v4.0スコアを
  算定し、重大度はCVSS v3.1の定量的区分を正として付与する。
  ユーザーが「セキュリティチェックして」「脆弱性がないか確認して」「このコードレビューして」
  「セキュリティ観点でレビューして」「総合監査/最終確認して」「セキュリティレポート作って」
  「DBまわり/認証まわりが安全か見て」「CVSSスコアを出して」「リスク分析して」などWebアプリの
  コードに関して言った場合、またはWebアプリのログイン・DB操作・API・ファイルアップロード等の
  コードを新規実装/追加する際には、明示的に「セキュリティ」と言われていなくても積極的に
  このスキルを使うこと。
---

# Webアプリ セキュリティチェックリスト SKILL

IPA・OWASP ASVS・OWASP Cheat Sheet Series・CWE Top25・依存関係SCAを統合したチェックリストを軸に、コード生成・監査レビュー・総合監査の3モードを提供します。
判定基準の実体は `references/checklists/principles.md` に一元化されています。モード1・2ではまずそちらを読み込んでください（モード3は下記の必読とゲートに従う）。

## 使う前に: 基準となるチェックリストを読み込む

モード1・2では、作業開始時に必ず `references/checklists/principles.md` を読み込んでください。データベースを
扱う場合は追加で `references/checklists/database/_index.md` と、そこに示す項目のファイルも読み込みます。依存関係チェックが必要な場合は
`references/checklists/dependency-sca.md` を参照してください。対象リポジトリのスタックが分かれば
`scripts/detect_stack.sh <対象ディレクトリ>` を実行し、該当する `references/lang/*.md` を読み込んでください
（未対応言語は `principles.md` の原則で判断する）。

<!--split:add-->
モード3の例外: `scripts/detect_stack.sh`はモード3でも手順1の前に実行する（R1）が、principles/database/lang/dependency-scaはオーケストレータが起動時に読まない（サブエージェントへパス渡し、principles等はG3。詳細はモード3節）。
<!--split:end-->
## モード判定

依頼文から次のように判定し、迷う場合はAskUserQuestionで希望のモードを確認する（無言で決め打ちしない）。

- 「〜を実装して」「〜機能を追加して」等、**新しくコードを書く/追加する**依頼で、対象がWebアプリの
  ログイン・DB操作・API・ファイル処理など本チェックリストに関わる場合 → **モード1**
- 差分・PR・「このコード/この変更をレビューして」等、**既存の変更を確認する**依頼 → **モード2**
- 「総合監査して」「最終確認して」「リポジトリ全体をチェックして」「セキュリティレポートを作って」等、
  **リポジトリ全体を対象にした網羅的な確認** → **モード3**
- 「DBまわりが安全か見て」等の**特定の機能領域だけ**の依頼は、既存コードの一部ならモード2、
  リポジトリ横断ならモード3寄りとし、迷えばAskUserQuestionで確認する。

---

## モード1: チェックリスト準拠コード生成

自動で強制せず、**必ず生成前にユーザーへ確認**します（厳格に適用すると生成コードの分量やレビュー観点が増えるため、
試作か本番向けかの意図を確かめてから適用する）。

1. AskUserQuestionで確認する（例:「IPA/OWASP ASVSベースのセキュリティチェックリストに沿って生成しますか？」—
   「はい（推奨）」/「いいえ、通常通り生成する」）。
2. 「はい」の場合:
   - `principles.md` の関連カテゴリ（今回の実装に関わるものだけでよい。例: ログイン機能なら
     認証・セッション管理・入力値検証）と、検出したスタックの `lang/*.md` を確認する。
   - 満たすべき項目を実装前に短く列挙してから生成する。
   - 該当箇所に、どの項目をどう満たしたか（例:「パラメータ化クエリでSQLi対策」）を短いコメントで残す（羅列は避け、根拠が追えれば十分）。
3. 「いいえ」なら通常通り生成し、明らかに重大なリスク（平文パスワード保存等）が混入しそうなら一言注意を添える。

---

<!--split:add-->
## 全モード共通の原則（要約。正本は `references/core/common-principles.md`）

モード1・2・3のすべてに次の4原則が適用されます。詳細・例外・理由は `references/core/common-principles.md` にあります
（モード2/3では必読。モード1では、迷ったとき・原則に触れる判断のときに読む）。
- **誠実な報告**: ツール未実行・スキャン未完了・判断不能のときは「不明/未実施」と書き、結果を捏造しない。
- **ツールに拒否されたら別の手段で回避しない**: Write等が拒否されたらBash heredoc等で迂回せず、拒否の事実を報告する。
- **根拠の明示**: 指摘には IPA章番号 / OWASP ASVS項番 / Cheat Sheet名 / CWE番号を添える。
- **過剰な足かせにしない**: チェックリストは判断材料であり、機械的な全項目強制ではない（重大度の調整はCVSS環境メトリクスで行う）。

---

## モード2: マルチエージェント監査レビュー（差分単位）— 概要

関連カテゴリごとにRed Team（攻撃者視点）→ Blue Team（実コード全体で検証・反証）→ Arbiter（あなた自身）の順で指摘を絞り込み、
採用した指摘に出典タグ(sources)・多層解説(5d)・修正案の監査レビュー(5e)・CVSS v3.1/v4.0(5f、`scripts/calculate_cvss.py`)を付け、
重大度はCVSS v3.1の区分を正とします。**手順の実体はこのファイルにはありません。**

**必読ファイル（モード2の着手前、カテゴリ判定・エージェント起動より前に、次の6つをすべて`Read`すること。モード3のゲート（G0〜G7・R1）は適用されない）**:
1. `references/modes/mode2-audit-review.md` — 手順1・2、手順6、出力フォーマット
2. `references/pipeline/finding-pipeline.md` — 手順3（Red/Blue起動・骨子、出力の構造化、結果の即時ファイル永続化）
3. `references/pipeline/fix-audit-strictness.md` — 5e（修正案監査レビューの厳格度）
4. `references/cvss/cvss.md` — CVSSスコアの算定の概要・環境メトリクスの確認
5. `references/core/common-principles.md` — 全モード共通の原則
6. `references/core/agent-roles.md` — Red/Blue/5e専用監査等の委任時の種別・モデル・実行制約（委任しない場合も読む）

**遅延ロード（ゲートM4。モード2のみ）**: 手順4（Arbiterの集約）に入る**前**に、`references/pipeline/finding-arbiter.md`（手順4・5。集約、5a〜5c）、`references/pipeline/finding-final.md`（5d〜5f）と`references/cvss/cvss-scoring.md`（5fの判定基準・判定原則・基準ベクター・整合性確認・スコア算出・リスク分析章への反映）をReadし、通過後の最初の出力に3ファイルの`GATE-TOKEN:`行を引用する。未読のまま集約・5a〜5f・CVSS算定を始めず、自己流で代替しない。手順2で影響カテゴリが無くモード2を終える場合は読まない。未読のまま手順4以降を進めていた場合は停止し、3ファイルを読んで既存の集約・5a〜5fを点検する。

**条件付き必読（モード2のみ）**: (a) 該当カテゴリが5個以上 → `references/modes/mode3-full-audit.md`（手順0・1のバッチ処理を準用。同ファイルのR1/G3等はモード3専用で無視し、principles.md等はモード2の従来どおり読む）。
(b) レポートのファイル保存を求められた、または実施メタデータを記入する → (a)に加え`references/modes/mode3-report.md`（手順5のみ。手順6のHTMLは不要）。
(c) 出典別ファイルの追加保存を求められた → (a)に加え`references/modes/mode3-html.md`（0件出典の判定基準のみ参照。同ファイル内のG6等はモード3専用で無視）、`references/modes/mode3-by-source.md`と`assets/templates/report_template_by_source.md`（手順7）。
理由: モード2の手順2・出力フォーマット・手順3がこれらのモード3手順を名指しで参照しており、読まないと参照先が空振りする。
(d) 設計書の候補を手順1で1回だけ探し（`mode3-full-audit.md`のG2の候補の行だけ準用。未読ならその行だけ参照）、1件でもある → `references/design/design-intent.md`（必読6本・M4に含めない）。0件・設計情報なしでも、Red/Blueには「設計書なし」と`references/design/design-fields.md`のパスを渡す（探索は手順1で1回のまま）

読まずに進めると5d・5e・5f（CVSS算定とスクリプト実行）・出力フォーマットが**未実行**になり、重大度がCVSS基準にならない・
修正案が未検証・必須章が欠落する等、成果物が不完全になります。読み込めないファイルは代替せず、ユーザーに報告してください。
**最終応答には、実際に`Read`したreferencesファイル名を1行で報告すること**（例:「読了: mode2-audit-review, finding-pipeline, ...」）。続けて設計書の探索結果を「設計書: 候補N件／なし（探索: …）」で述べる。
委任（Agent起動）をした場合は、最終応答にも役割別の種別・モデル（指定値/指定なし）・代替使用を1行で述べる（モード2で保存しない場合の唯一の記録）。

## モード3: マルチエージェント総合監査（リポジトリ全体）— 概要

モード2と同じRed/Blue/Arbiter構成を全11カテゴリに適用し、Markdown・HTML Artifact・出典別Markdownレポートを作成する（最大22エージェント）。**手順の実体はこのファイルにはありません。**

**必読ファイル（G0: モード3の着手前、手順0より前に、次の5つをすべて`Read`すること）**:
1. `references/modes/mode3-full-audit.md` — 手順0〜4。手順5〜7の実体は別ファイル（下記ゲート）
2. `references/pipeline/finding-pipeline.md` — 手順3（Red/Blue起動・骨子・結果の即時ファイル永続化）
3. `references/pipeline/fix-audit-strictness.md` — 5eの厳格度（手順0で確認）
4. `references/cvss/cvss.md` — CVSS環境メトリクスの確認（手順0で確認）
5. `references/core/common-principles.md` — 全モード共通の原則

**遅延ロード（ゲート。モード3のみ）**: 次は、示した手順に入る**前**にReadする。未読のままその手順の作業を始めず、自己流で代替しない。通過後の最初の出力に、新規ファイル冒頭の`GATE-TOKEN:`行を引用する。読めない場合は代替せず報告する。
- G1（手順1の前）: `references/core/agent-roles.md`、`references/core/handoff-files.md`（Agent起動前。通過後の最初の出力に`GATE-TOKEN:`行を引用）
- G2（手順1のRed起動前。条件付き）: 設計書の候補が1件でもあれば`references/design/design-intent.md`。候補の一覧と、無いときの記録は`mode3-full-audit.md`のG2（無いときは不要）
- G3（手順3の前）: `references/pipeline/finding-arbiter.md`, `references/pipeline/finding-final.md`, `references/cvss/cvss-scoring.md`, `references/checklists/principles.md`, `references/sources/ipa-secure-website.md`, `references/sources/cwe-top25.md`, `references/sources/owasp-cheatsheets.md`, `references/checklists/dependency-sca.md`
- G5（手順5の前）: `references/modes/mode3-report.md`, `assets/templates/report_template.md`
- G6（手順6の前）: `references/modes/mode3-html.md`
- G7（手順7の前）: `references/modes/mode3-by-source.md`, `assets/templates/report_template_by_source.md`
**サブエージェントに渡す（手順1でオーケストレータは全文Readしない）**: `principles.md`の該当節、`database/`、`detect_stack.sh`が示す`lang/*.md`、`dependency-sca.md`（R1）。
G0の必読が読み込めない場合は代替せず、その旨をユーザーに報告する。
**最終応答には、実際にReadしたreferences/assetsファイル名をゲート別に1行で報告すること**（未通過は「未読」。G2は設計書が無ければ「G2: 設計書なし（探索: …）」）。

## references/ の分割構成

- 13ファイル（agent-roles, mode2, pipeline, arbiter, final, mode3, mode3-report, mode3-html, mode3-by-source, fix-audit, cvss, cvss-scoring, common）

<!--split:end-->
## 補足ドキュメント (`docs/`)

- `docs/HISTORY.md`: 今の設計（3モード・Red/Blue/Arbiter構成等）になった経緯。仕様変更の理由が分からないとき・他のAgentに経緯を引き継ぐときに読む。
- `docs/USAGE_GUIDE.md`: 予備知識がない人向けの使い方ガイド（3モードの具体例、`principles.md`全項目の平易な解説）。使い方やチェック項目の意味を一般向けに説明するときに読む。
- `docs/SOURCES.md`: `references/`各ファイルが根拠にする外部基準（IPA/OWASP ASVS/Cheat Sheet Series/CWE Top25）の整理と最新化の確認先。`references/`を更新・見直しする前に読む。
- `docs/OPERATIONS.md`: モード2/3の長時間実行が中断した場合の運用ガイド（障害パターンと復旧手順、予防の工夫）と、コンテキストの圧迫を防ぐ結果保持方法（構造化フォーマット・即時ファイル永続化・バッチ処理・ログからの再構成）。モード3の中断時、コンテキスト消費が気になるとき、または事前確認に読む。
