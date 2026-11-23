---
name: web-security-checklist
description: >-
  VS Code Copilot Chat向けのWebアプリ セキュリティチェックリスト（IPA「安全なウェブサイトの作り方」・OWASP ASVS・
  OWASP Cheat Sheet Series・CWE Top25・依存関係のSCA）。Webアプリのログイン・DB操作・API・ファイルアップロード等の
  コードを新規に実装・追加するとき、ユーザーに確認してからチェックリストに沿って生成する（モード1）。
  既存コードや差分のセキュリティ確認を頼まれたときは、マルチエージェントの監査ではない「簡易確認」として
  助言する（モード2はこの環境で未確認、モード3は提供しない）。「セキュリティチェックして」「脆弱性がないか見て」
  「安全な実装で作って」などWebアプリのコードに関する依頼で使う。
---

# Webアプリ セキュリティチェックリスト（VS Code Copilot Chat版）

このファイルは`adapters/copilot/vscode/SKILL-copilot.md`を、Copilot用に`SKILL.md`へ置き換えたもの。判定基準の本体は同じフォルダの`references/`にある。Claude Code版との違いは、提供するモードと、使えないツールの扱いだけである。

## 提供範囲

| 依頼 | この環境での扱い |
| --- | --- |
| 新しくコードを書く・機能を追加する | モード1（下記） |
| 差分・PR・既存コードの確認 | 「簡易確認」（下記）。モード2は実機確認前のため提供しない |
| リポジトリ全体の総合監査・レポート作成 | 提供しない（サブエージェントによるRed/Blueの分離を確認していないため）。Claude Codeのモード3を案内する |

迷うときは、どの扱いを希望するかをチャットで質問し、回答を待つ（無言で決め打ちしない）。

## 使う前に

1. `references/checklists/principles.md`を読む。DBを扱うなら`references/checklists/database/_index.md`と、そこに示す項目のファイルも読む。依存関係の確認が必要なら`references/checklists/dependency-sca.md`を読む。
2. スタックの検出: ターミナルを使えるなら、このSKILLのフォルダ（例: `.github/skills/web-security-checklist/`）の`scripts/detect_stack.py`を対象ディレクトリを引数にして実行し、出力された`references/lang/*.md`を読む。実行できない・拒否されたときは、別の手段で迂回せず、依存の宣言ファイル（package.json等）から推定したことを明記する。
3. 迷ったとき・原則に触れる判断のときは`references/core/common-principles.md`を読む。

## モード1: チェックリスト準拠のコード生成

1. 生成の前にチャットで確認する（例: 「IPA/OWASP ASVSベースのセキュリティチェックリストに沿って生成しますか？（推奨）／通常どおり生成しますか？」）。回答を待つ。
2. 「沿って生成する」の場合:
   - `principles.md`の関連カテゴリ（今回の実装に関わるものだけ）と、検出したスタックの`lang/*.md`を確認する。
   - 満たすべき項目を実装前に短く列挙してから生成する。
   - 生成したコードの該当箇所に、どの項目をどう満たしたかを簡潔なコメントで残す（例: 「パラメータ化クエリでSQLi対策」）。
3. 「通常どおり」の場合も、明らかに重大なリスク（平文のパスワード保存等）が混入しそうなら一言注意する。

## 簡易確認（差分・既存コードの確認を頼まれたとき）

- 回答の冒頭に「簡易確認（単一エージェント。Red/Blueの検証・CVSSの算定は行っていない）」と書く。
- `references/modes/category-map.md`で関係するカテゴリを選び、`principles.md`の該当節と照らして気づいた点を挙げる。
- 指摘ごとに、ファイルと行、問題、根拠（IPA章番号・ASVS項番・Cheat Sheet名・CWE番号のうち確かなもの）、修正の方向を書く。確かでない根拠は書かない。
- 重大度は「高・中・低（目安）」までとし、CVSSのベクターやスコアは書かない（LLMが暗算しない）。必要ならClaude Codeのモード2・3を案内する。
- 確証のない指摘は「要確認」と分けて書き、事実として断定しない。

## 全モード共通の原則（要約）

- 誠実な報告: 実行できなかった・判断できないことは「未実施」「不明」と書く。
- ツールに拒否されたら別の手段で迂回しない。
- 根拠を示す。チェックリストは判断材料であり、全項目を機械的に強制しない。

## モード2の実機評価（P8。評価者が明示したときのみ）

評価者が「モード2を試行」と明示したときだけ、Claude Code版のモード2の必読とゲートM4の9本（`references/modes/mode2-audit-review.md`、`references/pipeline/finding-pipeline.md`、`references/pipeline/finding-arbiter.md`、`references/pipeline/finding-final.md`、`references/pipeline/fix-audit-strictness.md`、`references/cvss/cvss.md`、`references/cvss/cvss-scoring.md`、`references/core/common-principles.md`、`references/core/agent-roles.md`）を読んで試す。AskUserQuestionとAgentはこの環境の質問とサブエージェントに読み替える。最終応答には、実際に読んだファイル、Red/Blueを別のサブエージェントで動かせたか、`scripts/calculate_cvss.py`を実行できたかを1行ずつ書く。実行できなかったCVSSは「未算定」とし、暗算で埋めない。
