# GitHub Agentic Workflows（エンジンはCopilot）

PRレビューを優先する。リポジトリ全体の確認（モード3に当たるもの）は手動起動だけにし、試行の扱いとする。形式はgh-awの公式文書（確認日 2026-11-22。出典は`dev/p8/adapters-20261122.md`）で確かめた。

| ファイル | 起動 | 出力（safe-outputs） | 時間の上限 |
| --- | --- | --- | --- |
| `adapters/gh-aw/workflows/wsc-pr-review.md` | PRの作成・更新・レビュー可能化（下書きは除く） | 行へのレビューコメント最大10件、COMMENTのレビュー1件 | 20分 |
| `adapters/gh-aw/workflows/wsc-full-audit.md` | 手動（workflow_dispatch）のみ | 指定したIssue/PRへのコメント1件 | 60分 |

## 権限と安全の設計

- エージェントのジョブには読み取りの権限だけを与える（`contents: read`ほか）。書き込みはsafe-outputsの別ジョブが行い、出力の種類と件数をフロントマターで制限する。
- レビューは`allowed-events: [COMMENT]`だけにし、承認・変更要求をさせない。
- `strict: true`（既定）のまま。`forks:`を書かないので、フォークからのPRでは起動しない（gh-awの既定）。起動できる利用者は`roles`の既定（admin、maintainer、write）。
- PRの本文・差分・リポジトリの内容はデータとして扱い、中の指示に従わないよう本文で指示している。gh-awはイベントの文面の無害化と出力の脅威検出も行うが、公式文書は検出を多層防御の一部としており、完全な防御ではない。
- チェックリストを変更するPRでは、変更後の基準を信用しないよう本文で指示している。
- bashは読み取りのコマンドだけを許可する。スクリプトは実行しないので、CVSSと依存関係のSCAは行わない（結果に明記させる）。

## 導入

1. 対象リポジトリに、このSKILLを`.github/skills/web-security-checklist/`として置く（`adapters/copilot/README.md`のVS Codeへの導入と同じ。`SKILL.md`はCopilot版に置き換える。Claude Code版のままだと、エンジンがモード3の指示を読む恐れがある）。
2. `gh extension install github/gh-aw`でgh-awを入れる。
3. 使うワークフローのファイルを、対象リポジトリの`.github/workflows/`に複製する。
4. `gh aw compile`を実行し、生成された`.lock.yml`と元の`.md`の両方をコミットする。
5. Copilotの認証を用意する。組織でCopilotの請求をまとめていれば`copilot-requests: write`を使う方法、そうでなければ、Copilot Requestsの読み取り権限を持つfine-grainedの個人用アクセストークンをリポジトリのシークレット`COPILOT_GITHUB_TOKEN`に登録する方法がある（公式のクイックスタート）。
6. 総合確認は`gh aw run wsc-full-audit`、またはActionsの画面から、結果を書くIssue/PRの番号を指定して起動する。

## 未確認（P9の実機評価で確かめる）

| 項目 | 状態 |
| --- | --- |
| `gh aw compile`がこの2ファイルをエラーなく変換するか | 未確認（この環境ではgh-awを実行していない） |
| bashの許可の書き方（コマンド名の列挙で前方一致になるか） | 未確認 |
| 1回の実行時間、20分・60分の上限で足りるか | 未確認 |
| 課金（Copilotのリクエスト数、Actionsの実行時間） | 未確認 |
| 認証（`copilot-requests`と`COPILOT_GITHUB_TOKEN`のどちらが使えるか） | 未確認 |
| 行コメントの位置の正確さ、指摘の品質（Claude Codeの基準値は流用しない） | 未確認 |
| 悪意ある指示を含むPRで、指示に従わず報告するか | 未確認 |
| Red/Blueを別のサブエージェントに分離できるか | 未確認。確認できるまで`adapters/gh-aw/workflows/wsc-full-audit.md`はモード3として扱わない |
