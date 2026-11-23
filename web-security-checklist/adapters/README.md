# adapters（環境ごとの差分）

このフォルダには、Claude Code以外の環境でこのSKILLを使うための差分だけを置く。判定基準の本体（`references/`・`assets/`・`scripts/`）は複製せず、各環境からそのまま参照する。

**Claude Codeのモード1・2・3はこのフォルダを読まない。** 読込予算（`manifest.json`の`budgets`）にも含めない。

| フォルダ | 環境 | 提供する範囲 | 状態 |
| --- | --- | --- | --- |
| `adapters/claude-code/` | Claude Code（Linux、Windows、macOS） | 全モード | 基準環境。差分なし（README.mdのみ） |
| `adapters/copilot/` | VS Code Copilot Chat | モード1。モード2は実機確認後 | 雛形のみ。実機未確認 |
| `adapters/copilot/` | github.com Copilot Chat | 助言とコード生成時の確認のみ（「簡易確認」） | 雛形のみ。実機未確認 |
| `adapters/gh-aw/` | GitHub Agentic Workflows（エンジンはCopilot） | PRレビュー。モード3は手動起動のみ | 雛形のみ。実機未確認 |

共通の約束:

- サブエージェントで分離できない環境ではモード3を提供しない。
- スクリプトを実行できない環境では、CVSSなどの数値をLLMが暗算しない（「未算定」と書く）。
- 品質は環境ごとに測定し、Claude Codeの基準値を流用しない。
- 雛形の形式は各環境の公式文書で確かめた（確認日と出典は`dev/p8/adapters-20261122.md`）。
