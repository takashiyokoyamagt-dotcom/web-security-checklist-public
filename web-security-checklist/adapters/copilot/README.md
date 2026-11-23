# Copilot Chat（VS Code、github.com）

公式文書（確認日 2026-11-22。出典は`dev/p8/adapters-20261122.md`）によると、使える仕組みは環境ごとに違う。

| 環境 | 使う仕組み | 置き場所（対象リポジトリ） | 提供範囲 |
| --- | --- | --- | --- |
| VS Code Copilot Chat | Agent Skills | `.github/skills/web-security-checklist/SKILL.md` | モード1と「簡易確認」。モード2は実機確認後 |
| github.com Copilot Chat | リポジトリ全体のカスタム指示 | `.github/copilot-instructions.md` | 助言とコード生成時の確認のみ（「簡易確認」） |

github.com Copilot Chatは、公式の対応表でパス別の指示（`.github/instructions/*.instructions.md`）とAGENTS.mdに対応しておらず、Agent Skillsの対応先にも挙がっていない。プロンプトファイル（`.github/prompts/*.prompt.md`）はVS Codeの旧方式（Localハーネス）専用で2027年2月に廃止予定のため使わない。

## VS Code Copilot Chatへの導入

1. このSKILLのフォルダ（`web-security-checklist/`）を、対象リポジトリの`.github/skills/web-security-checklist/`に複製する。`adapters/`・`docs/`・`evals/`は複製しなくてよい。
2. 複製先の`SKILL.md`を、`adapters/copilot/vscode/SKILL-copilot.md`の内容で置き換える（フォルダ名と`name`が一致している必要がある）。
3. チャットで`/web-security-checklist`と入力するか、実装やレビューを依頼して自動で読み込まれることを確かめる。

注意:

- 同じリポジトリの`.claude/skills/`にClaude Code版を置くと、VS Codeが同名のSKILLを二重に読む場合がある（未確認）。どちらか一方にする。
- `scripts/detect_stack.py`はターミナルの実行承認が必要になる。承認しなければ、依存の宣言ファイルからの推定になる。
- CVSSは算定しない。重大度は目安で示す。

## github.com Copilot Chatへの導入

1. `adapters/copilot/github-com/instructions.md`の内容（コメントの「ここから」〜「ここまで」）を、対象リポジトリの`.github/copilot-instructions.md`の末尾に貼る（無ければ新規に作る）。
2. 既定のブランチへ取り込み、github.comのChatでそのリポジトリを対象にして質問する。

注意:

- このファイルは、github.comのChatだけでなく、VS CodeのChat、Copilotのコードレビュー、クラウドエージェントにも読み込まれる。常に読み込まれるので、内容を増やすほど全ての会話の文脈を使う。
- スクリプトは実行できない前提で書いている。既知脆弱性の判定とCVSSの算定は行わない。
- 結果はマルチエージェントの監査と同等ではない。正式な確認はClaude Codeのモード2・3で行う。

## 提供しないもの

- モード3（総合監査）: サブエージェントによるRed/Blueの分離を、どちらの環境でも確認していない。
- github.comでのモード2: スクリプトを実行できず、CVSSの算定と修正案の監査ができない。

## 未確認（P8の実機評価で確かめる）

- VS Codeが`adapters/copilot/vscode/SKILL-copilot.md`由来のSKILLを期待どおりに読み込み、`references/`を必要な時だけ読むか。
- VS Codeでのモード1の品質（Claude Codeの基準値は流用しない）。
- VS Codeでのモード2の可否（Red/Blueを別のサブエージェントで動かせるか、`scripts/calculate_cvss.py`を実行できるか）。SKILL内の「モード2の実機評価」節を使う。
- github.comのChatが`.github/copilot-instructions.md`の節を守るか（「簡易確認」の表示、CVSSを書かない）。
