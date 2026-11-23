# 変更履歴

`web-security-checklist`の版ごとの主な変更。版番号は`web-security-checklist/manifest.json`の`skill.version`。

## v2.0.0（2026-11-23）

最初の版番号付きの版。

### 主な変更

- **安全網**: `manifest.json`（版、環境、手順、役割ごとの読込ファイル、予算）、読み手別の読込予算の検査（`check_read_budget.py`）、モード2の手順検査、`.sh`のPython移植（`detect_stack.py`・`run_sca_scan.py`）。
- **構造の再編**: `references/`を下位フォルダ（core、modes、pipeline、cvss、design、checklists、sources、lang）に、`assets/`を`templates/`に分けた。
- **DBの強化**: `references/checklists/database.md`を`database/`の7ファイル（`_index`、SQLi、アクセス、データ保護、ネットワークとTLS、ログ、運用の確認依頼）に分け、ACSC ISMの管理策を取り込んだ。運用でしか確かめられない事項は指摘にせず、報告書の「運用の確認依頼（データベース）」に載せる（DB-OPS-01〜11）。出典ISM（タグ、出典別レポート、HTMLのタブ）、`detect_stack.py`のDB検出の修正、TLSは`verify-full`を求める記述を足した。
- **処理のスクリプト化**: 指摘の集約、CVSSの確定と最終番号、JUDGE・WRITERの入力、`findings.jsonl`、出典別レポート、統合レポートとHTMLの組み立てを同梱スクリプトにした（`aggregate_findings.py`、`synth_groups.py`、`make_packets.py`、`cvss_finalize.py`、`build_findings.py`、`render_findings_s56.py`、`render_by_source.py`、`assemble_report.py`、`render_html.py`）。サブエージェントの結果はファイル経由で受け渡し、書き出し後に検査する（`references/core/handoff-files.md`、`scripts/check_handoff.py`）。
- **読込量の削減と遅延ロード**: モード2の`finding-arbiter.md`・`cvss-scoring.md`を遅延ロードに移し、手順1〜3の読込を約半分にした。`finding-arbiter.md`の後半を`finding-final.md`に分け、WRITER・CVSS-JUDGE・SYNTHの読込を減らした。
- **総合検証での修正**: モード2の文書の不足、KEV・EPSSが無いときの報告書の欄、OWASP Cheat Sheetの一覧（139件）、CVSS 0.0の表示、SYNTHの戻り値の保存と検査（`check_handoff.py --schema`）、WRITERの出力の型の検査を直した。
- **他の環境向けの雛形**（`web-security-checklist/adapters/`）: GitHub Copilotと、GitHub Agentic Workflows（PRレビューと、手動起動だけの総合確認）の雛形を公式文書に沿って作った。

### 未検証

- CopilotとGitHub Agentic Workflowsの雛形は実環境で確かめていない（`manifest.json`の`environments`は`unverified`）。
- LLMを含むSKILL全体の実行は、すべてのOSでは確かめていない。
