# web-security-checklist

Claude Code Skill「`web-security-checklist`」一式。Webアプリのリポジトリに対し、IPA「安全なウェブサイトの
作り方」・OWASP ASVS・OWASP Cheat Sheet Series・CWE Top 25・依存関係SCAを統合したチェックリストで、
コード生成／敵対的コードレビュー／マルチエージェント総合監査の3モードのセキュリティ確認を行う。

## 構成

- [`web-security-checklist/`](./web-security-checklist/) — SKILL本体（`SKILL.md`(入口)、`references/`(チェックリスト＋モード別手順。モード3の手順5〜7・Arbiter手順・CVSS判定基準は遅延ロード用に別ファイル)、
  スクリプト、evalフィクスチャ）。使い方は `web-security-checklist/docs/USAGE_GUIDE.md` を参照。
  版ごとの変更は [`CHANGELOG.md`](./CHANGELOG.md)（現在 v2.0.0）。

## 注意

- 使うには、`web-security-checklist/` フォルダを `~/.claude/skills/` の下に置きます。
- これは公開用の版です。開発記録（`dev/`、`docs/HISTORY.md`）、評価の実行結果、採点用の正解表は含めていません。
  文書の中にそれらへの参照が残っていますが、公開版には含まれていません。
- 評価用のサンプルアプリ（`web-security-checklist/evals/`）は、意図的に脆弱性と偽の秘密情報を含みます。
  本番環境では動かさないでください。

## ライセンス

[MIT](./LICENSE)
