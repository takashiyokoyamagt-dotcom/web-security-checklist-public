# Claude Code

Claude Codeは基準環境で、環境差分はない。入口は`SKILL.md`で、モードごとの読込と予算は`manifest.json`に定める。

- 導入: `web-security-checklist/`をClaude Codeのスキルの置き場所（例: `~/.claude/skills/`、プロジェクトの`.claude/skills/`）に置く。
- 提供範囲: モード1・2・3のすべて（AskUserQuestion、サブエージェント、シェル、ファイル書き込み、Artifactを使う）。

Claude Code固有の差分が生じたら、このフォルダに置き、`SKILL.md`から参照する。
