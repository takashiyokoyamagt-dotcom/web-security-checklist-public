#!/usr/bin/env python3
"""成果物への秘密値の漏れの検査（標準ライブラリのみ。Python 3.9以上）。
監査した対象リポジトリ（--source）の設定・秘密系のファイルから秘密値の候補を集め、成果物の保存先
（--outputs。再帰的に走査。複数回指定できる: 作業ディレクトリと保存先の両方を走査する）のテキスト
ファイルに、候補がそのまま（またはJSON・HTMLのエスケープ形で）部分文字列として含まれていないかを調べる。
秘密値は報告書・出典別レポート・HTML・Artifactに渡すファイル・保存する判定記録（jsonl）・委任の指示書の
どこにも出してはならない（引用せずマスク）。
候補の収集: ファイル名が config / settings / secret / credential / application を含む、.env で始まる・
.env. を含む、docker-compose*.yml・.yaml（compose*.yml・.yamlも）、または親ディレクトリ名（--source から
のいずれかの階層）が config / conf / settings / secrets / env のファイル（node_modules・.git・vendor・
lockfile、--source の中にある --outputs の配下は除く）から、鍵名が secret / key / token / pass /
password / passwd / pwd / credential / private / auth / jwt / salt / cert / signing の「鍵名: 値」
「鍵名 = 値」の値（--min-len 以上）。鍵名は、単語の区切り（キャメルケース・スネークケース・ケバブケース・
ドットの境界）で区切った語のどれかが判定語（とその複数形等）に一致するときだけ対象にする（author・
passport_strategy・keyboard_layout は対象外）。
JS・JSON・Python等のコードでは引用符付きの文字列だけを値とし（参照式の後ろの既定値の文字列も取る。
環境変数・設定の参照の引数（環境変数名・config.get('a.b') の鍵のパス）は取らない）、.env・YAML・ini等
では引用符なしの値（行末まで）も取る。引用符で囲まれた値は、内側に空白や「語:」があっても引用符の
終わりまでを1つの値とする。URLに埋め込まれた「://ユーザー:パスワード@」のパスワードも取る。
除外は、参照式（process.env.X・os.environ等）、プレースホルダ（<...>・${...}・{{...}}・changeme・
x/*だけの値・your-...-here等）、true/false/null 等だけ（.env.example のようなサンプルの値も、実在しそう
なら候補にする）。候補を集めた設定ファイル自身（realpath）は走査しない（--outputs と --source が同じ、
または包含関係でも、設定ファイル自身はヒットにならない）。
--extra-file には1行1リテラルで追加の秘密値を書く（成果物の保存先の外に置く。中にあれば走査しない）。
値は画面にもログにも出さない（ヒットは「ファイル:行」と「***(長さ)」だけを出し、値の文字は1つも出さない）。
限界: 改行をまたぐ値・一部を変形した値（分割・Base64化等）は検出しない。上のファイル名・ディレクトリ名・
鍵名の判定範囲の外にある秘密値（例: 区切りなしの小文字の鍵名 dbpassword・apikey、設定ファイル以外の
コードに直書きした値）と、--min-len 未満の値は検出しない（--extra-file で足す）。鍵名に該当語を含む
秘密でない値（例: 認証方式の名前）も候補になり得る（出典の「ファイル:行」で確かめる）。
終了コード 0=ヒットなし（候補0件はWARNで0） 1=ヒットあり 2=入力エラー。
最終行は RESULT: OK / RESULT: NG (N件) / RESULT: ERROR。"""

from __future__ import annotations

import argparse
import contextlib
import html
import io
import json
import os
import re
import sys
import tempfile

SKIP_DIRS = {"node_modules", ".git", "vendor"}
SCAN_SKIP_DIRS = {".git", "node_modules"}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "composer.lock", "gemfile.lock", "poetry.lock", "pipfile.lock", "cargo.lock",
    "go.sum", "mix.lock", "pubspec.lock", "packages.lock.json", "bun.lockb",
}
NAME_WORDS = ("config", "settings", "secret", "credential", "application")
CONFIG_DIRS = {"config", "conf", "settings", "secrets", "env"}
COMPOSE_RE = re.compile(r"^(?:docker-)?compose[\w.\-]*\.ya?ml$")
# 鍵名を単語の区切りで分けた語が、次のどれかに一致するときだけ候補にする
KEY_TOKENS = {
    "secret", "secrets", "key", "keys", "token", "tokens", "pass", "password", "passwords",
    "passphrase", "passwd", "pwd", "credential", "credentials", "creds", "private", "auth",
    "authorization", "jwt", "salt", "cert", "certs", "signing",
}
# 引用符なしの値も取る形式（拡張子。.env系・拡張子なしもこちら）
PLAIN_EXT = {".env", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties", ".toml", ""}
MAX_SOURCE_BYTES = 2 * 1024 * 1024

KEY_RE = re.compile(
    r"""(?:^|(?<=[\s{,(\[;]))(?:export\s+)?["']?([A-Za-z_$][\w$.\-]*)["']?\s*(?::(?!//)|=(?![=>~]))"""
)
LIT_RE = re.compile(r"""(["'`])((?:\\.|(?!\1).)*)\1""")
URL_CRED_RE = re.compile(r"""[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'"`]+:([^\s@/'"`]+)@""")
# 環境変数・設定の参照の引数（環境変数名・鍵のパス）の直前の形
ENV_CALL_RE = re.compile(
    r"(?:environ(?:\.get)?|getenv|process\.env|\benv|\bENV(?:\.fetch)?|\bconfig|\bConfig\.get|"
    r"\.(?:get\w*|fetch|require|has|value))\s*[\(\[]\s*$"
)
REF_RE = re.compile(
    r"^(?:process\.env|os\.environ|os\.getenv|getenv\s*\(|System\.getenv|ENV\[|ENV\.fetch|env\s*\(|"
    r"import\.meta\.env|Deno\.env|config\s*\(|require\s*\()"
)
NOT_SECRET = {
    "true", "false", "null", "none", "nil", "undefined", "yes", "no", "on", "off",
    "changeme", "change_me", "change-me", "password", "secret", "example", "placeholder",
    "dummy", "sample", "default", "required", "optional",
}
PLACEHOLDER_RE = re.compile(
    r"^(?:<[^<>]*>|\$\{[^{}]*\}|\{\{.*\}\}|%[^%]*%|[xX*.\-_]+|"
    r"(?:your|enter|insert)[-_ ].*|.*[-_ ]here)$",
    re.IGNORECASE,
)
WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

SHOW_CANDS = 5  # 成功時にも出る候補の一覧の上限（件数は1行目に全件を出す）


def is_config_file(rel: str) -> bool:
    """--source からの相対パスで、設定・秘密系のファイルかを判定する"""
    parts = rel.replace(os.sep, "/").split("/")
    low = parts[-1].lower()
    if low in LOCKFILES or low.endswith(".lock"):
        return False
    if low.startswith(".env") or ".env." in low or COMPOSE_RE.match(low):
        return True
    if any(w in low for w in NAME_WORDS):
        return True
    return any(d.lower() in CONFIG_DIRS for d in parts[:-1])


def is_secret_key(key: str) -> bool:
    """鍵名を単語の区切り（キャメル・スネーク・ケバブ・ドット）で分け、判定語に一致する語があるか"""
    words: list[str] = []
    for part in re.split(r"[^A-Za-z0-9]+", key):
        words += WORD_RE.findall(part)
    return any(w.lower() in KEY_TOKENS for w in words)


def plain_style(name: str) -> bool:
    low = name.lower()
    if low.startswith(".env") or ".env." in low or low.endswith(".env"):
        return True
    return os.path.splitext(low)[1] in PLAIN_EXT


def acceptable(val: str, min_len: int) -> bool:
    v = val.strip()
    if len(v) < min_len:
        return False
    if v.lower() in NOT_SECRET or PLACEHOLDER_RE.match(v) or REF_RE.match(v):
        return False
    return True


def clean_plain(seg: str) -> str:
    """引用符なしの値: 行末コメント・末尾の区切りを除く"""
    s = seg.strip()
    s = re.split(r"\s+[#;]", s, maxsplit=1)[0]
    return s.rstrip(",;").strip()


def extract_line(line: str, plain: bool, min_len: int) -> list[tuple[str, str]]:
    """1行から (鍵名, 値) の候補を返す"""
    out: list[tuple[str, str]] = []
    st = line.lstrip()
    if st.startswith(("#", "//", ";", "*", "/*")):
        return out
    spans = [(lm.start(), lm.end()) for lm in LIT_RE.finditer(line)]
    # 引用符の内側（値の中の「空白＋語＋:」等）で始まる鍵は、鍵とみなさない
    keys = [m for m in KEY_RE.finditer(line) if not any(s < m.start() < e for s, e in spans)]
    consumed = 0
    for i, m in enumerate(keys):
        if m.start() < consumed:
            continue
        nxt = next((k.start() for k in keys[i + 1:] if k.start() >= m.end()), len(line))
        seg = line[m.end():nxt]
        lits = list(LIT_RE.finditer(seg))
        secret_key = is_secret_key(m.group(1))
        if lits:
            if not secret_key:
                continue
            for lm in lits:
                if ENV_CALL_RE.search(seg[: lm.start()]):
                    continue  # 環境変数・設定の参照の引数（環境変数名・鍵のパス）
                if acceptable(lm.group(2), min_len):
                    out.append((m.group(1), lm.group(2)))
        elif plain:
            v = clean_plain(line[m.end():])
            if not v or v[0] in "|>{[&*!":
                continue
            consumed = len(line)  # 引用符なしの値は行末まで（値の中の「語:」を次の鍵とみなさない）
            if secret_key and acceptable(v, min_len):
                out.append((m.group(1), v))
    for um in URL_CRED_RE.finditer(line):
        if acceptable(um.group(1), min_len):
            out.append(("(URL)", um.group(1)))
    return out


def _real(p: str) -> str:
    return os.path.realpath(os.path.abspath(p))


def collect(source: str, min_len: int, exclude_dirs: set[str] | None = None):
    """候補 {値: [(相対パス, 行, 鍵名)]}・設定ファイル数・読んだ設定ファイルのrealpathの集合"""
    cands: dict[str, list[tuple[str, int, str]]] = {}
    files: set[str] = set()
    excl = exclude_dirs or set()
    for dp, dns, fns in os.walk(source):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and _real(os.path.join(dp, d)) not in excl)
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, source)
            if not is_config_file(rel):
                continue
            try:
                if os.path.getsize(p) > MAX_SOURCE_BYTES:
                    continue
                with open(p, "rb") as f:
                    raw = f.read()
            except OSError:
                continue
            if b"\0" in raw[:8192]:
                continue
            files.add(_real(p))
            plain = plain_style(fn)
            for ln, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
                for key, val in extract_line(line, plain, min_len):
                    cands.setdefault(val, []).append((rel, ln, key))
    return cands, len(files), files


def variants(val: str) -> list[bytes]:
    """そのまま・JSON・HTMLのエスケープ形（重複除去）"""
    forms = [
        val,
        json.dumps(val)[1:-1],
        json.dumps(val, ensure_ascii=False)[1:-1],
        html.escape(val, quote=True),
        html.escape(val, quote=False),
        val.replace("/", "\\/"),
    ]
    seen: list[bytes] = []
    for s in forms:
        b = s.encode("utf-8")
        if b and b not in seen:
            seen.append(b)
    return seen


def mask(val: str) -> str:
    """値の文字は1つも出さず、長さだけを出す"""
    return f"***({len(val)}文字)"


def scan(outputs: list[str], cands: dict, skip: set[str]):
    """ヒット [(表示パス, 行, 値)]・テキスト数・バイナリ数（重なる保存先のファイルは1回だけ走査）"""
    hits: list[tuple[str, int, str]] = []
    ntext = nbin = 0
    pats = {v: variants(v) for v in cands}
    seen: set[str] = set()
    for root in outputs:
        for dp, dns, fns in os.walk(root):
            dns[:] = sorted(d for d in dns if d not in SCAN_SKIP_DIRS)
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                rp = _real(p)
                if rp in skip or rp in seen:
                    continue
                seen.add(rp)
                try:
                    with open(p, "rb") as f:
                        raw = f.read()
                except OSError:
                    continue
                if b"\0" in raw[:8192]:
                    nbin += 1
                    continue
                ntext += 1
                rel = os.path.relpath(p, root)
                shown = rel if len(outputs) == 1 else os.path.join(root, rel)
                for v, forms in pats.items():
                    lines: set[int] = set()
                    for b in forms:
                        i = raw.find(b)
                        while i != -1:
                            lines.add(raw.count(b"\n", 0, i) + 1)
                            i = raw.find(b, i + 1)
                    for ln in sorted(lines):
                        hits.append((shown, ln, v))
    return hits, ntext, nbin


def run(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="成果物への秘密値の漏れの検査")
    ap.add_argument("--source", help="監査した対象リポジトリ")
    ap.add_argument("--outputs", action="append",
                    help="成果物の保存先（再帰的に走査。複数回指定できる: 作業ディレクトリと保存先）")
    ap.add_argument("--min-len", type=int, default=8, help="候補にする値の最小長（既定8）")
    ap.add_argument("--extra-file", help="追加の秘密値（1行1リテラル）")
    ap.add_argument("--self-test", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        if e.code == 0:  # --help
            return 0
        print("RESULT: ERROR")
        return 2
    if a.self_test:
        return self_test()
    err = []
    if not a.source or not os.path.isdir(a.source):
        err.append(f"--source がディレクトリでない: {a.source}")
    if not a.outputs:
        err.append("--outputs が無い")
    for o in a.outputs or []:
        if not os.path.isdir(o):
            err.append(f"--outputs がディレクトリでない: {o}")
    if a.min_len < 1:
        err.append(f"--min-len は1以上: {a.min_len}")
    extra: list[str] = []
    if a.extra_file:
        try:
            with open(a.extra_file, encoding="utf-8") as f:
                extra = [ln.rstrip("\r\n") for ln in f if ln.strip()]
        except (OSError, UnicodeDecodeError) as e:
            err.append(f"--extra-file を読めない: {a.extra_file} ({type(e).__name__})")
    if err:
        for e in err:
            print(f"ERROR: {e}")
        print("RESULT: ERROR")
        return 2
    src_real = _real(a.source)
    # --source の中にある保存先は、候補の収集から外す（成果物を設定ファイルとみなさない）
    excl = {_real(o) for o in a.outputs if _real(o) != src_real}
    cands, nconf, conf_files = collect(a.source, a.min_len, excl)
    for i, v in enumerate(extra, 1):
        if len(v) >= a.min_len:
            cands.setdefault(v, []).append(("--extra-file", i, "-"))
        else:
            print(f"WARN: --extra-file の{i}行目は{a.min_len}文字未満のため使わない")
    # 候補を集めた設定ファイル自身と --extra-file は走査しない（保存先と同じ・包含関係のとき）
    skip = set(conf_files)
    if a.extra_file:
        skip.add(_real(a.extra_file))
    hits, ntext, nbin = scan(a.outputs, cands, skip)
    print(f"設定・秘密系のファイル {nconf}本 / 候補 {len(cands)}件 / 走査 {ntext}本（バイナリ除外 {nbin}本）")
    for v, locs in list(cands.items())[:SHOW_CANDS]:  # 一覧は先頭だけ（P6: 出力の短縮。NGの行は全件）
        where = ", ".join(f"{r}:{ln}（鍵名 {k}）" for r, ln, k in locs[:3])
        more = f" ほか{len(locs) - 3}箇所" if len(locs) > 3 else ""
        print(f"  候補 {len(v)}文字: {where}{more}")
    if len(cands) > SHOW_CANDS:
        print(f"  候補ほか{len(cands) - SHOW_CANDS}件（一覧は省略）")
    if not cands:
        print("WARN: 候補0件（設定ファイルが見つからない、または鍵名に該当なし）")
    if hits:
        for rel, ln, v in hits:
            r, sl, k = cands[v][0]
            print(f"NG: {rel}:{ln} に秘密値 {mask(v)}（出典 {r}:{sl} 鍵名 {k}）")
        print(f"RESULT: NG ({len(hits)}件)")
        return 1
    print("RESULT: OK")
    return 0


def _write(path: str, text: str | bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(text, bytes) else "w"
    with open(path, mode, **({} if isinstance(text, bytes) else {"encoding": "utf-8"})) as f:
        f.write(text)


def _call(args: list[str]) -> tuple[int, str]:
    """標準出力・標準エラー・例外メッセージをまとめて取り込む"""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            rc = run(args)
        except Exception as e:  # noqa: BLE001  例外メッセージも値の露出の検査対象にする
            print(f"EXCEPTION: {type(e).__name__}: {e}")
            rc = 99
    return rc, buf.getvalue()


def self_test() -> int:
    # 偽の値。英単語を含めず、先頭2文字（大文字＋小文字）が出力の他の語に現れないものにする
    s_js, s_fb, s_env, s_envq, s_json, s_yml, s_py, s_url, s_extra = (
        "Qz7mR2-vK9p-0x41", "Vx3nL8-fq2W", "Wq5tB7yH2cN9", "Zj!4pR8sD1m",
        "Kq2&Hm6Lr9", "Yx#8dN3kV5", "Jq9-wT4zM7", "Xz6gF1hQ3", "Qv2-eY8uP5",
    )
    s_sp, s_dir, s_dc, s_jwt, s_salt = (
        "Zw7 rJ def:Gh4-pL9", "Kv9cX2bN6m", "Yq8hT5jW3", "Jx6sD9fG2k", "Xq5vB8nM1",
    )
    noise = ["NOT_A_SECRET_ENVNAME", "SECRET_KEY_NAME"]
    fp = ["Wz4tauthorx-91", "Vq3pport-x8", "Zk2kblay-US7", "auth.jwtSecret"]
    all_secrets = [s_js, s_fb, s_env, s_envq, s_json, s_yml, s_py, s_url, s_extra,
                   s_sp, s_dir, s_dc, s_jwt, s_salt]
    fails: list[str] = []

    def check(name: str, cond: bool) -> None:
        print(f"  {'ok ' if cond else 'NG '} {name}")
        if not cond:
            fails.append(name)

    def leaked(o: str) -> bool:
        """値の一部（先頭2文字・末尾3文字・連続4文字）が出力に出ていれば真"""
        for s in all_secrets:
            if s[:2] in o or s[-3:] in o or any(s[i:i + 4] in o for i in range(len(s) - 3)):
                return True
        return False

    with tempfile.TemporaryDirectory() as td:
        src, out = os.path.join(td, "src"), os.path.join(td, "out")
        _write(os.path.join(src, "config.js"), (
            "// apiKey: 'commentedOut-123456'\n"
            "module.exports = {\n"
            f"  jwtSecret: '{s_js}',\n"
            f"  apiKey: process.env.API_KEY || '{s_fb}',\n"
            "  sessionSecret: process.env.SESSION_SECRET,\n"
            "  authMode: tokenVar,\n"
            "  dbPassword: '<your-password>',\n"
            "  privateKey: 'xxxxxxxxxxxx',\n"
            "  port: 3000, name: 'not-a-secret-value',\n"
            f"  author: '{fp[0]}', passport_strategy: '{fp[1]}', keyboard_layout: '{fp[2]}',\n"
            f"  jwtSecretRef: config.get('{fp[3]}'),\n"
            f"  sessionKey: '{s_sp}',\n"
            "};\n"
        ))
        _write(os.path.join(src, ".env.example"), (
            f"API_TOKEN={s_env}\n"
            f"export DB_PASSWORD=\"{s_envq}\"\n"
            "SECRET_KEY=${SECRET_FROM_VAULT}\n"
            "AUTH_PASS=changeme\n"
            "ENABLE_AUTH=true\n"
            "SHORT_KEY=abc\n"
            f"DATABASE_URL=postgres://app:{s_url}@db:5432/app\n"
        ))
        _write(os.path.join(src, "settings.json"), (
            "{\n"
            f'  "apiKey": "{s_json}",\n'
            '  "refreshToken": null,\n'
            '  "secretPath": "${HOME_SECRET_PATH}"\n'
            "}\n"
        ))
        _write(os.path.join(src, "conf", "application.yml"), (
            "db:\n"
            f"  password: {s_yml}  # 本番では差し替え\n"
            "  admin_pass: <admin-password>\n"
            "  auth_enabled: false\n"
            "  token_cert: |\n"
        ))
        _write(os.path.join(src, "app", "settings.py"), (
            f"SECRET_KEY = os.environ.get('{noise[1]}', '{s_py}')\n"
            f"API_KEY = os.getenv('{noise[0]}')\n"
        ))
        _write(os.path.join(src, "config", "env", "development.js"), (
            "module.exports = {\n"
            f"  cookieSecret: '{s_dir}',\n"
            f"  jwtKey: '{s_jwt}',\n"
            f"  salt: \"{s_salt}\",\n"
            "};\n"
        ))
        _write(os.path.join(src, "docker-compose.yml"), (
            "services:\n  db:\n    environment:\n"
            f"      POSTGRES_PASSWORD: {s_dc}\n"
            "      POSTGRES_USER: app\n"
        ))
        _write(os.path.join(src, "node_modules", "pkg", "config.js"), "secret: 'nodeModulesSecret99'\n")
        _write(os.path.join(src, "package-lock.json"), '{"integrity": "lockfileSecretToken1"}\n')
        _write(os.path.join(src, "server.js"), "const apiKey = 'notConfigFile-12345';\n")

        cands, nconf, _ = collect(src, 8)
        expect = {s_js, s_fb, s_env, s_envq, s_json, s_yml, s_py, s_url, s_sp, s_dir, s_dc, s_jwt, s_salt}
        check("候補の抽出（JS・.env・JSON・YAML・Python・URL・config/env配下・docker-compose・jwtKey・salt）",
              set(cands) == expect)
        check("参照式・プレースホルダ・true/false/null・環境変数名の除外", not (set(cands) - expect))
        check("鍵名の区切り判定（author・passport_strategy・keyboard_layout）とconfig.get('…')の鍵のパスの除外",
              not any(f in cands for f in fp))
        check("値の中の空白とコロン（'… def:…'）を引用符の終わりまで1つの値として取る", s_sp in cands)
        check("node_modules・lockfile・設定以外のファイル名の除外", nconf == 7)

        extra = os.path.join(td, "extra.txt")
        _write(extra, f"{s_extra}\nshort\n")
        _write(os.path.join(out, "report.md"), f"# 報告\n\n鍵は `{s_js}` です\n")
        _write(os.path.join(out, "report.html"), "<p>" + html.escape(f'k="{s_yml}"') + "</p>\n<p>"
               + html.escape(s_json) + "</p>\n")
        _write(os.path.join(out, "sub", "findings.jsonl"), json.dumps({"code": f'p="{s_url}"/{s_extra}'}) + "\n")
        _write(os.path.join(out, "bin.dat"), b"\0\0" + s_env.encode())
        _write(os.path.join(out, "clean.txt"), f"{noise[0]} {noise[1]} マスク済み\n")
        rc, o = _call(["--source", src, "--outputs", out, "--extra-file", extra])
        check("ヒット（md・html（エスケープ形を含む）・jsonl・--extra-file）で rc=1", rc == 1 and o.rstrip().endswith("RESULT: NG (5件)"))
        check("ヒットのファイル:行", all(x in o for x in ("report.md:3", "report.html:1", "report.html:2", os.path.join("sub", "findings.jsonl") + ":1")))
        check("バイナリは走査しない", "bin.dat" not in o)
        check("出力（標準出力・標準エラー）に値の一部（先頭2文字を含む）が出ない", not leaked(o))
        check("マスク表示（***と長さだけ）", f"秘密値 ***({len(s_js)}文字)" in o)

        out2 = os.path.join(td, "out2")
        _write(os.path.join(out2, "report.md"), "秘密値は `***` とマスクした\n")
        _write(os.path.join(out2, "extra.txt"), s_extra + "\n")
        rc, o = _call(["--source", src, "--outputs", out2, "--extra-file", os.path.join(out2, "extra.txt")])
        check("ヒットなしで rc=0（保存先内の--extra-fileは走査しない）", rc == 0 and o.rstrip().endswith("RESULT: OK"))
        check("ヒットなしでも値の一部が出ない", not leaked(o))

        # --outputs の複数指定（作業ディレクトリと保存先）。重なる指定でも同じファイルを二重に数えない
        rc, o = _call(["--source", src, "--outputs", out2, "--outputs", out, "--outputs", os.path.join(out, "sub")])
        check("--outputs の複数指定で全部を走査する（rc=1・4件・表示は保存先つき）",
              rc == 1 and o.rstrip().endswith("RESULT: NG (4件)") and os.path.join(out, "report.md") + ":3" in o)
        check("--outputs の複数指定でも値の一部が出ない", not leaked(o))

        # --source と --outputs が同じ・包含関係: 候補を集めた設定ファイル自身はヒットにしない
        rc, o = _call(["--source", src, "--outputs", src])
        check("--source と --outputs が同じで rc=0（設定ファイル自身はヒットにしない）",
              rc == 0 and o.rstrip().endswith("RESULT: OK"))
        rc, o = _call(["--source", src, "--outputs", td])
        ng = [ln for ln in o.splitlines() if ln.startswith("NG: ")]
        check("--outputs が --source を含むとき設定ファイル自身はヒットにしない（保存先のヒットだけ・4件）",
              rc == 1 and o.rstrip().endswith("RESULT: NG (4件)")
              and not any(ln.startswith("NG: " + "src" + os.sep) for ln in ng))
        inner = os.path.join(src, "audit-out")
        _write(os.path.join(inner, "config-summary.md"), f"鍵 {s_dc} を含む\n")
        _write(os.path.join(inner, "report.md"), "apiKey: 'Kx1notInConfigList-77'\n")
        rc, o = _call(["--source", src, "--outputs", inner])
        check("--outputs が --source の中にあるとき、保存先は候補の収集に使わず走査する（rc=1・1件）",
              rc == 1 and o.rstrip().endswith("RESULT: NG (1件)") and "config-summary.md:1" in o
              and "候補 13件" in o)
        rc, o = _call(["--source", src, "--outputs", src, "--outputs", inner])
        check("同じ・包含の保存先を重ねて指定しても1回だけ走査する（rc=1・1件）",
              rc == 1 and o.rstrip().endswith("RESULT: NG (1件)"))
        check("同じ・包含関係のケースでも値の一部が出ない", not leaked(o))

        empty = os.path.join(td, "empty")
        _write(os.path.join(empty, "main.js"), "const apiKey = 'notConfigFile-12345';\n")
        rc, o = _call(["--source", empty, "--outputs", out2])
        check("候補0件はWARNで rc=0", rc == 0 and "WARN: 候補0件" in o and o.rstrip().endswith("RESULT: OK"))

        rc, o = _call(["--source", os.path.join(td, "nope"), "--outputs", out2])
        check("存在しない--sourceで rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))
        rc, o = _call(["--source", src, "--outputs", out2, "--outputs", os.path.join(td, "nope")])
        check("存在しない--outputs（複数指定の1つ）で rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))
        rc, o = _call(["--source", src])
        check("--outputs が無いと rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))
        rc, o = _call(["--source", src, "--outputs", out2, "--extra-file", os.path.join(td, "nope.txt")])
        check("読めない--extra-fileで rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))
        rc, o = _call(["--source", src, "--outputs", out2, "--min-len", "0"])
        check("--min-len 0で rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))
        rc, o = _call(["--source", src, "--unknown"])
        check("未知の引数で rc=2", rc == 2 and o.rstrip().endswith("RESULT: ERROR"))

    if fails:
        print(f"self-test: NG ({len(fails)}件)")
        print(f"RESULT: NG ({len(fails)}件)")
        return 1
    print("self-test: OK")
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
