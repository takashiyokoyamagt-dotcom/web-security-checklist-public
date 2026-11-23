#!/usr/bin/env python3
"""報告書の指摘本文の「ファイル:行」参照を、対象リポジトリの実ファイルと照合する
（標準ライブラリのみ）。指摘本文の行番号がずれる・別の関数の位置を指す事例（docs/HISTORY.md
47節。run6 NodeGoat）への対応。locate_snippet.py は「該当コード」の断片だけを照合するので、
本文（表のセル・解説の文）の参照はこのスクリプトで照合する（references/pipeline/finding-final.md
5d補足（本文の参照の照合））。

使い方:
  check_refs.py --report <報告書.md> --repo <対象ディレクトリ> [--extra-root <修正後のツリー>]
                [--section 5] [--window 3] [--search 30] [--verbose]
  check_refs.py --self-test
対象: 報告書の「## <section>.」の節（既定は5節。モード2で保存する報告書も同じ構成）の、
  「### <section>.N」の指摘ごとの本文。コードフェンスの中（該当コード・推奨される修正の
  diffの+/-行）と見出しの行は読まない。--repo はモード3では監査した対象、モード2では差分を
  適用した後のツリー。
参照の書式: `path:行`・`path:開始-終了`・`path:行,行`（区切りは , 、 ・。範囲は - – 〜 ~。
  「:」は全角の「：」も認める）、`path#L行-L行`。path は / を含むか拡張子を持つ語（拡張子の
  無い名前は、リポジトリに同名のファイルがあるときだけ）。URL（://）・IPアドレスとポート・
  `localhost:3000` は参照にしない。続きの番号の後ろに助数詞（行・節・章・組・番・箇所等）が
  続くもの（「、6節を参照」）は行番号にしない。短いパス（`session.js:208`）は、リポジトリの
  パスの末尾との一致で解決する（複数あれば全候補で調べる）。node_modules・.git 等は自分の
  ファイルとして数えない。
読むファイル: realpath が --repo（--extra-root）の中にある通常ファイル（S_ISREG）だけを、
  MAX_BYTES まで読む（O_NONBLOCK で開き、開いた後にも通常ファイルかを確かめる）。FIFO・
  デバイス・リポジトリの外へのシンボリックリンクは読まず「未解決」の WARN にする。「..」を
  含む参照は解決しない。
検査:
  (a) ファイルの実在。解決できない参照は、参照のディレクトリ部分がリポジトリに実在する
      （app/routes/x.js の app/routes/ がある）ときだけ NG。依存の置き場所（直下の node_modules・
      vendor 等）にあるもの、node_modules/… と書いたもの、Node.js 等の製品名は対象外。どれでも
      ないもの（依存を導入していない対象での依存の内部・成果物のファイル名・短い名前の誤り）は
      「未解決」の WARN にし、パスごとに1行で示す。
  (b) 行がファイルの行数の範囲内（1以上・行数以下・開始<=終了）。外れは NG。
  修正案の部分（推奨される修正・修正内容の解説・修正後に残るリスクと別経路・修正案の監査
  レビュー・元の処理の意図と、修正による挙動の変化・設計方針に従えない場合の代替案の小見出しの
  下）の参照は、--extra-root を渡せば --repo とそのどちらかで (a)〜(c) が成り立てばよい（修正で
  新設するファイル・修正後の行番号を述べるため）。渡さなければ --repo だけで調べる。
  (c) 同じ単位（表のセル、または文。文は「。」で区切る）の、同じ節（読点「、」「；」で区切る）
      にある識別子のうち、参照先のファイルに現れるものを、文字位置が最も近い参照に割り当てる。
      識別子は、バッククォートで囲んだコード片の語（ルートのパス `/login`、英数字と空白だけの
      語句・コマンド `npm start` は除く）と、本文中のキャメルケース・スネークケース・呼び出し
      `f(`・ドット連結の語、ハイフン連結の語（パッケージ名とみなし、依存の宣言ファイル
      package.json 等の参照にだけ使う）。4文字未満の語・一般的な語（STOP）・参照先のファイルに
      無い語、直後に否定の語（ず・ない・無い・なし・欠如・未適用等。同じ節の12字以内と、節が
      「が」「は」等で終わるときは次の節）が続く語は使わない（無いことを述べる語で誤検出しない
      ため）。区切りだけで並んだ参照（「（a.js:43, b.js:12）」）は1組とし、どれかの近傍にあれば
      よい。文書（.md・.txt 等）の参照は (c) を調べない。割り当てた識別子が1つもその参照の
      行の前後 --window 行以内に無く、範囲の上 --search 行以内にその識別子の定義（関数・変数・
      メソッド・クラス）も無ければ WARN（行番号のずれの疑い）とし、最寄りの出現行（--search
      行以内。無ければファイル内の最寄り）を示す。
  前後 --window 行以内には現れるが参照の範囲そのものには無いものは「近接」として件数だけ示す
  （--verbose で一覧。複数行にまたがる文の参照で普通に起こるので WARN にしない）。
限界: 識別子を含まない参照（「ファイル」行の参照の列だけ等）は (c) を調べない。識別子が前後
  --window 行以内にあれば 1〜3 行のずれは検出しない。識別子が使う行と別の行（定義・設定）に
  ある正しい参照は WARN になりうる（WARN は目で確かめる）。文の意味（その行が述べた挙動を
  するか）は調べない。
終了コード 0=OK（WARNのみでも0） / 1=NG（(a)(b)） / 2=入力エラー（報告書・repoを読めない、
  節が無い）。最終行は RESULT: OK / RESULT: NG (N件) / RESULT: ERROR。Python 3.9以上で動く。"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import stat
import sys
import tempfile

MAX_BYTES = 5_000_000  # 読むファイルの上限（巨大な生成物で止まらないように）
SKIP_DIRS = {".git", "node_modules", ".hg", ".svn", "__pycache__"}
# 依存の内部を指す参照（リポジトリに無いのが普通）は (a) の対象外
DEP_DIRS = set("node_modules vendor site-packages .venv venv bower_components".split())
# 拡張子つきの語のうち、ファイルでなく製品名として書かれるもの（解決できなくても NG にしない）
PRODUCTS = set(
    (
        "node.js vue.js express.js next.js nuxt.js react.js angular.js d3.js chart.js "
        "three.js moment.js ember.js backbone.js socket.io asp.net ado.net"
    ).split()
)
# 一般的すぎて照合の手がかりにならない語（キーワード・頻出の語）
STOP = set(
    (
        "true false null none undefined function return const this self async await "
        "else then catch error value data user users name type string number object "
        "array http https json html path file line lines code text body item items "
        "list from import export default class require module exports console bool "
        "void with when where while break case continue throw throws static public "
        "private "
        "protected final super yield print length index count todo note test tests"
    ).split()
)
CODE_EXT = (
    "js|mjs|cjs|jsx|ts|tsx|json|ya?ml|md|html?|ejs|pug|hbs|njk|twig|vue|svelte|py|rb|"
    "php|java|kt|go|rs|cs|c|h|cpp|hpp|swift|sql|sh|bash|toml|ini|cfg|conf|env|xml|css|"
    "scss|less|lock|txt|gradle|properties|tf|erb|jinja2?|tpl|mustache|graphql|proto"
)
NUM = r"\d+(?:\s?[-–〜~]\s?\d+)?"
# 続きの番号: 「, 16」「、16」「・149-155」。数字の後ろに「行」「節」「組」等の助数詞が
# 続くもの（「、6節を参照」「、3組」）は行番号でない
COUNTER = "行件個つ目回年月日時分秒%節章項組番本名通種箇点倍人台例部段"
MORE = rf"(?:\s?[,、・]\s?{NUM}(?!\d|\.\d|[{COUNTER}]))"
PATHPAT = r"(?:\.{1,2}/)?(?:[\w.\-]+/)*[\w.\-]*[A-Za-z][\w.\-]*"
# 区切りの「:」は全角の「：」も認める（login.js：2）
REF_RE = re.compile(
    rf"(?<![\w./\-@#:：])({PATHPAT})[:：]({NUM}(?!\d|\.\d){MORE}*)", re.ASCII
)
LREF_RE = re.compile(rf"(?<![\w./\-@#:])({PATHPAT})#L(\d+)(?:-L?(\d+))?", re.ASCII)
URL_RE = re.compile(r"[A-Za-z][\w+.\-]*://\S+|\]\(#[^)]*\)", re.ASCII)
FILE_RE = re.compile(rf"[\w./\-]+\.(?:{CODE_EXT})(?![\w])", re.ASCII)
NOISE_RE = re.compile(r"\b(?:CWE|CVE|GHSA|CAPEC)-[\w\-]+|CVSS:[\w./:]+", re.ASCII)
# 依存の宣言ファイル（パッケージ名はこの行にだけ現れる。コードでは別名の変数で使われる）
MANIFEST_RE = re.compile(
    r"(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml"
    r"|bower\.json|requirements[\w.\-]*\.txt|Pipfile(?:\.lock)?|pyproject\.toml"
    r"|poetry\.lock|setup\.(?:py|cfg)|Gemfile(?:\.lock)?|go\.(?:mod|sum)"
    r"|composer\.(?:json|lock)|pom\.xml|build\.gradle(?:\.kts)?|Cargo\.(?:toml|lock))$"
)
# 否定・不在を述べる語。直後にこれが来る識別子は「その行に無い」ことを述べるので照合に使わない
NEG_RE = re.compile(
    r"ず|ない|無い|なし|無し|欠如|欠落|不在|未適用|未設定|未導入|未使用|未実装|未指定"
)
# 文書のファイル。自然文の行は識別子の位置と対応しないので (c) を調べない
DOC_RE = re.compile(r"\.(?:md|markdown|rst|txt|adoc)$", re.I)
TOKEN_RE = re.compile(r"[A-Za-z_$][\w$]*(?:-[A-Za-z0-9_$]+)*", re.ASCII)
TICK_RE = re.compile(r"`([^`\n]+)`")
FENCE = re.compile(r"( {0,3})(`{3,}|~{3,})(.*)$")


def fence_step(ln, open_):
    """CommonMarkに沿ったコードフェンスの開閉（check_5b_clique.py と同じ規則）。
    (この行がフェンス行か, 次の open_) を返す。open_ は開いているフェンスの(文字, 個数)"""
    m = FENCE.match(ln)
    if not m:
        return False, open_
    ch, n, rest = m.group(2)[0], len(m.group(2)), m.group(3)
    if not open_:
        if ch == "`" and "`" in rest:  # インラインコード（```x```）は開きでない
            return False, None
        return True, (ch, n)
    if ch == open_[0] and n >= open_[1] and not rest.strip():
        return True, None
    return False, open_


def split_outside(text: str, seps: str) -> list[tuple[int, str]]:
    """バッククォートの外にある seps の文字で分け、(元の文字位置, 部分) の列を返す"""
    out, start, tick = [], 0, False
    for i, ch in enumerate(text):
        if ch == "`":
            tick = not tick
        elif not tick and ch in seps and not (ch == "|" and i and text[i - 1] == "\\"):
            out.append((start, text[start:i]))
            start = i + 1
    out.append((start, text[start:]))
    return out


def ranges_of(spec: str) -> list[tuple[int, int]]:
    """「12-37, 40」→ [(12, 37), (40, 40)]"""
    out = []
    for part in re.split(r"\s?[,、・]\s?", spec):
        m = re.fullmatch(r"(\d+)(?:\s?[-–〜~]\s?(\d+))?", part.strip())
        if m:
            a = int(m.group(1))
            out.append((a, int(m.group(2)) if m.group(2) else a))
    return out


def find_refs(text: str) -> list[dict]:
    """単位の文字列から参照を取り出す。{path, ranges, span, raw} の列"""
    refs = []
    for m in REF_RE.finditer(text):
        refs.append(
            {
                "path": m.group(1),
                "ranges": ranges_of(m.group(2)),
                "span": m.span(),
                "raw": m.group(0).strip(),
            }
        )
    for m in LREF_RE.finditer(text):
        a = int(m.group(2))
        b = int(m.group(3)) if m.group(3) else a
        refs.append(
            {
                "path": m.group(1),
                "ranges": [(a, b)],
                "span": m.span(),
                "raw": m.group(0),
            }
        )
    return [r for r in refs if r["ranges"]]


def distinctive(tok: str, text: str, end: int, start: int) -> bool:
    """バッククォートの外の語を識別子とみなすか
    （キャメルケース・スネークケース・ハイフン連結・呼び出し・ドット連結）"""
    if "_" in tok.strip("_$") or "-" in tok:
        return True
    if re.search(r"[a-z][A-Z]", tok) and tok[0].islower():
        return True
    nxt = text[end : end + 1]
    prv = text[start - 1 : start] if start else ""
    dotted = nxt == "." and text[end + 1 : end + 2].isalpha()
    return nxt == "(" or dotted or prv == "."


def prose(span: str) -> bool:
    """バッククォートの中身が識別子でないもの: ルートのパス（/login）、記号の無い語句・
    コマンド（npm start、POST /upload）"""
    t = span.strip()
    return t.startswith("/") or (" " in t and bool(re.fullmatch(r"[\w\s/@-]+", t)))


def usable(tok: str) -> bool:
    core = tok.strip("_$")
    return len(core) >= 4 and tok.lower() not in STOP and not core.isdigit()


def negated(text: str, end: int) -> bool:
    """位置 end の後ろに否定の語があるか。見るのは同じ節（読点まで）の、空白・括弧・引用符を
    除いた12字と、その節が「が」「は」等の助詞で終わるときは次の節（述語）の20字。
    例: 「`helmet` が無い」「getUserFromTokenを呼ばず」「Xによる確認が、ここに存在しない」"""
    parts = re.split(r"[、，；;:：]", re.split(r"。", text[end:], maxsplit=1)[0])

    def squeeze(x):
        return re.sub(r"[\s`（）()「」『』]", "", x)

    first = squeeze(parts[0])
    if NEG_RE.search(first[:12]):
        return True
    if len(parts) > 1 and re.search(r"[がはもをに]$", first):
        return bool(NEG_RE.search(squeeze(parts[1])[:20]))
    return False


def find_idents(text: str, refs: list[dict]) -> list[tuple[str, int, bool]]:
    """単位の文字列から照合に使う識別子と文字位置を取り出す。3番目は、バッククォートの外の
    ハイフン連結の語（パッケージ名。依存の宣言ファイルの参照にだけ使う）なら True。
    直後に否定の語が続く識別子（その行に無いことを述べる語）は除く"""
    masked = list(text)

    def blank(a, b):
        masked[a:b] = " " * (b - a)

    for r in refs:
        blank(*r["span"])
    for rx in (URL_RE, NOISE_RE):
        for m in rx.finditer(text):
            blank(*m.span())
    plain = "".join(masked)  # 参照・URLだけを消した文（否定の判定用）
    out = []
    ticks = []
    for m in TICK_RE.finditer("".join(masked)):
        ticks.append(m.span())
        inner = m.group(1)
        if prose(inner):
            continue
        inner_m = FILE_RE.sub(lambda x: " " * len(x.group(0)), inner)
        if negated(plain, m.end()):
            continue
        for t in TOKEN_RE.finditer(inner_m):
            if usable(t.group(0)):
                out.append((t.group(0), m.start(1) + t.start(), False))
    for a, b in ticks:
        blank(a, b)
    for m in FILE_RE.finditer("".join(masked)):
        blank(*m.span())
    s = "".join(masked)
    for t in TOKEN_RE.finditer(s):
        tok = t.group(0)
        if usable(tok) and distinctive(tok, s, t.end(), t.start()):
            if not negated(plain, t.end()):
                out.append((tok, t.start(), "-" in tok))
    return out


def clauses(text: str, refs: list[dict]) -> list[int]:
    """読点（、，；;）で区切った節の境界の文字位置
    （参照の中・バッククォートの中の読点は除く）"""
    cuts, tick = [], False
    for i, ch in enumerate(text):
        if ch == "`":
            tick = not tick
        elif not tick and ch in "、，；;":
            if not any(a <= i < b for a, b in (r["span"] for r in refs)):
                cuts.append(i)
    return cuts


def split_lines(raw: bytes) -> list[str]:
    """改行（\\n）だけで分ける（locate_snippet.py と同じ）。
    末尾の改行の後ろの空行は数えない"""
    text = raw.decode("utf-8-sig", "replace")
    lines = [ln.removesuffix("\r") for ln in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


class Repo:
    """対象リポジトリのファイル一覧・行の読込・識別子の出現行の索引"""

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        self.files: list[str] = []  # 読んでよいファイル（root の中の通常ファイル）
        self.unsafe: list[str] = []  # FIFO・デバイス・root の外へのリンク等（読まない）
        for d, dirs, names in os.walk(self.root):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for n in sorted(names):
                path = os.path.join(d, n)
                rel = os.path.relpath(path, self.root).replace(os.sep, "/")
                (self.files if self.safe(path) else self.unsafe).append(rel)
        self.names = {f.rsplit("/", 1)[-1] for f in self.files}
        # 実在するディレクトリ（「/a/b/」の形。参照のディレクトリ部分の末尾一致に使う）
        parts = [f.split("/")[:-1] for f in self.files]
        anc = {"/" + "/".join(p[:k]) + "/" for p in parts for k in range(1, len(p) + 1)}
        self.dirs = {d[i:] for d in anc for i in range(len(d) - 1) if d[i] == "/"}
        self._deps: list[str] | None = None
        self._lines: dict[str, list[str] | None] = {}
        self._occ: dict[tuple[str, str], list[int]] = {}

    def safe(self, path: str) -> bool:
        """realpath が root の中にあり、通常ファイル（S_ISREG）か。stat は FIFO でも待たない"""
        real = os.path.realpath(path)
        try:
            st = os.stat(real)
        except OSError:
            return False
        inside = os.path.commonpath([self.root, real]) == self.root
        return inside and stat.S_ISREG(st.st_mode)

    def resolve(self, path: str, pool=None) -> list[str]:
        p = re.sub(r"^(?:\./)+", "", path.replace("\\", "/")).lstrip("/")
        if ".." in p.split("/"):
            return []
        pool = self.files if pool is None else pool
        if p in pool:
            return [p]
        return [f for f in pool if f.endswith("/" + p)]

    def in_deps(self, path: str) -> bool:
        """依存の置き場所（直下の node_modules 等）に、末尾が一致するファイルがあるか"""
        if self._deps is None:
            self._deps = []
            for top in sorted(DEP_DIRS):
                base = os.path.join(self.root, top)
                for d, dirs, names in os.walk(base):
                    dirs[:] = sorted(x for x in dirs if x != ".git")
                    for n in names:
                        rel = os.path.relpath(os.path.join(d, n), self.root)
                        self._deps.append("/" + rel.replace(os.sep, "/"))
        p = "/" + re.sub(r"^(?:\./)+", "", path.replace("\\", "/")).lstrip("/")
        return any(f.endswith(p) for f in self._deps)

    def own_dir(self, path: str) -> bool:
        """参照のディレクトリ部分が、リポジトリに実在するディレクトリの末尾と一致するか"""
        p = re.sub(r"^(?:\./)+", "", path.replace("\\", "/")).lstrip("/")
        return "/" in p and "/" + p.rsplit("/", 1)[0] + "/" in self.dirs

    def lines(self, rel: str) -> list[str] | None:
        """行の列。root の外・通常ファイルでない・MAX_BYTES 超・読めないときは None。
        開いた後にも通常ファイルかを確かめ（O_NONBLOCK で FIFO を待たない）、上限まで読む"""
        if rel not in self._lines:
            self._lines[rel] = None
            path = os.path.join(self.root, rel)
            if rel in self.files and self.safe(path):
                flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                try:
                    fd = os.open(os.path.realpath(path), flags)
                    with os.fdopen(fd, "rb") as f:
                        if stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                            raw = f.read(MAX_BYTES + 1)
                            if len(raw) <= MAX_BYTES:
                                self._lines[rel] = split_lines(raw)
                except OSError:
                    pass
        return self._lines[rel]

    def occ(self, rel: str, ident: str) -> list[int]:
        """識別子が（語の境界で）現れる行番号の昇順リスト"""
        key = (rel, ident)
        if key not in self._occ:
            b = r"[\w$\-]" if "-" in ident else r"[\w$]"
            rx = re.compile(rf"(?<!{b}){re.escape(ident)}(?!{b})")
            ls = self.lines(rel) or []
            self._occ[key] = [i for i, s in enumerate(ls, 1) if rx.search(s)]
        return self._occ[key]


def fence_lines(text: str):
    """コードフェンスの外の (行番号, 行) を順に返す（フェンスの行自体も除く）"""
    fence = None
    for n, ln in enumerate(text.split("\n"), 1):
        isf, fence = fence_step(ln, fence)
        if not (isf or fence):
            yield n, ln


# 修正案の部分（修正で新設するファイル・修正後の行番号を述べうる）の小見出し
FIX_LABELS = (
    "推奨される修正",
    "修正内容の解説",
    "修正後に残るリスクと別経路",
    "修正案の監査レビュー",
    "元の処理の意図と、修正による挙動の変化",
    "設計方針に従えない場合の代替案",
)


def units(report_text: str, section: str):
    """(指摘番号, 報告書の行番号, 単位の文字列, 修正案の部分か) を順に返す。
    単位は表のセルか文。修正案の部分は FIX_LABELS の小見出しから次の小見出しまで"""
    in_sec, cur, fix = False, None, False
    head = re.compile(rf"^## {re.escape(section)}\.")
    item = re.compile(rf"^### ({re.escape(section)}\.\d+)(?![\d.])")
    for n, ln in fence_lines(report_text):
        if re.match(r"^#{1,2} ", ln):
            in_sec, cur = bool(head.match(ln)), None
            continue
        if not in_sec:
            continue
        m = item.match(ln)
        if m:
            cur, fix = m.group(1), False
            continue
        if cur is None or ln.startswith("#"):
            continue
        s = ln.strip()
        lab = re.match(r"\*\*([^*]+)\*\*", s)
        if lab:
            fix = lab.group(1).startswith(FIX_LABELS)
        if s.startswith("|"):
            if re.fullmatch(r"[|\-: ]+", s):
                continue
            parts = [p for _, p in split_outside(s.strip("|"), "|")]
        else:
            parts = [s]
        for part in parts:
            for _, sent in split_outside(part, "。"):
                if sent.strip():
                    yield cur, n, sent, fix


def defines(line: str, ident: str) -> bool:
    """行が ident の定義（関数・メソッド・変数への関数の代入・クラス）か"""
    i = re.escape(ident)
    return bool(
        re.search(
            rf"\b(?:function|def|class|func|fn)\s+{i}\b"
            rf"|\b(?:const|let|var)\s+{i}\s*="
            rf"|\b(?:this|exports|self)\.{i}\s*="
            r"|^\s*(?:(?:public|private|protected|static|async|export)\s+)*"
            rf"{i}\s*\([^)]*\)\s*(?::[^{{=]*)?\{{",
            line,
        )
    )


def near(occ: list[int], a: int, b: int) -> tuple[int, int] | None:
    """範囲 a〜b に最も近い出現行と符号つきの距離（範囲内は0）"""
    best = None
    for x in occ:
        d = 0 if a <= x <= b else (x - b if x > b else x - a)
        if best is None or abs(d) < abs(best[1]):
            best = (x, d)
    return best


def groups_of(text: str, live: list) -> list[list[int]]:
    """区切り（, 、 ・ と 空白）だけで並んだ参照（「（a.js:43, b.js:12）」）を1組にする。
    組の参照のどれかの近傍に識別子があればよい（列挙した場所のどこかを述べる文のため）"""
    order = sorted(range(len(live)), key=lambda k: live[k][0]["span"][0])
    out: list[list[int]] = []
    for k in order:
        if out:
            prev = live[out[-1][-1]][0]["span"][1]
            if re.fullmatch(r"[\s,、・と]*", text[prev : live[k][0]["span"][0]]):
                out[-1].append(k)
                continue
        out.append([k])
    return out


def check(
    report_text: str,
    repo: Repo,
    section="5",
    window=3,
    search=30,
    extra: Repo | None = None,
) -> dict:
    """extra は修正後のツリー（--extra-root）。修正案の部分の参照は、repo と extra の
    どちらかで成り立てばよい（修正で新設するファイル・修正後の行番号を述べるため）"""
    res = {"ng": [], "warn": [], "near": [], "skip": [], "n": 0, "res": 0}
    res.update({"amb": 0, "chk": 0, "units": 0, "unres": {}, "special": {}})
    heads = [ln for _, ln in fence_lines(report_text) if ln.startswith("## ")]
    res["section"] = any(re.match(rf"## {re.escape(section)}\.", h) for h in heads)
    for no, rl, text, fix in units(report_text, section):
        refs = find_refs(text)
        if not refs:
            continue
        res["units"] += 1
        trees = [repo] + ([extra] if extra is not None and fix else [])
        live = []
        for r in refs:
            where = f"{no} L{rl}: {r['raw']}"
            base = r["path"].rsplit("/", 1)[-1]
            top = r["path"].lstrip("./").split("/", 1)[0]
            if "/" not in r["path"] and "." not in base:
                if not any(base in t.names for t in trees):
                    continue  # 拡張子の無い語（localhost:3000 等）は参照にしない
            res["n"] += 1
            cands = [(t, c) for t in trees for c in t.resolve(r["path"])]
            if not cands:
                if r["path"].lower() in PRODUCTS or top in DEP_DIRS:
                    res["skip"].append(f"{where}（製品名・依存の内部として対象外）")
                elif any(t.resolve(r["path"], t.unsafe) for t in trees):
                    res["special"].setdefault(r["path"], []).append(f"{no} L{rl}")
                elif repo.in_deps(r["path"]):
                    res["skip"].append(f"{where}（依存の内部として対象外）")
                elif repo.own_dir(r["path"]):
                    res["ng"].append(f"{where} のファイルがリポジトリに無い")
                else:
                    res["unres"].setdefault(r["path"], []).append(f"{no} L{rl}")
                continue
            res["res"] += 1
            res["amb"] += len(cands) > 1
            known = [len(ls) for ls in (t.lines(c) for t, c in cands) if ls is not None]
            bad = []
            for a, b in r["ranges"]:
                if a < 1 or b < a:
                    bad.append(f"範囲{a}-{b}が不正（1以上・開始<=終了）")
                elif known and all(b > n for n in known):  # 読めないファイルは調べない
                    bad.append(f"行{b}がファイルの行数{max(known)}を超える")
            if bad:
                names = ", ".join(c for _, c in cands)
                res["ng"].append(f"{where}: {'、'.join(bad)}（{names}）")
                continue
            live.append((r, cands))
        if not live:
            continue
        bound: dict[int, set[str]] = {}
        cuts = clauses(text, refs)

        def part(pos):  # 何番目の節か
            return sum(c < pos for c in cuts)

        for ident, pos, weak in find_idents(text, refs):
            best, who = None, []
            for k, (r, cands) in enumerate(live):
                if DOC_RE.search(r["path"]):
                    continue  # 文書（README等）の行は識別子で照合しない
                if part(r["span"][0]) != part(pos):
                    continue  # 同じ節の参照にだけ割り当てる
                if weak and not any(MANIFEST_RE.search(c) for _, c in cands):
                    continue
                if not any(t.occ(c, ident) for t, c in cands):
                    continue
                a, b = r["span"]
                d = 0 if a <= pos < b else min(abs(pos - a), abs(pos - b))
                if best is None or d < best:
                    best, who = d, [k]
                elif d == best:
                    who.append(k)
            for k in who:
                bound.setdefault(k, set()).add(ident)
        for grp in groups_of(text, live):
            ids = sorted(set().union(*(bound.get(k, set()) for k in grp)))
            if not ids:
                continue
            res["chk"] += 1
            raw = ", ".join(live[k][0]["raw"] for k in grp)
            where = f"{no} L{rl}: {raw}"
            hits, inside, best = False, False, None
            for k in grp:
                r, cands = live[k]
                for t, c in cands:
                    for ident in ids:
                        occ = t.occ(c, ident)
                        ls = t.lines(c) or []
                        for a, b in r["ranges"]:
                            nb = near(occ, a, b)
                            if nb is None:
                                continue
                            hits |= abs(nb[1]) <= window
                            # 関数等の定義が範囲の上（--search 行以内）にあり、範囲がその本体
                            hits |= any(
                                a - search <= x < a and defines(ls[x - 1], ident)
                                for x in occ
                            )
                            inside |= nb[1] == 0
                            if best is None or abs(nb[1]) < abs(best[2]):
                                best = (ident, nb[0], nb[1], c)
            if not hits:
                ident, ln, d, c = best
                paths = {live[k][0]["path"] for k in grp}
                where_c = f"（{c}）" if c not in paths else ""
                if abs(d) <= search:
                    hint = f"最寄り: `{ident}` L{ln}（{d:+d}行）"
                else:
                    hint = (
                        f"±{search}行以内に無い（ファイル内の最寄り: `{ident}` L{ln}）"
                    )
                names = "・".join(f"`{x}`" for x in ids[:4])
                more = f"ほか{len(ids) - 4}語" if len(ids) > 4 else ""
                res["warn"].append(
                    f"{where} の前後{window}行に{names}{more}が無い{where_c}。{hint}"
                )
            elif not inside:
                ident, ln, d, _ = best
                res["near"].append(f"{where}: `{ident}` L{ln}（{d:+d}行）")
    return res


def run(
    report: str,
    repo_dir: str,
    section="5",
    window=3,
    search=30,
    verbose=False,
    extra_dir=None,
):
    try:
        with open(report, "rb") as f:
            text = f.read().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        print(f"ERROR: 報告書を読めない: {e}")
        print("RESULT: ERROR")
        return 2
    if not os.path.isdir(repo_dir):
        print(f"ERROR: --repo がディレクトリでない: {repo_dir}")
        print("RESULT: ERROR")
        return 2
    if extra_dir is not None and not os.path.isdir(extra_dir):
        print(f"ERROR: --extra-root がディレクトリでない: {extra_dir}")
        print("RESULT: ERROR")
        return 2
    extra = Repo(extra_dir) if extra_dir is not None else None
    r = check(text, Repo(repo_dir), section, window, search, extra)
    if not r["section"]:
        print(
            f"ERROR: 報告書に「## {section}.」の節（「### {section}.N」の指摘）が無い"
        )
        print("RESULT: ERROR")
        return 2
    for x in r["ng"]:
        print("NG:", x)
    for x in r["warn"]:
        print("WARN:", x)
    for path, at in r["unres"].items():
        print(
            f"WARN: 未解決: {path} がリポジトリにも依存の置き場所にも無い（{len(at)}箇所: "
            f"{', '.join(at[:3])}{' ほか' if len(at) > 3 else ''}）。"
            "依存の内部なら依存を導入した対象で再実行し、ファイル名の誤りなら直す"
        )
    for path, at in r["special"].items():
        print(
            f"WARN: 未解決: {path} は通常ファイルでないか、リポジトリの外へのリンクのため"
            f"読まない（{len(at)}箇所: {', '.join(at[:3])}{' ほか' if len(at) > 3 else ''}）"
        )
    if verbose:
        for x in r["near"]:
            print("INFO: 近接:", x)
        for x in r["skip"]:
            print("INFO: 対象外:", x)
    pct = f"{100 * len(r['warn']) / r['chk']:.1f}%" if r["chk"] else "-"
    print(
        f"参照{r['n']}件（解決{r['res']}・うち候補が複数{r['amb']}・対象外{len(r['skip'])}・"
        f"未解決{sum(map(len, [*r['unres'].values(), *r['special'].values()]))}）、"
        f"識別子で照合{r['chk']}件のうちWARN {len(r['warn'])}件（{pct}）、"
        f"近接{len(r['near'])}件（範囲外だが前後{window}行以内。--verboseで一覧）"
    )
    if r["ng"]:
        print(f"RESULT: NG ({len(r['ng'])}件)")
        return 1
    print("RESULT: OK")
    return 0


# ---- 自己テスト ----
def self_test() -> int:
    """自己検査の本体は scripts/selftests/st_check_refs.py（本体の読込を減らすため分けた）。"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "selftests"))
    import st_check_refs

    return st_check_refs._st_entry(globals())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="報告書の指摘本文の「ファイル:行」参照を対象リポジトリと照合する"
    )
    ap.add_argument("--report", help="報告書（Markdown）")
    ap.add_argument("--repo", help="対象リポジトリのディレクトリ")
    ap.add_argument(
        "--extra-root",
        help="修正後のツリー。修正案の部分の参照は、--repo とこれのどちらかで成り立てばよい",
    )
    ap.add_argument("--section", default="5", help="照合する節の番号（既定 5）")
    ap.add_argument("--window", type=int, default=3, help="近傍とみなす前後の行数")
    ap.add_argument("--search", type=int, default=30, help="最寄りの行を示す範囲")
    ap.add_argument("--verbose", action="store_true", help="近接・対象外の一覧も出す")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.report and a.repo):
        print("ERROR: --report と --repo が必要")
        print("RESULT: ERROR")
        return 2
    return run(a.report, a.repo, a.section, a.window, a.search, a.verbose, a.extra_root)


if __name__ == "__main__":
    sys.exit(main())
