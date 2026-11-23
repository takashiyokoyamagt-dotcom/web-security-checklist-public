#!/usr/bin/env python3
"""Redが引用した断片を実ファイルから探し、実ファイルの行番号を返す（標準ライブラリのみ）。
WRITERに渡す「該当コード」（file・start_line・end_line・code）の start_line が、断片の省略・
抜粋で実ファイルとずれる事例（docs/HISTORY.md 43・45節）への対応。Arbiterが5dの入力を作るとき、Redの
file_lineをそのまま使わずに、この結果の行番号にする（references/pipeline/finding-final.md 5d）。

使い方:
  locate_snippet.py --repo <対象ディレクトリ> --file <repoからの相対パス> --code-file <断片テキスト>
                    [--hint-start N]
  locate_snippet.py --self-test
出力（JSON1行。標準出力）:
  {"file":..., "matched":true|false, "contiguous":true|false,
   "chunks":[{"start":N,"end":M},...], "start_line":N, "end_line":M,
   "candidates":K, ...}
  matched=false のときは chunks=[]、reason に理由、断片の一部だけが見つかったときは
  unmatched_chunks（見つからなかったチャンクの番号。1始まり）と partial_chunks（単独で見つかったもの）を付ける。
  unmatched_detail は、見つからなかったチャンクごとに、行数（lines）、実ファイルのどこかに同じ行がある行数
  （present）、実ファイルで連続して一致する最長の部分（longest_run。無ければnull）を示す。present が
  lines と同じで longest_run が短ければ、Redが省略記号なしに行を落とした／並べ替えた断片、present が少なければ、
  Redの注記・他ファイルの断片が混ざった、または要約的な書き換えで原文にない断片である（どれも
  WRITERに実ファイルの行番号で書き直させる対象）。
断片の扱い:
  - 「...」「…」だけの行、またはその前後にコメント記号・括弧が付いた行（`// ...`・`# ...`・`/* ... */`・
    `<!-- ... -->`・`[...]`・`(...)`）は省略行とし、そこで断片を複数のチャンクに分ける。
    断片の先頭・末尾の省略行は無視する。コードの行の途中の `...`（スプレッド等）は省略行ではない。
  - 各チャンクは、前後のインデント・連続する空白（タブ含む）の違いと空行を無視して、実ファイルの
    連続した行（間に空行があってもよい）に一致するものを探す。大文字小文字・文字の違いは無視しない。
  - チャンクは断片の順に、前のチャンクの後ろで見つける。複数箇所に一致するときは、--hint-start（Redの
    file_line。断片の途中の行を指すことがある）の行を範囲に含むもの、無ければ範囲の端が最も近いもの
    （同じなら先頭が近いもの）の組を選ぶ。--hint-start が無ければ範囲が最も狭いもの（同じなら先頭に
    近いもの）。candidates に一致した組の数を出す。
  - contiguous は、チャンクが1つ、またはチャンクの間に空行以外の行が無いとき true。
    false のときは断片が実ファイルの離れた箇所を省略記号でつないだもので、start_line〜end_line は
    その全体を含む範囲である（報告書の「ファイル」行と「該当コード」の見出しはこの範囲に合わせる）。
  - repo の外を指す --file（.. や絶対パス、シンボリックリンクを含む）は読まない（エラー）。
  - 行は改行（\\n。CRLFの\\rは除く）だけで分け、\\x0c・U+2028等では割らない。UTF-8のBOMは除く。
  - 一致した組が10000を超える（`}`だけの断片など）ときは matched=false（理由「候補が多すぎる」）。
終了コード 0=一致 / 1=一致なし（matched=false。断片が要約的な書き換えで原文にない等）/
  2=入力不正（ファイルを読めない、断片が空、repoの外、引数の不足）。入力不正のときも標準出力に
  {"matched":false,"chunks":[],"error":...} を出す（argparse が拒む未知のオプション・--hint-start
  の非整数だけは、標準エラーに使い方を出して終了コード2で、標準出力は空）。Python 3.9以上で動く。"""

from __future__ import annotations

import argparse
import bisect
import contextlib
import io
import json
import os
import re
import sys
import tempfile

MAX_BYTES = 5_000_000  # 読むファイルの上限（巨大な生成物で止まらないように）
MAX_CANDIDATES = (
    10000  # 一致した組の数の上限（超えたら matched=false。頻出行だけの断片）
)
# 省略行: 記号・括弧に囲まれた「...」または「…」だけの行
OMIT_RE = re.compile(
    r"^(?:(?://+|#+|--+|;+|\*+|/\*+|<!--|\[|\()\s*)?"
    r"(?:\.\.\.|…)"
    r"(?:\s*(?:\*+/|-->|\]|\)))?$"
)


class TooMany(Exception):
    """一致した組が MAX_CANDIDATES を超えた"""


def split_lines(text: str) -> list[str]:
    r"""行に分ける。区切りは改行（\n。CRLFは行末の\rを除く）だけで、\x0b・\x0c・\x1c-\x1e・
    \x85・U+2028・U+2029では割らない（エディタや git の行番号と合わせるため）"""
    return [ln.removesuffix("\r") for ln in text.split("\n")]


def norm(line: str) -> str:
    """比較用の正規化: 前後の空白を除き、連続する空白（タブ含む）を1つのスペースにする"""
    return re.sub(r"\s+", " ", line.strip())


def is_omit(line: str) -> bool:
    return bool(OMIT_RE.match(line.strip()))


def split_chunks(code: str) -> list[list[str]]:
    """断片を省略行で区切り、空行を除いた正規化済みの行のチャンクの列にする。
    空のチャンク（連続する省略行、先頭・末尾の省略行）は捨てる"""
    chunks: list[list[str]] = [[]]
    for raw in split_lines(code):
        if is_omit(raw):
            chunks.append([])
        elif raw.strip():
            chunks[-1].append(norm(raw))
    return [c for c in chunks if c]


def index_lines(nonblank: list[tuple[int, str]]) -> dict[str, list[int]]:
    """正規化した行 → nonblank 内の添字の昇順リスト"""
    pos: dict[str, list[int]] = {}
    for k, (_, text) in enumerate(nonblank):
        pos.setdefault(text, []).append(k)
    return pos


def chunk_matches(nonblank, pos, chunk) -> list[int]:
    """chunk が連続して一致する位置（nonblank 内の先頭の添字）の昇順リスト"""
    m, n = len(chunk), len(nonblank)
    out = []
    for i in pos.get(chunk[0], ()):
        if i + m > n:
            break
        if all(nonblank[i + k][1] == chunk[k] for k in range(1, m)):
            out.append(i)
    return out


def placements(nonblank, chunks, matches):
    """全チャンクを順に置ける組（各チャンクの(先頭行, 末尾行)の列）を全て列挙する。
    matches[c] は chunk_matches の結果。先頭チャンクの候補ごとに、後続のチャンクは
    前のチャンクの末尾より後ろの最初の一致に置く（重ならない）。
    組が MAX_CANDIDATES を超えたら TooMany"""
    out = []
    for i0 in matches[0]:
        placed = [i0]
        for c in range(1, len(chunks)):
            prev_end = placed[-1] + len(chunks[c - 1]) - 1
            k = bisect.bisect_right(matches[c], prev_end)
            if k == len(matches[c]):
                placed = None
                break
            placed.append(matches[c][k])
        if placed is not None:
            out.append(placed)
            if len(out) > MAX_CANDIDATES:
                raise TooMany()
    return [
        [(nonblank[i][0], nonblank[i + len(chunks[c]) - 1][0]) for c, i in enumerate(p)]
        for p in out
    ]


def longest_run(nonblank, pos, chunk):
    """チャンクの連続した部分で、実ファイルに連続して一致する最長のもの。
    {"lines":k,"start":N,"end":M}（実ファイルの行番号）。1行も無ければ None"""
    best = (0, 0)  # (長さ, 実ファイル側の末尾の添字)
    prev: dict[int, int] = {}
    for line in chunk:
        cur: dict[int, int] = {}
        for j in pos.get(line, ()):
            cur[j] = prev.get(j - 1, 0) + 1
            if cur[j] > best[0]:
                best = (cur[j], j)
        prev = cur
    k, j = best
    if not k:
        return None
    return {"lines": k, "start": nonblank[j - k + 1][0], "end": nonblank[j][0]}


def locate(lines: list[str], code: str, hint=None) -> dict:
    """ファイルの行の列と断片から結果の辞書を返す（ファイル名なし）"""
    chunks = split_chunks(code)
    if not chunks:
        return {"matched": False, "chunks": [], "reason": "断片に比較できる行がない"}
    nonblank = [(i, norm(s)) for i, s in enumerate(lines, 1) if s.strip()]
    pos = index_lines(nonblank)
    matches = [chunk_matches(nonblank, pos, ch) for ch in chunks]
    try:
        found = placements(nonblank, chunks, matches) if all(matches) else []
    except TooMany:
        return {
            "matched": False,
            "chunks": [],
            "reason": f"候補が多すぎる（一致が{MAX_CANDIDATES}組を超える）",
        }
    if not found:
        res = {
            "matched": False,
            "chunks": [],
            "reason": "断片が実ファイルに連続して一致しない",
        }
        part = []
        for idx, hits in enumerate(matches, 1):
            if hits:
                i = hits[0]
                part.append(
                    {
                        "chunk": idx,
                        "start": nonblank[i][0],
                        "end": nonblank[i + len(chunks[idx - 1]) - 1][0],
                    }
                )
        missing = [i for i in range(1, len(chunks) + 1) if not matches[i - 1]]
        if missing:
            res["unmatched_chunks"] = missing
            res["unmatched_detail"] = [
                {
                    "chunk": i,
                    "lines": len(chunks[i - 1]),
                    "present": sum(1 for t in chunks[i - 1] if t in pos),
                    "longest_run": longest_run(nonblank, pos, chunks[i - 1]),
                }
                for i in missing
            ]
        if part:
            res["partial_chunks"] = part
            if not missing:
                res["reason"] = "各チャンクは見つかるが、断片の順に並ぶ組がない"
        return res
    if hint is None:
        best = min(found, key=lambda p: (p[-1][1] - p[0][0], p[0][0]))
    else:

        def dist(p):  # ヒントを含む範囲は0、含まなければ範囲の端までの距離
            a, b = p[0][0], p[-1][1]
            return 0 if a <= hint <= b else min(abs(a - hint), abs(b - hint))

        best = min(found, key=lambda p: (dist(p), abs(p[0][0] - hint), p[0][0]))
    text = [s.strip() for s in lines]
    contig = all(
        not any(text[k - 1] for k in range(best[i][1] + 1, best[i + 1][0]))
        for i in range(len(best) - 1)
    )
    return {
        "matched": True,
        "contiguous": contig,
        "chunks": [{"start": a, "end": b} for a, b in best],
        "start_line": best[0][0],
        "end_line": best[-1][1],
        "candidates": len(found),
    }


def read_target(repo: str, rel: str) -> list[str]:
    """repo 内のファイルを読む。repoの外・読めない・大きすぎるときは ValueError。
    BOM（UTF-8）は除き、行は split_lines で分ける"""
    root = os.path.realpath(repo)
    if not os.path.isdir(root):
        raise ValueError(f"--repo がディレクトリでない: {repo}")
    path = os.path.realpath(os.path.join(root, rel))
    if os.path.commonpath([root, path]) != root:
        raise ValueError(f"--file が repo の外を指す: {rel}")
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise ValueError(f"ファイルが大きすぎる（{MAX_BYTES}B超）: {rel}")
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ValueError(f"--file を読めない: {rel} ({e.strerror or e})") from None
    return split_lines(raw.decode("utf-8-sig", errors="replace"))


def run(repo, rel, code_file, hint) -> tuple[int, dict]:
    try:
        lines = read_target(repo, rel)
        with open(code_file, "rb") as f:
            code = f.read().decode("utf-8-sig", errors="replace")
    except (ValueError, OSError) as e:
        return 2, {"file": rel, "matched": False, "chunks": [], "error": str(e)}
    if not split_chunks(code):
        return 2, {
            "file": rel,
            "matched": False,
            "chunks": [],
            "error": "断片に比較できる行がない",
        }
    res = locate(lines, code, hint)
    out = {"file": rel}
    out.update(res)
    if hint is not None:
        out["hint_start"] = hint
    return (0 if res["matched"] else 1), out


# ---- 自己テスト ----
SAMPLE = """\
'use strict';

function a(x) {
\tif (x) {
\t\treturn 1;
\t}
\treturn 0;
}

function b(q) {
  if (!q) {
    return null;
  }
  const r = db.find({ name: q.name });
  // 後処理
  log(r);
  return r;
}

function c(x) {
  if (x) {
    return 1;
  }
  return 0;
}
"""


def _case(tmp, name, code, hint=None, rel="s.js"):
    cf = os.path.join(tmp, name + ".txt")
    with open(cf, "w", encoding="utf-8") as f:
        f.write(code)
    return run(tmp, rel, cf, hint)


def self_test() -> int:
    fails: list[str] = []

    def check(label, cond):
        if not cond:
            fails.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "s.js"), "w", encoding="utf-8") as f:
            f.write(SAMPLE)
        # 1. 正常系: 単一チャンク
        rc, r = _case(
            tmp, "t1", "function b(q) {\n  if (!q) {\n    return null;\n  }\n"
        )
        check("単一チャンク", rc == 0 and r["chunks"] == [{"start": 10, "end": 13}])
        check("単一はcontiguous", r.get("contiguous") is True and r["start_line"] == 10)
        # 2. インデント違い（タブ・連続空白・先頭の空白なし）
        rc, r = _case(tmp, "t2", "if   (x)  {\nreturn   1;\n}\nreturn 0;\n", hint=3)
        check("インデント違い", rc == 0 and r["chunks"] == [{"start": 4, "end": 7}])
        # 3. 省略行を含む断片（...・// ...）で離れた箇所をつなぐ
        code = "const r = db.find({ name: q.name });\n// ...\nreturn r;\n"
        rc, r = _case(tmp, "t3", code)
        check(
            "省略行",
            rc == 0
            and r["chunks"] == [{"start": 14, "end": 14}, {"start": 17, "end": 17}]
            and r["contiguous"] is False
            and (r["start_line"], r["end_line"]) == (14, 17),
        )
        for mark in ("...", "…", "/* ... */", "# ...", "<!-- ... -->", "[...]"):
            rc, r = _case(tmp, "t3b", f"log(r);\n{mark}\n}}\n")
            check("省略行の書式 " + mark, rc == 0 and len(r["chunks"]) == 2)
        # 先頭・末尾の省略行は無視され、行の途中の ... は省略行にならない
        rc, r = _case(tmp, "t3c", "...\nlog(r);\n// ...\n")
        check("先頭末尾の省略行", rc == 0 and r["chunks"] == [{"start": 16, "end": 16}])
        rc, r = _case(tmp, "t3d", "f(...args);\n")
        check("行内の...は本文", rc == 1 and r["matched"] is False)
        # 4. 複数箇所に一致: hintに近い方を選ぶ。hintなしは範囲が最も狭い（同じなら先頭に近い）もの
        code = "if (x) {\nreturn 1;\n}\n"
        rc, r = _case(tmp, "t4a", code, hint=21)
        check(
            "複数一致hint後ろ",
            rc == 0 and r["start_line"] == 21 and r["candidates"] == 2,
        )
        rc, r = _case(tmp, "t4b", code, hint=1)
        check("複数一致hint前", rc == 0 and r["start_line"] == 4)
        rc, r = _case(tmp, "t4c", code)
        check("複数一致hintなし", rc == 0 and r["start_line"] == 4)
        # 4d. ヒントを含む範囲を優先（先頭の距離だけで選ぶと隣の一致になる）
        with open(os.path.join(tmp, "r.txt"), "w", encoding="utf-8") as f:
            f.write("a\nb\nc\n" * 3)
        rc, r = _case(tmp, "t4d", "a\nb\nc\n", hint=6, rel="r.txt")
        check(
            "ヒントを含む範囲",
            rc == 0 and r["start_line"] == 4 and r["candidates"] == 3,
        )
        # 5. 不一致（要約的な書き換え・一部のチャンクだけ一致・順序違い）
        rc, r = _case(tmp, "t5a", "const result = database.lookup(q.name);\n")
        check("不一致", rc == 1 and r["matched"] is False and r["chunks"] == [])
        rc, r = _case(tmp, "t5b", "log(r);\n...\nnot in file();\n")
        check(
            "一部のチャンクだけ一致",
            rc == 1
            and r.get("unmatched_chunks") == [2]
            and r["partial_chunks"][0]["start"] == 16,
        )
        d = r.get("unmatched_detail", [{}])[0]
        check("t5b detail", d.get("present") == 0 and d.get("longest_run") is None)
        rc, r = _case(tmp, "t5d", "log(r);\nreturn r;\n// Redの注記\n")
        d = r.get("unmatched_detail", [{}])[0]
        check(
            "注記の混入",
            rc == 1
            and (d.get("lines"), d.get("present")) == (3, 2)
            and d.get("longest_run") == {"lines": 2, "start": 16, "end": 17},
        )
        rc, r = _case(tmp, "t5c", "return r;\n...\nlog(r);\n")
        check("順序違い", rc == 1 and "順" in r["reason"])
        # 6. 空行は断片側・実ファイル側とも無視（空行をまたぐ連続）
        rc, r = _case(tmp, "t6", "}\nfunction b(q) {\n")
        check("空行をまたぐ", rc == 0 and r["chunks"] == [{"start": 8, "end": 10}])
        # 7. 入力不正
        rc, r = _case(tmp, "t7a", "log(r);\n", rel="none.js")
        check("ファイルなし", rc == 2 and "error" in r)
        rc, r = _case(tmp, "t7b", "// ...\n\n")
        check("空の断片", rc == 2 and "比較できる行" in r["error"])
        outside = tempfile.mkdtemp(prefix="locate-out-")
        try:
            with open(os.path.join(outside, "o.js"), "w", encoding="utf-8") as f:
                f.write("log(r);\n")
            up = os.path.join("..", os.path.basename(outside), "o.js")
            rc, r = _case(tmp, "t7c", "log(r);\n", rel=up)
            check("repoの外(..)", rc == 2 and "repo の外" in r["error"])
            try:
                os.symlink(os.path.join(outside, "o.js"), os.path.join(tmp, "ln.js"))
                rc, r = _case(tmp, "t7d", "log(r);\n", rel="ln.js")
                check("repoの外(symlink)", rc == 2 and "repo の外" in r["error"])
            except OSError:
                pass  # シンボリックリンクを作れない環境では省略
            rc, r = _case(tmp, "t7e", "log(r);\n", rel=os.path.join(outside, "o.js"))
            check("repoの外(絶対パス)", rc == 2 and "repo の外" in r["error"])
        finally:
            for name in os.listdir(outside):
                os.remove(os.path.join(outside, name))
            os.rmdir(outside)
        # 8. CLI（終了コードと標準出力のJSON）
        cf = os.path.join(tmp, "cli.txt")
        with open(cf, "w", encoding="utf-8") as f:
            f.write("log(r);\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(
                [
                    "--repo",
                    tmp,
                    "--file",
                    "s.js",
                    "--code-file",
                    cf,
                    "--hint-start",
                    "5",
                ]
            )
        try:
            j = json.loads(buf.getvalue())
        except ValueError:
            j = {}
        check(
            "CLI一致",
            rc == 0 and j.get("start_line") == 16 and j.get("hint_start") == 5,
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = main(["--repo", tmp, "--file", "s.js"])
        try:
            j = json.loads(buf.getvalue())
        except ValueError:
            j = {}
        check("CLI引数不足", rc == 2 and j.get("matched") is False and "error" in j)

        # 9. 行の分け方とBOM（改行以外の区切り文字で割らない）
        def put(name, data):
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)

        put("bom.js", b"\xef\xbb\xbflog(r);\nnext();\n")
        rc, r = _case(tmp, "t9a", "log(r);\n", rel="bom.js")
        check("BOM付き1行目", rc == 0 and r["start_line"] == 1)
        put("ff1.js", b"a\n\x0c\nb\nc\nd")
        rc, r = _case(tmp, "t9b", "c\n", rel="ff1.js")
        check("単独の\\f行", rc == 0 and r["start_line"] == 4)
        put("ff2.js", b"a\nx\x0cy\nc\nd")
        rc, r = _case(tmp, "t9c", "c\n", rel="ff2.js")
        check("行内の\\f", rc == 0 and r["start_line"] == 3)
        put("ls.js", "a\nx\u2028y\nc\n".encode("utf-8"))
        rc, r = _case(tmp, "t9d", "c\n", rel="ls.js")
        check("行内のU+2028", rc == 0 and r["start_line"] == 3)
        put("fs.js", b"a\nx\x1cy\x85z\nc\n")
        rc, r = _case(tmp, "t9e", "c\n", rel="fs.js")
        check("行内の\\x1c・\\x85", rc == 0 and r["start_line"] == 3)
        put("crlf.js", b"a\r\nb\r\nc\r\n")
        rc, r = _case(tmp, "t9f", "b\r\nc\r\n", rel="crlf.js")
        check("CRLF", rc == 0 and r["chunks"] == [{"start": 2, "end": 3}])
        # 10. 変異の検出: ヒントなしは範囲が最小の組（最初の候補ではない）
        put("sp.js", b"a\nx\nx\nx\nb\na\nb\n")
        rc, r = _case(tmp, "t10a", "a\n...\nb\n", rel="sp.js")
        check("範囲最小の組", rc == 0 and r["start_line"] == 6 and r["candidates"] == 2)
        # チャンクは重ならない（同じ行を2つのチャンクに使わない）
        put("ov.js", b"a\nb\n")
        rc, r = _case(tmp, "t10b", "a\n...\na\n", rel="ov.js")
        check("チャンクの重なり", rc == 1 and r["matched"] is False)
        # サイズ上限・候補数の上限（モジュールの値を一時的に小さくする）
        g = globals()
        old = (g["MAX_BYTES"], g["MAX_CANDIDATES"])
        try:
            g["MAX_BYTES"] = 50
            rc, r = _case(tmp, "t10c", "log(r);\n")
            check("サイズ上限", rc == 2 and "大きすぎる" in r["error"])
            g["MAX_BYTES"] = old[0]
            g["MAX_CANDIDATES"] = 2
            rc, r = _case(tmp, "t10d", "a\nb\nc\n", rel="r.txt")
            check("候補数の上限", rc == 1 and "多すぎる" in r["reason"])
        finally:
            g["MAX_BYTES"], g["MAX_CANDIDATES"] = old
    if fails:
        print("self-test NG: " + ", ".join(fails))
        return 1
    print("self-test OK (正常系 + 省略行・複数一致・不一致・インデント違い・入力不正)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Redの断片を実ファイルから探し、実ファイルの行番号をJSONで返す"
    )
    ap.add_argument("--repo", help="対象のディレクトリ")
    ap.add_argument("--file", help="repoからの相対パス")
    ap.add_argument("--code-file", help="断片のテキストファイル")
    ap.add_argument(
        "--hint-start", type=int, help="複数一致のときに近いものを選ぶ行番号"
    )
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.repo and a.file and a.code_file):
        msg = "--repo・--file・--code-file が必要"
        print(msg, file=sys.stderr)
        print(
            json.dumps(
                {"matched": False, "chunks": [], "error": msg}, ensure_ascii=False
            )
        )
        return 2
    rc, out = run(a.repo, a.file, a.code_file, a.hint_start)
    print(json.dumps(out, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())
