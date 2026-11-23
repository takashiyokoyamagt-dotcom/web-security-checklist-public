#!/usr/bin/env python3
"""5cの機械判定。修正案のdiffから近接するhunkのペアと連結成分を求め、5c補足3を使うかを決める。

Usage:
  python3 check_5c_components.py --members members.json --target TARGET_DIR DIFFS.jsonl [DIFFS.jsonl ...]
         [--strip-hyphen] [--json OUT.json]
  python3 check_5c_components.py --self-test

入力:
- members.json: 5b後の項目（群と単独項目）ごとの構成一時ID。例 {"F1": ["I3", "U1"], "F2": ["R0104"]}
  （finding-arbiter.md 5b補足2の`members.json`と同じ）。
- DIFFS.jsonl: 1指摘＝JSON1行。一時IDは`tmp_id`・`tmp`・`n`・`id`のどれか、diffは`diff`・
  `fix_suggestion_check.diff`・文字列の`fix_suggestion_check`内のdiff（最初の`--- `か`@@`の行から後）・
  `fix_suggestion`（文字列）の順で最初にあるもの、位置のヒントは
  `corrected_file_line`・`file_line`。BLUEの出力（`out/blue-NN.jsonl`）や`findings-log.jsonl`をそのまま渡せる。
  JSONとして読めない行は無視する。同じ一時IDが複数の行にあれば、後の行を使う。
  --strip-hyphenで一時IDのハイフンを除いて members と照合する。
- --target: 監査対象のディレクトリ。`@@`の無いdiff断片（finding-pipeline.md 手順3で認める形）の位置を、
  `locate_snippet.py`と同じ方法で対象のファイルから求めるのに使う。

判定（finding-arbiter.md 5c・5c補足3）:
- 位置: `@@`付きのhunkは、変更行（削除行の旧行番号。削除を伴わない追加行は挿入位置の前後の旧行）の
  最小〜最大をhunkの範囲とする。新規ファイル（`/dev/null`）は行0。`@@`の無い断片は、旧側（文脈行と
  `-`行）を、ファイル見出し（`--- a/…`）か位置のヒントの最初のファイルで探し、旧側が連続して見つかれば
  変更行の位置、飛び飛びなら見つかった範囲全体とする。見つからないとき・旧側が無いとき（全行`+`）は、
  位置のヒントの行範囲を使う（`unlocated`に表示）。ファイル名は`a/`・`b/`・`./`を除いて比べる。
- ペア: 別の項目の、同じファイルの範囲どうしで、重なるか、間が3行以内（差が4以下）のもの。
- 連結成分: ペアでつながる項目の集まり。diffの無い項目は1件の成分とする。
- DECISION: 最大の連結成分の項目数が全項目数の過半なら`synth`（5c補足3: 群ごとにSYNTHへ委任）、
  そうでなければ`sequential`（5c(a)〜(c)の逐次合成。ペアの無い項目は個別提示）。
  判断を挟まない。Arbiterはこの出力に従い、`synth`のときは報告書9節に規定の手順として書く。

BLUEの確定diffは`@@`付きが必須（finding-pipeline.md 手順3）。`@@`の無いdiffの一時IDはWARNで列挙する
（判定は上の方法で続ける）。
出力: ペア一覧、連結成分、`DECISION:`の行。rc0=判定完了、rc2=入力エラー。membersに無い一時IDのdiffは
WARNとして表示し判定に含めない。membersの一時IDに1つもdiffが合わないときもWARN。
Stdlib only, Python 3.9+.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import locate_snippet  # noqa: E402

NEAR = 3
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
FILE_LINE = re.compile(r"([\w./\\-]+\.[A-Za-z0-9]+):(\d+)(?:\s*-\s*(\d+))?")


def clean_path(p):
    p = p.strip().split("\t")[0]
    for pre in ("a/", "b/"):
        if p.startswith(pre):
            p = p[len(pre):]
    while p.startswith("./"):
        p = p[2:]
    return p.replace("\\", "/")


def strip_fence(diff):
    """Keep the inside of the first ``` fence when the diff is fenced (notes after it are dropped)."""
    lines = diff.split("\n")
    opens = [i for i, l in enumerate(lines) if l.strip().startswith("```")]
    if opens:
        start = opens[0] + 1
        end = next((i for i in opens[1:]), len(lines))
        return lines[start:end]
    return lines


def parse_hint(file_line):
    """'routes/a.js:8-18 , db.js:24' -> [('routes/a.js', 8, 18), ('db.js', 24, 24)]"""
    out = []
    for m in FILE_LINE.finditer(file_line or ""):
        lo = int(m.group(2))
        out.append((clean_path(m.group(1)), lo, int(m.group(3) or lo)))
    return out


def split_files(lines):
    """Split diff lines into [(path or None, [lines])] by '--- ' headers."""
    parts, path, cur = [], None, []
    for line in lines:
        if line.startswith("--- "):
            if cur:
                parts.append((path, cur))
            path, cur = line[4:], []
            continue
        if line.startswith("+++ "):
            if path is None or clean_path(path) == "/dev/null":
                path = line[4:]
            continue
        cur.append(line)
    if cur:
        parts.append((path, cur))
    return [(clean_path(p) if p else None, ls) for p, ls in parts]


def header_ranges(path, lines):
    out, cur, old_ln, prev = [], None, 0, ""

    def touch(a, b):
        cur[1] = a if cur[1] is None else min(cur[1], a)
        cur[2] = b if cur[2] is None else max(cur[2], b)

    for line in lines:
        m = HUNK.match(line)
        if m:
            if cur and cur[1] is not None:
                out.append(tuple(cur))
            cur, old_ln, prev = [path or "?", None, None], int(m.group(1)), ""
            continue
        if cur is None:
            continue
        if line.startswith("-"):
            touch(old_ln, old_ln)
            old_ln += 1
        elif line.startswith("+"):
            if not prev.startswith(("-", "+")):  # pure insertion: between the previous and next old line
                touch(max(old_ln - 1, 0), old_ln)
        elif line.startswith("\\"):
            continue
        else:
            old_ln += 1
        prev = line
    if cur and cur[1] is not None:
        out.append(tuple(cur))
    return out


def _norm(s):
    """Strip spaces and a trailing // comment (fragments often drop comments)."""
    s = s.strip()
    i = s.find(" //")
    return (s[:i] if i >= 0 else s).rstrip() if not s.startswith("//") else s


def anchor_lines(flines, old, hint):
    """Fallback when the old side is not contiguous in the file (omitted comment lines etc.).
    Map each old-side line to a file line in order: the first to the match nearest the hint,
    each next one to the first match within 10 lines after the previous. Returns {old_index: line}
    when at least half of the non-blank old lines are mapped, else None."""
    fn = [_norm(s) for s in flines]
    idx = {}
    for i, s in enumerate(fn, 1):
        if s:
            idx.setdefault(s, []).append(i)
    pos, prev = {}, None
    keys = [(k, _norm(s)) for k, s in enumerate(old) if _norm(s)]
    for k, s in keys:
        cands = idx.get(s, [])
        if prev is None:
            if cands:
                prev = min(cands, key=lambda x: (abs(x - hint) if hint else 0, x))
                pos[k] = prev
        else:
            nxt = [x for x in cands if prev < x <= prev + 10]
            if nxt:
                prev = nxt[0]
                pos[k] = prev
    return pos if keys and len(pos) * 2 >= len(keys) else None


def marked_span(pos, marks):
    """File line span of the changed old lines, from an old_index->line map."""
    known = sorted(pos)
    if not marks or not known:
        return min(pos.values()), max(pos.values())

    def at(k):  # nearest mapped old line
        j = min(known, key=lambda x: (abs(x - k), x))
        return pos[j] + (k - j) if abs(k - j) <= 1 else pos[j]
    pts = [at(k) for m in marks for k in (max(m[0], 0), max(m[1], 0)) if k <= max(known) + 1]
    pts = pts or list(pos.values())
    return min(pts), max(pts)


def fragment_range(path, lines, hints, target):
    """Range of a fragment without @@: locate its old side in the target file."""
    hint = next((h for h in hints if h[0] == path), None) if path else None
    if path is None and hints:
        path, hint = hints[0][0], hints[0]
    old, marks, prev = [], [], ""
    for line in lines:
        if not line.strip() and not line.startswith(" "):
            continue
        if line.startswith("-"):
            marks.append((len(old), len(old)))
            old.append(line[1:])
        elif line.startswith("+"):
            if not prev.startswith(("-", "+")):
                marks.append((len(old) - 1, len(old)))
        else:
            old.append(line[1:] if line.startswith(" ") else line)
        prev = line
    if path and target and any(s.strip() for s in old):
        try:
            flines = locate_snippet.read_target(target, path)
        except (OSError, SystemExit, ValueError):
            flines = None
        if flines is not None:
            res = locate_snippet.locate(flines, "\n".join(old), hint[1] if hint else None)
            if res.get("matched"):
                a, b = res["start_line"], res["end_line"]
                if len(res["chunks"]) == 1 and b - a + 1 == len(old) and marks:
                    lo = min(max(m[0], 0) for m in marks)
                    hi = max(min(m[1], len(old) - 1) for m in marks)
                    return (path, a + lo, a + hi), True
                return (path, a, b), True
            pos = anchor_lines(flines, old, hint[1] if hint else None)
            if pos:
                return (path,) + marked_span(pos, marks), True
    if hint:
        return hint, False
    return None, False


def diff_ranges(diff, file_line, target):
    """Return ([(file, lo, hi)], unlocated_count)."""
    hints = parse_hint(file_line)
    out, unlocated = [], 0
    for path, lines in split_files(strip_fence(diff)):
        if any(HUNK.match(l) for l in lines):
            out += header_ranges(path, lines)
            continue
        if not any(l.startswith(("-", "+")) for l in lines):
            continue
        rng, ok = fragment_range(path, lines, hints, target)
        if rng:
            out.append(rng)
        if not ok:
            unlocated += 1
    return out, unlocated


def row_id(row):
    for k in ("tmp_id", "tmp", "n", "id"):
        v = row.get(k)
        if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v):
            return str(v)
    return None


def embedded_diff(text):
    """BLUEの`fix_suggestion_check`は判定文の後にdiffが続く文字列のことがある。最初の`--- `か`@@ `の行から後を返す。"""
    lines = text.split("\n")
    for i, l in enumerate(lines):
        s = l.lstrip()
        if s.startswith("--- ") or HUNK.match(s):
            if i and lines[i - 1].strip().startswith("```"):
                i -= 1
            return "\n".join(lines[i:])
    return ""


def row_diff(row):
    if isinstance(row.get("diff"), str):
        return row["diff"]
    fsc = row.get("fix_suggestion_check")
    if isinstance(fsc, dict) and isinstance(fsc.get("diff"), str):
        return fsc["diff"]
    if isinstance(fsc, str) and embedded_diff(fsc):
        return embedded_diff(fsc)
    if isinstance(row.get("fix_suggestion"), str):
        return row["fix_suggestion"]
    return ""


def row_hint(row):
    for k in ("corrected_file_line", "file_line"):
        if isinstance(row.get(k), str) and row[k]:
            return row[k]
    return ""


def analyze(members, entries, target=None):
    """members: {unit: [tmp...]}, entries: {tmp: (diff, file_line)}."""
    unit_of = {t: u for u, ts in members.items() for t in ts}
    units = sorted(members)
    ranges = {u: [] for u in units}
    warns, unlocated, no_header = [], [], []
    for tmp, (diff, fl) in sorted(entries.items()):
        u = unit_of.get(tmp)
        if u is None:
            warns.append("diff of %s: not in members (ignored)" % tmp)
            continue
        if not any(HUNK.match(l) for l in diff.split("\n")):
            no_header.append(tmp)
        rs, miss = diff_ranges(diff, fl, target)
        ranges[u] += rs
        if miss:
            unlocated.append(tmp)
    if not any(t in entries for t in unit_of):
        warns.append("no diff matched any member (check --strip-hyphen and the ID key)")
    no_diff = [u for u in units if not ranges[u]]
    pairs = []
    for i, a in enumerate(units):
        for b in units[i + 1:]:
            where = sorted({fa for fa, la, ha in ranges[a] for fb, lb, hb in ranges[b]
                            if fa == fb and la <= hb + NEAR + 1 and lb <= ha + NEAR + 1})
            if where:
                pairs.append([a, b, where])
    parent = {u: u for u in units}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b, _ in pairs:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)
    comps = {}
    for u in units:
        comps.setdefault(find(u), []).append(u)
    comps = sorted(comps.values(), key=lambda c: (-len(c), c))
    largest = len(comps[0]) if comps else 0
    decision = "synth" if units and largest * 2 > len(units) else "sequential"
    return {"units": len(units), "pairs": pairs, "components": comps, "largest": largest,
            "no_diff": no_diff, "unlocated": unlocated, "no_header": no_header, "decision": decision, "warnings": warns}


def load_entries(paths, strip_hyphen):
    out = {}
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict):
                    continue
                tid, d = row_id(row), row_diff(row)
                if not tid or not d:
                    continue
                if strip_hyphen:
                    tid = tid.replace("-", "")
                out[tid] = (d, row_hint(row))
    return out


def render(res):
    L = ["5c pairs (near hunks, <=%d lines): %d" % (NEAR, len(res["pairs"]))]
    L += ["  %s-%s %s" % (a, b, ",".join(w)) for a, b, w in res["pairs"]]
    L.append("components: %d (largest %d of %d units)" % (len(res["components"]), res["largest"], res["units"]))
    L += ["  [%d] %s" % (len(c), "+".join(c)) for c in res["components"] if len(c) > 1]
    if res["no_diff"]:
        L.append("units without diff: " + ",".join(res["no_diff"]))
    if res["no_header"]:
        L.append("WARN: diffs without @@ (BLUE must add them, finding-pipeline.md): " + ",".join(res["no_header"]))
    if res["unlocated"]:
        L.append("unlocated fragments (file_line used): " + ",".join(res["unlocated"]))
    L += ["WARN: " + w for w in res["warnings"]]
    L.append("DECISION: %s" % res["decision"])
    return "\n".join(L)


def self_test():
    import tempfile
    d1 = "--- a/x.js\n+++ b/x.js\n@@ -10,3 +10,3 @@\n a\n-b\n+B\n c\n"
    d2 = "--- a/x.js\n+++ b/x.js\n@@ -14,2 +14,3 @@\n d\n+e\n f\n"
    d3 = "--- a/x.js\n+++ b/x.js\n@@ -40,1 +40,1 @@\n-z\n+Z\n"
    d4 = "--- /dev/null\n+++ b/new.js\n@@ -0,0 +1,2 @@\n+n1\n+n2\n"
    fsc = "①構文的妥当性: 合格。確定版:\n" + d1
    assert row_diff({"fix_suggestion_check": fsc, "fix_suggestion": "x"}) == d1
    assert row_diff({"fix_suggestion_check": "合格（diffなし）", "fix_suggestion": "x"}) == "x"
    assert diff_ranges(d1, "", None) == ([("x.js", 11, 11)], 0)
    assert diff_ranges(d2, "", None) == ([("x.js", 14, 15)], 0)
    assert diff_ranges(d4, "", None) == ([("new.js", 0, 0)], 0)
    m = {"F1": ["A"], "F2": ["B"], "F3": ["C"], "F4": ["D", "E"]}
    r = analyze(m, {"A": (d1, ""), "B": (d2, ""), "C": (d3, ""), "D": (d4, ""), "X": (d3, "")})
    assert r["pairs"] == [["F1", "F2", ["x.js"]]], r["pairs"]  # 11 vs 14: 2 lines between
    assert r["decision"] == "sequential" and r["largest"] == 2
    assert r["warnings"] == ["diff of X: not in members (ignored)"]
    d5 = "--- a/x.js\n+++ b/x.js\n@@ -16,1 +16,1 @@\n-q\n+Q\n"
    d6 = "--- a/x.js\n+++ b/x.js\n@@ -20,1 +20,1 @@\n-w\n+W\n"
    r = analyze(m, {"A": (d1, ""), "B": (d2, ""), "C": (d5, ""), "D": (d6, "")})
    assert r["largest"] == 4 and r["decision"] == "synth", r
    d7 = "--- a/x.js\n+++ b/x.js\n@@ -21,1 +21,1 @@\n-w\n+W\n"
    r = analyze({"F1": ["A"], "F2": ["B"]}, {"A": (d1, ""), "B": (d7, "")})  # 11 vs 21: far
    assert r["pairs"] == [] and r["decision"] == "sequential"
    d8 = d1.replace("a/x.js", "a/./y.js").replace("b/x.js", "b/y.js")
    assert analyze({"F1": ["A"], "F2": ["B"]}, {"A": (d1, ""), "B": (d8, "")})["pairs"] == []
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "r"))
        with open(os.path.join(td, "r", "s.js"), "w", encoding="utf-8") as f:
            f.write("\n".join("line%d" % i for i in range(1, 31)) + "\n")
        frag = "```diff\n line9\n-line10\n+LINE10\n line11\n```\n(注記)"
        assert diff_ranges(frag, "r/s.js:8-12", td) == ([("r/s.js", 10, 10)], 0)
        ins = " line20\n+new\n line21"
        assert diff_ranges(ins, "r/s.js:20", td) == ([("r/s.js", 20, 21)], 0)
        miss = "-nothere\n+x"
        assert diff_ranges(miss, "r/s.js:3-4", td) == ([("r/s.js", 3, 4)], 1)
        allplus = "+a\n+b"
        assert diff_ranges(allplus, "r/s.js:25", td) == ([("r/s.js", 25, 25)], 1)
        r = analyze({"F1": ["A"], "F2": ["B"]}, {"A": (frag, "r/s.js:8-12"), "B": (miss, "r/s.js:3-4")}, td)
        assert r["pairs"] == [] and r["unlocated"] == ["B"], r  # 10 vs 3-4: 5 lines between
        assert r["no_header"] == ["A", "B"], r
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("diffs", nargs="*")
    ap.add_argument("--members")
    ap.add_argument("--target", help="audited directory, used to locate diff fragments without @@")
    ap.add_argument("--strip-hyphen", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.members or not a.diffs:
        print("error: --members and at least one DIFFS.jsonl are required", file=sys.stderr)
        return 2
    try:
        with open(a.members, encoding="utf-8") as f:
            members = json.load(f)
        entries = load_entries(a.diffs, a.strip_hyphen)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if not isinstance(members, dict) or not all(isinstance(v, list) for v in members.values()):
        print("error: members.json must map each unit to a list of temporary IDs", file=sys.stderr)
        return 2
    members = {u: [str(t) for t in ts] for u, ts in members.items()}
    res = analyze(members, entries, a.target)
    print(render(res))
    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="\n") as f:
            json.dump(res, f, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
