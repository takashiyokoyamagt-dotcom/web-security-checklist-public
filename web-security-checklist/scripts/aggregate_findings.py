#!/usr/bin/env python3
"""モード3手順3の前半（受け渡しの検査・集約・5b・5cの機械判定）を1回の呼び出しで行う。

Usage:
  python3 aggregate_findings.py --work WORK --target TARGET [--force]
  python3 aggregate_findings.py --rows ROWS.jsonl --work WORK --target TARGET [--force]
  python3 aggregate_findings.py --self-test

--rows（受け渡しファイル`out/red-NN.jsonl`等が無いとき。モード2等。finding-arbiter.md 5b補足2）: 手順1・2を行わず、
ROWS（JSON Linesか JSON配列。RED・BLUEの全指摘を1行1指摘）から手順3・4だけを行う。各行のキーは`tmp_id`（英数字と`.`）・
`file_line`・`cwe`（整数か`CWE-89`の配列、または`CWE-89`を含む文字列）・`summary`（REDの概要）・`verdict`（BLUEの
判定。先頭語がCONFIRMED/PLAUSIBLE/REFUTED）・`diff`（任意。BLUEの確定diff、無ければREDの修正案）。キーの欠け・
形式違い・`tmp_id`の重複はNGで、何も書かずに rc1。`findings-log.jsonl`は書かない（触らない）。

WORK は保存先（`findings-log.jsonl`と同じ。`out/red-NN.jsonl`・`out/blue-NN.jsonl`・
`target-snapshot.json`があること。references/core/handoff-files.md）。順に次を行う。
1. 検査: 対象が`target-snapshot.json`から変わっていないこと、全`red-NN`・`blue-NN`の形式と必須キー
   （`check_handoff.py --check`と同じ）、REDとBLUEの組がそろい、BLUEの`n`がREDのID（またはREDの行番号）に対応すること。
   NGが1件でもあれば何も書かずに rc1。
2. `findings-log.jsonl`: REDの1指摘＝1行。`tmp_id`（REDの`id`からハイフンを除いたもの。`id`が無ければ
   `R<NN><連番2桁>`）・`red_id`・`cat`・`file_line`・`category`・`cwe`（`category`のCWE番号）・
   `severity`・`summary`・`verdict`（BLUEの`verdict`の先頭語）・`diff`（BLUEの`fix_suggestion_check`内の
   確定diff。無ければREDの`fix_suggestion`）・`diff_source`（`blue`/`red`）。
3. 5b（finding-arbiter.md 5b・5b補足・5b補足2・5b補足5〜8）: CONFIRMED・PLAUSIBLEの指摘について、共有CWEか
   同族CWE（`FAMILIES`）を持つ全ペアを判定し（広範CWEだけの共有と同族CWEは、行の重なりが長い方の半分以上、または短い方の半分以上で
   要約が近ければ〔5b補足6〕成立。CWEの関係が無くても、長い方の半分以上が重なり要約がかなり近ければ〔5b補足7〕成立）、
   全ペア成立の組だけを群にする
   （`check_5b_clique.py`と同じ導出）。`5b-pair-table.md`（ペア表・群表）と`members.json`
   （群・単独項目→一時ID。キーは`F1`…、群が先で構成IDの昇順）を書き、`check_5b_clique.py`で検算する。
4. 5c: `check_5c_components.py`で近接するhunkの連結成分を求め、`5c-components.txt`に保存する。
最後に件数と`DECISION:`の行だけを表示する。既存の出力ファイルがあれば`--force`が無い限り rc2。
判断を含まない。統合の可否・経路の選択をArbiterが変えない。Stdlib only, Python 3.9+.
"""
import argparse
import glob
import io
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_5b_clique as c5b  # noqa: E402
import check_5c_components as c5c  # noqa: E402
import check_handoff as ho  # noqa: E402

BROAD = {20, 200, 284, 285, 287, 306, 693, 862, 863}  # finding-arbiter.md 5b補足（306はエンドポイントごとに別の欠陥）
# finding-arbiter.md 5b補足5: 同じ欠陥にRedが付けがちな別番号の族。共有CWEが無くても、同じ族で
# 行が重なれば（5b補足の重なり）成立。族は増やしすぎない（別の欠陥を統合しないため）
FAMILIES = {
    "露出": {200, 201, 209, 210, 211, 213, 312, 359, 497, 538, 540},
    "認可": {269, 284, 285, 306, 639, 862, 863},
    "Cookie属性": {614, 1004, 1275},
    "秘密の直書き": {259, 321, 547, 798},
    "入力・例外": {20, 248, 476, 754, 755},
}
FAMILY_OF = {c: k for k, v in FAMILIES.items() for c in v}
# 5b補足6: 同じ欠陥を別の行範囲で書いた重複を、短い方の半分以上の重なりで統合するときの要約の近さの
# 下限（r5〜r10の保存データで誤統合0件の値。0.20では誤統合1件）
SIM_MIN = 0.25
# 5b補足7: 共有CWEも同族CWEも無いペア（同じ欠陥に別系統のCWEを付けたもの）を、行の重なり（長い方の半分以上）で
# 統合するときの要約の近さの下限（r5〜r11の保存データで0.4・0.5は誤統合0件、0.3で誤統合あり）
SIM_ANY = 0.5
# 5b補足8: 箇所ごとに別の欠陥になる広範以外のCWE（注入・資源の上限・権限の付与）。これだけの共有は、共通のファイルが
# 無ければ成立しない（r13で全エンドポイントにCWE-770を付けたREDの指摘が1群になり、GET /users等の本来の群から外れた。
# DB評価セットでは別ファイルのSQLi 17件が1群になった。89・943を足すと、保存データのサンプルアプリは項目479→486、
# DBは統合後の必須項目の検出率84%→92%で重複は増えない。全CWEに広げるとXSS（ビューとルート）等の同じ欠陥が分かれ、
# 1327・250を足すとDBの重複が倍になる。dev/p4/db-gate-20261116.md）。共通のファイルでも、行が重なるか隣接しなければ
# 成立しない（同じファイルの別の注入箇所を分ける。DBは誤った統合14→10組・検出率+1件、サンプルアプリは検索のSQLiが
# /search と /search/sorted に分かれる。dev/p4/sqli-same-file-20261122.md）
LOCAL = {89, 269, 400, 770, 943}
ADOPT = ("CONFIRMED", "PLAUSIBLE")
OUTPUTS = ("findings-log.jsonl", "5b-pair-table.md", "members.json", "5c-components.txt")


def cwes(category):
    return sorted({int(x) for x in re.findall(r"CWE-(\d+)", str(category or ""))})


def verdict_word(v):
    m = re.match(r"\s*([A-Za-z]+)", str(v or ""))
    return m.group(1).upper() if m else ""


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(s) for s in (l.strip() for l in f) if s]


def check(work, target):
    """手順1。問題の一覧と、カテゴリ番号の一覧を返す"""
    problems = ho.check_target(target, os.path.join(work, "target-snapshot.json"))
    out = os.path.join(work, "out")
    reds = {re.match(r"red-(\d+)", os.path.basename(p)).group(1): p
            for p in glob.glob(os.path.join(out, "red-*.jsonl")) if re.match(r"red-\d+\.jsonl$", os.path.basename(p))}
    blues = {re.match(r"blue-(\d+)", os.path.basename(p)).group(1): p
             for p in glob.glob(os.path.join(out, "blue-*.jsonl")) if re.match(r"blue-\d+\.jsonl$", os.path.basename(p))}
    if not reds:
        problems.append("no out/red-NN.jsonl")
    for nn in sorted(set(reds) | set(blues)):
        if nn not in reds:
            problems.append("blue-%s.jsonl has no red-%s.jsonl" % (nn, nn))
        if nn not in blues:
            problems.append("red-%s.jsonl has no blue-%s.jsonl" % (nn, nn))
    for nn, p in sorted(reds.items()):
        problems += ["red-%s: %s" % (nn, x) for x in ho.check_out(p, "red")[0]]
    for nn, p in sorted(blues.items()):
        problems += ["blue-%s: %s" % (nn, x) for x in ho.check_out(p, "blue")[0]]
    return problems, sorted(set(reds) & set(blues))


def unfence(d):
    """先頭の```のフェンスの中身だけを返す（閉じた後の注記は捨てる）。フェンスが無ければそのまま"""
    lines = d.strip("\n").split("\n")
    if lines[0].startswith("```"):
        end = next((i for i in range(1, len(lines)) if lines[i].strip() == "```"), None)
        if end:
            return "\n".join(lines[1:end]) + "\n"
    return d


def build_log(work, cats):
    rows, problems = [], []
    for nn in cats:
        red = load_jsonl(os.path.join(work, "out", "red-%s.jsonl" % nn))
        blue = load_jsonl(os.path.join(work, "out", "blue-%s.jsonl" % nn))
        rid = [str(r.get("id") or "R%s-%02d" % (nn, k)) for k, r in enumerate(red, 1)]
        bmap = {}
        for b in blue:
            key = str(b.get("n"))
            if key not in rid and key.isdigit() and 1 <= int(key) <= len(rid):
                key = rid[int(key) - 1]  # nをREDの行番号（1始まり）で書いた場合
            if key in bmap:
                problems.append("blue-%s: duplicate n %s" % (nn, key))
            bmap[key] = b
        for key in sorted(set(bmap) - set(rid)):
            problems.append("blue-%s: n %s is not a RED id" % (nn, key))
        for r, i in zip(red, rid):
            b = bmap.get(i)
            if b is None:
                problems.append("red-%s: %s has no BLUE verdict" % (nn, i))
                continue
            fsc = b.get("fix_suggestion_check")
            d = c5c.row_diff({"fix_suggestion_check": fsc}) if fsc else ""
            src = "blue" if d else "red"
            if not d:
                d = r.get("fix_suggestion") if isinstance(r.get("fix_suggestion"), str) else ""
            d = unfence(d)
            rows.append({"tmp_id": re.sub(r"[^0-9A-Za-z.]", "", i), "red_id": i, "cat": nn,
                         "file_line": r.get("file_line"), "category": r.get("category"),
                         "cwe": cwes(r.get("category")), "severity": r.get("severity"),
                         "summary": r.get("summary"), "verdict": verdict_word(b.get("verdict")),
                         "diff": d, "diff_source": src})
    ids = [r["tmp_id"] for r in rows]
    problems += ["duplicate tmp_id %s" % t for t in sorted({t for t in ids if ids.count(t) > 1})]
    return rows, problems


ROW_KEYS = ("tmp_id", "file_line", "cwe", "summary", "verdict")


def load_rows(path):
    """--rows の入力（JSON Linesか JSON配列）を手順3・4の行にする。(行, 問題の一覧)"""
    try:
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return [], ["cannot read %s: %s" % (path, e)]
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if not isinstance(data, list):
        try:
            data = [json.loads(s) for s in (x.strip() for x in text.split("\n")) if s]
        except ValueError as e:
            return [], ["%s is neither a JSON array nor JSON Lines: %s" % (path, e)]
    rows, problems = [], []
    for i, r in enumerate(data, 1):
        miss = [k for k in ROW_KEYS if not isinstance(r, dict) or k not in r]
        if miss:
            problems.append("row %d: missing %s" % (i, ",".join(miss)))
            continue
        t, c, d = str(r["tmp_id"]), r["cwe"], r.get("diff") or ""
        if not re.fullmatch(r"[0-9A-Za-z.]+", t):
            problems.append("row %d: tmp_id %r must be letters, digits and '.' only (5b補足2)" % (i, t))
        cw = cwes(" ".join("CWE-%s" % x if str(x).isdigit() else str(x) for x in c)) if isinstance(c, list) else cwes(c)
        if not cw:
            problems.append("row %d (%s): no CWE number in cwe %r" % (i, t, c))
        v = verdict_word(r["verdict"])
        if v not in ADOPT + ("REFUTED",):
            problems.append("row %d (%s): verdict %r is not CONFIRMED/PLAUSIBLE/REFUTED" % (i, t, r["verdict"]))
        if not isinstance(d, str):
            problems.append("row %d (%s): diff must be a string" % (i, t))
            d = ""
        rows.append({"tmp_id": t, "file_line": str(r["file_line"]), "cwe": cw, "summary": str(r["summary"]),
                     "verdict": v, "diff": unfence(d) if d.strip() else ""})
    ids = [r["tmp_id"] for r in rows]
    problems += ["duplicate tmp_id %s" % t for t in sorted({t for t in ids if ids.count(t) > 1})]
    if not data:
        problems.append("%s has no rows" % path)
    return rows, problems


def overlaps_short(x, y):
    """5b補足6の重なり: 同じファイル名で共有する行が、短い方の範囲の半分以上"""
    for f in sorted(set(x) & set(y)):
        sh = x[f] & y[f]
        if sh and 2 * len(sh) >= min(len(x[f]), len(y[f])):
            return f, sh
    return None


_SEP = re.compile(r"[\s、。・，,.:;()（）「」『』/\[\]{}=<>'\"`!?！？-]+")


def summary_grams(s):
    """要約の語の集合: 英数字は2文字以上の語、それ以外は区切り記号で分けた各断片の2文字組。
    「（要検証…）」の注記は除く"""
    s = re.sub(r"\(要検証[^)]*\)|（要検証[^）]*）", "", str(s or "")).lower()
    out = set(re.findall(r"[a-z0-9_]{2,}", s))
    for w in _SEP.sub(" ", re.sub(r"[a-z0-9_]+", " ", s)).split():
        out |= {w[i:i + 2] for i in range(len(w) - 1)}
    return out


def summary_sim(a, b):
    """要約の近さ: 共通の語の数 ÷ 少ない方の語の数（0〜1）"""
    x, y = summary_grams(a), summary_grams(b)
    return len(x & y) / max(1, min(len(x), len(y)))


def _loose(a, b):
    """5b補足6: 長い方の半分に届かない重なりでも、短い方の半分以上が重なり、要約が近ければ成立。注記か None"""
    ov = overlaps_short(c5b.spans(a["file_line"]), c5b.spans(b["file_line"]))
    if not ov:
        return None
    s = summary_sim(a.get("summary"), b.get("summary"))
    if s < SIM_MIN:
        return None
    return "行の重なり %s:%s（短い方の半分以上・要約の近さ %.2f）" % (ov[0], c5b.compact(ov[1]), s)


def _unrelated(a, b):
    """5b補足7: CWEの関係が無いペアは、行の重なりと要約の近さ SIM_ANY 以上で成立。(CWE, True, 注記) か None"""
    ov = c5b.overlaps(c5b.spans(a["file_line"]), c5b.spans(b["file_line"]))
    s = summary_sim(a.get("summary"), b.get("summary")) if ov else 0
    if s < SIM_ANY:
        return None
    return (set(a["cwe"]) | set(b["cwe"]), True,
            "CWEの関係なし・行の重なり %s:%s（要約の近さ %.2f）" % (ov[0], c5b.compact(ov[1]), s))


def near(x, y):
    """5b補足8: 同じファイル名で、行が1行以上重なるか隣接する（34と35）"""
    return any(x[f] & {n + d for n in y[f] for d in (-1, 0, 1)} for f in set(x) & set(y))


def pair_judgement(a, b):
    """(共有CWE, 成立か, 注記)。共有CWEも同族CWEも無ければ None"""
    sh = set(a["cwe"]) & set(b["cwe"])
    if not sh:
        fam = {FAMILY_OF[c] for c in a["cwe"] if c in FAMILY_OF} & {FAMILY_OF[c] for c in b["cwe"] if c in FAMILY_OF}
        if not fam:
            return _unrelated(a, b)
        cw = {c for c in set(a["cwe"]) | set(b["cwe"]) if FAMILY_OF.get(c) in fam}
        head = "同族CWE（%s）・" % "・".join(sorted(fam))
    elif sh - BROAD:
        if not (sh - BROAD - LOCAL) and not near(c5b.spans(a["file_line"]), c5b.spans(b["file_line"])):
            return sh, False, "広範以外のCWE共有・共通のファイルで行の重なりも隣接もなし（5b補足8）"
        return sh, True, "広範以外のCWE共有"
    else:
        cw, head = sh, "広範CWEのみ・"
    ov = c5b.overlaps(c5b.spans(a["file_line"]), c5b.spans(b["file_line"]))
    if ov:
        return cw, True, head + "行の重なり %s:%s" % (ov[0], c5b.compact(ov[1]))
    loose = _loose(a, b)
    if loose:
        return cw, True, head + loose
    return cw, False, head + "行の重なり不足"


def build_5b(rows):
    ad = [r for r in rows if r["verdict"] in ADOPT]
    by = {r["tmp_id"]: r for r in ad}
    pairs = {}
    for x, y in itertools.combinations(sorted(by), 2):
        j = pair_judgement(by[x], by[y])
        if j:
            pairs[(x, y)] = j
    ok = lambda x, y: bool(pairs.get(tuple(sorted((x, y))), (0, False))[1])  # noqa: E731
    groups = sorted((sorted(g) for g in c5b.derive(by, ok)), key=lambda g: g)
    members, gid = {}, {}
    grouped = set()
    for g in groups:
        k = "F%d" % (len(members) + 1)
        members[k] = g
        grouped |= set(g)
        for t in g:
            gid[t] = k
    for t in sorted(set(by) - grouped):
        k = "F%d" % (len(members) + 1)
        members[k] = [t]
        gid[t] = k
    lines = ["| ペア | 共有CWE | 判定 | 注記 |", "| --- | --- | --- | --- |"]
    cnt = {"統合": 0, "非統合": 0, "連鎖切断": 0}
    for (x, y), (sh, good, note) in sorted(pairs.items()):
        j = "非統合" if not good else ("統合" if gid[x] == gid[y] else "連鎖切断")
        cnt[j] += 1
        lines.append("| %s-%s | %s | %s | %s |" % (x, y, ",".join("CWE-%d" % c for c in sorted(sh)), j, note))
    lines += ["", "| 群 | 構成 |", "| --- | --- |"]
    lines += ["| %s | %s |" % (k, "+".join(v)) for k, v in members.items() if len(v) > 1]
    return members, "\n".join(lines) + "\n", cnt, len(ad)


def run(work, target, force=False, rows_path=None):
    outputs = OUTPUTS[1:] if rows_path else OUTPUTS  # --rows は findings-log.jsonl を書かない
    if not force:
        exist = [p for p in outputs if os.path.exists(os.path.join(work, p))]
        if exist:
            print("error: already exists (use --force): " + ", ".join(exist))
            return 2
    if rows_path:
        rows, problems = load_rows(rows_path)
        cats = []
    else:
        problems, cats = check(work, target)
        rows = []
        if not problems:
            rows, problems = build_log(work, cats)
    if problems:
        for p in problems:
            print("NG: " + p)
        print("RESULT: NG (nothing written)")
        return 1
    members, table, cnt, nad = build_5b(rows)

    def write(name, text):
        with open(os.path.join(work, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    if not rows_path:
        write("findings-log.jsonl", "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    write("5b-pair-table.md", table)
    write("members.json", json.dumps(members, ensure_ascii=False, indent=1) + "\n")
    chk = subprocess.run([sys.executable, os.path.join(HERE, "check_5b_clique.py"),
                          os.path.join(work, "5b-pair-table.md")],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace",
                         env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    entries = {r["tmp_id"]: (r["diff"], r["file_line"] or "") for r in rows if r["verdict"] in ADOPT and r["diff"]}
    res = c5c.analyze(members, entries, target)
    write("5c-components.txt", c5c.render(res) + "\n")
    v = {k: sum(1 for r in rows if r["verdict"] == k) for k in ("CONFIRMED", "PLAUSIBLE", "REFUTED")}
    other = len(rows) - sum(v.values())
    counts = "%d row(s) (CONFIRMED %d / PLAUSIBLE %d / REFUTED %d%s)" % (
        len(rows), v["CONFIRMED"], v["PLAUSIBLE"], v["REFUTED"], " / other %d" % other if other else "")
    if rows_path:
        print("rows: %s; adopted without diff: %d" % (counts, sum(1 for r in rows if r["verdict"] in ADOPT and not r["diff"])))
    else:
        nsrc = sum(1 for r in rows if r["verdict"] in ADOPT and r["diff_source"] == "red")
        print("handoff: OK (red/blue %d pair(s), target unchanged)" % len(cats))
        print("findings-log.jsonl: %s; adopted without BLUE diff: %d" % (counts, nsrc))
    print("5b: %d pair(s) (統合 %d / 非統合 %d / 連鎖切断 %d); %d group(s) + %d single(s) = %d item(s)"
          % (sum(cnt.values()), cnt["統合"], cnt["非統合"], cnt["連鎖切断"],
             sum(1 for m in members.values() if len(m) > 1), sum(1 for m in members.values() if len(m) == 1),
             len(members)))
    last = (chk.stdout.strip().splitlines() or ["(no output)"])[-1]
    print("check_5b_clique: rc%d %s" % (chk.returncode, last))
    print("5c: largest component %d of %d item(s); pairs %d" % (res["largest"], res["units"], len(res["pairs"])))
    for w in (["diffs without @@: " + ",".join(res["no_header"])] if res["no_header"] else []) + res["warnings"]:
        print("WARN: " + w)
    print("DECISION: %s" % res["decision"])
    return 0 if chk.returncode == 0 else 1


def self_test():
    with tempfile.TemporaryDirectory() as d:
        tgt, work = os.path.join(d, "app"), os.path.join(d, "work")
        os.makedirs(os.path.join(tgt, "routes"))
        os.makedirs(os.path.join(work, "out"))
        src = "\n".join("l%d" % i for i in range(1, 41)) + "\n"
        with open(os.path.join(tgt, "routes", "a.js"), "w", encoding="utf-8") as f:
            f.write(src)
        with open(os.path.join(work, "target-snapshot.json"), "w", encoding="utf-8") as f:
            json.dump({"files": ho.digest(tgt)}, f)

        def red(i, fl, cat):
            return {"id": i, "file_line": fl, "category": cat, "severity": "High", "summary": "s",
                    "vulnerable_code": "c", "root_cause": "r", "failure_scenario": "f", "fix_suggestion": "x"}

        def blue(n, v, line):
            diff = "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -%d,1 +%d,1 @@\n-l%d\n+L%d\n" % (line, line, line, line)
            return {"n": n, "verdict": v, "evidence": "e", "fix_suggestion_check": "①合格。確定版:\n" + diff}

        def put(name, rows):
            with open(os.path.join(work, "out", name), "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))

        put("red-01.jsonl", [red("R01-01", "routes/a.js:10-12", "入力 CWE-89"),
                             red("R01-02", "routes/a.js:30", "認可 CWE-862"),
                             red("R01-03", "routes/a.js:5", "x CWE-79")])
        put("blue-01.jsonl", [blue("R01-01", "CONFIRMED", 11), blue("R01-02", "PLAUSIBLE（要確認）", 30),
                              blue("R01-03", "REFUTED", 5)])
        put("red-02.jsonl", [red("R02-01", "routes/a.js:10-11", "DB CWE-89"),
                             red("R02-02", "routes/a.js:20-21", "認可 CWE-862"),
                             red("R02-03", "routes/a.js:30", "IDOR CWE-639"),
                             red("R02-04", "routes/a.js:5", "CSRF CWE-352")])
        put("blue-02.jsonl", [blue(1, "CONFIRMED", 12), blue("R02-02", "CONFIRMED", 20),
                              blue("R02-03", "CONFIRMED", 30), blue("R02-04", "CONFIRMED", 5)])  # nは行番号でもよい
        with open(os.path.join(work, "out", "blue-02.jsonl"), encoding="utf-8") as f:
            fenced = f.read().replace("確定版:\\n---", "確定版:\\n```diff\\n---", 1).replace("+L12\\n", "+L12\\n```\\n（注記）", 1)
        assert fenced.count("```") == 2, fenced
        with open(os.path.join(work, "out", "blue-02.jsonl"), "w", encoding="utf-8") as f:
            f.write(fenced)
        buf = io.StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            rc = run(work, tgt)
            rc2 = run(work, tgt)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert rc == 0, out
        assert rc2 == 2, out
        rows = load_jsonl(os.path.join(work, "findings-log.jsonl"))
        assert [r["tmp_id"] for r in rows] == ["R0101", "R0102", "R0103", "R0201", "R0202", "R0203", "R0204"], rows
        assert rows[1]["verdict"] == "PLAUSIBLE" and rows[0]["diff_source"] == "blue", rows
        assert rows[3]["diff"].startswith("--- a/") and rows[3]["diff"].endswith("+L12\n"), rows[3]  # フェンスと注記を外す
        mem = json.load(open(os.path.join(work, "members.json"), encoding="utf-8"))
        assert mem == {"F1": ["R0101", "R0201"], "F2": ["R0102", "R0203"], "F3": ["R0202"], "F4": ["R0204"]}, mem
        table = open(os.path.join(work, "5b-pair-table.md"), encoding="utf-8").read()
        assert "| R0101-R0201 | CWE-89 | 統合 |" in table, table
        assert "| R0102-R0202 | CWE-862 | 非統合 |" in table, table
        assert "| R0102-R0203 | CWE-639,CWE-862 | 統合 | 同族CWE（認可）" in table, table  # 5b補足5
        assert "R0204" not in table, table  # 族の外（CWE-352）は同じ行でも統合しない
        P = lambda c, fl: {"cwe": c, "file_line": fl}  # noqa: E731
        assert pair_judgement(P([306], "u.js:37-45"), P([306], "up.js:16-18"))[1] is False  # 306は広範: 別の箇所は統合しない
        assert pair_judgement(P([306], "u.js:37-45"), P([862], "u.js:37-45"))[1] is True  # 認可の族
        assert pair_judgement(P([200], "u.js:39-45"), P([213], "u.js:39-45"))[1] is True  # 露出の族
        # 5b補足8: 資源の上限・権限の付与だけの共有は、共通のファイルが無ければ不成立
        assert pair_judgement(P([306, 770], "u.js:39-45"), P([307, 770], "auth.js:30-49"))[1] is False
        assert pair_judgement(P([770], "up.js:14"), P([306, 770], "up.js:10-18"))[1] is True
        assert pair_judgement(P([79], "v.ejs:8"), P([79], "c.js:6-34"))[1] is True  # LOCAL以外は別ファイルでも統合
        assert pair_judgement(P([269, 915], "auth.js:14-18"), P([269, 862], "u.js:48-58"))[1] is False
        assert pair_judgement(P([89], "inv.js:14-16"), P([89], "cust.js:26-30"))[1] is False  # 別ファイルのSQLi
        # 同じファイルでも別の箇所（status 14-16とsort 21、export 39-44と二次SQLi 46-53）は不成立。重なり・隣接は成立
        assert pair_judgement(P([89], "inv.js:14-16"), P([89], "inv.js:21"))[1] is False
        assert pair_judgement(P([89], "inv.js:39-44"), P([89], "inv.js:46-53"))[1] is False
        assert pair_judgement(P([89], "inv.js:21"), P([89], "inv.js:21-22"))[1] is True
        assert pair_judgement(P([943], "c.js:49-54"), P([943], "c.js:55"))[1] is True  # 隣接
        assert pair_judgement(P([89], "s.js:8-18,db.js:24-26"), P([89], "db.js:25"))[1] is True  # 共通の関数
        assert pair_judgement(P([89], "c.js:13-15,32-37"), P([89], "c.js:26-30"))[1] is False  # 範囲の間は重ならない
        assert pair_judgement(P([770], "c.js:6-17"), P([770], "c.js:22-33"))[1] is False
        assert pair_judgement(P([89], "inv.js:全体"), P([89], "inv.js:21"))[1] is False  # 行が非数値
        # 5b補足6: 短い方の半分以上の重なりは、要約が近いときだけ成立
        Q = lambda c, fl, s: {"cwe": c, "file_line": fl, "summary": s}  # noqa: E731
        s1 = "GET /search が未認証かつ件数上限なしで、q 未指定時に全ユーザーの id・email を返す。"
        s2 = "GET /search が未認証・件数無制限で、q未指定（空文字）なら全ユーザーのメールアドレスを返す。"
        s3 = "POST /loginがdb.getのerrを無視し、DB障害を「未登録」と誤応答してログにも残さない。"
        j = pair_judgement(Q([200], "s.js:8-11", s1), Q([200], "s.js:8-18", s2))
        assert j[1] is True and "短い方の半分以上" in j[2], j
        assert pair_judgement(Q([200], "s.js:8-11", s1), Q([200], "s.js:8-18", s3))[1] is False  # 要約が遠い
        assert pair_judgement(Q([200], "s.js:8-9", s1), Q([200], "s.js:9-18", s2))[1] is True  # 短い方2行の1行
        assert pair_judgement(Q([200], "s.js:8-11", s1), Q([200], "s.js:11-18", s2))[1] is False  # 4行の1行は不足
        assert pair_judgement(Q([614], "a.js:43-47", s1), Q([1004], "a.js:46", s2))[1] is True  # 同族にも適用
        assert pair_judgement(Q([352], "a.js:43-47", s1), Q([942], "a.js:46", s2)) is None  # 族の外は対象外
        # 5b補足7: CWEの関係が無いペアは、長い方の半分以上の重なりと要約の近さ SIM_ANY 以上で成立
        s4 = "パスワードを平文のままusersテーブルに保存している。"
        s5 = "パスワードを平文のままDBに保存している。"
        j = pair_judgement(Q([521], "a.js:14-27", s4), Q([256], "a.js:14-24", s5))
        assert j[1] is True and "CWEの関係なし" in j[2], j
        assert pair_judgement(Q([521], "a.js:14-27", s4), Q([256], "a.js:14-24", s3)) is None  # 要約が遠い
        assert pair_judgement(Q([521], "a.js:14-27", s4), Q([256], "a.js:24-30", s5)) is None  # 重なり不足
        assert summary_sim("（要検証: x）", "") == 0 and summary_sim(s1, s1) == 1.0
        assert "check_5b_clique: rc0" in out and "DECISION: sequential" in out, out
        # --rows（モード2等）: 同じ指摘を1行1指摘で渡すと、同じ5b・5cの結果になり findings-log.jsonl は書かない
        w2 = os.path.join(d, "w2")
        os.makedirs(w2)
        rp = os.path.join(w2, "rows.jsonl")
        conv = [{"tmp_id": r["tmp_id"], "file_line": r["file_line"],
                 "cwe": r["cwe"] if k % 2 else ["CWE-%d" % c for c in r["cwe"]],  # 整数でも「CWE-n」でもよい
                 "summary": r["summary"], "verdict": r["verdict"] + "（根拠）", "diff": r["diff"]}
                for k, r in enumerate(rows)]
        with open(rp, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in conv))
        buf = io.StringIO()
        sys.stdout = buf
        try:
            rc = run(w2, tgt, rows_path=rp)
            rc2 = run(w2, tgt, rows_path=rp)
        finally:
            sys.stdout = old
        out2 = buf.getvalue()
        assert rc == 0 and rc2 == 2 and "rows: 7 row(s)" in out2 and "DECISION: sequential" in out2, out2
        assert json.load(open(os.path.join(w2, "members.json"), encoding="utf-8")) == mem
        assert open(os.path.join(w2, "5b-pair-table.md"), encoding="utf-8").read() == table
        assert sorted(os.listdir(w2)) == ["5b-pair-table.md", "5c-components.txt", "members.json", "rows.jsonl"]
        with open(rp, "w", encoding="utf-8") as f:  # JSON配列も読む。欠け・形式違い・重複はNGで何も書かない
            json.dump([dict(conv[0], tmp_id="R01-01"), {"tmp_id": "X1"}, dict(conv[1], cwe="なし"),
                       dict(conv[2], verdict="要確認"), conv[3], conv[3]], f, ensure_ascii=False)
        buf = io.StringIO()
        sys.stdout = buf
        try:
            rc = run(w2, tgt, force=True, rows_path=rp)
        finally:
            sys.stdout = old
        out2 = buf.getvalue()
        for x in ("tmp_id 'R01-01'", "row 2: missing file_line", "no CWE number", "is not CONFIRMED", "duplicate tmp_id R0201"):
            assert x in out2, (x, out2)
        assert rc == 1 and json.load(open(os.path.join(w2, "members.json"), encoding="utf-8")) == mem, out2
        # 対象の変更とBLUEの欠けはNGで、何も書かない
        with open(os.path.join(tgt, "routes", "a.js"), "a", encoding="utf-8") as f:
            f.write("x\n")
        os.remove(os.path.join(work, "out", "blue-02.jsonl"))
        buf = io.StringIO()
        sys.stdout = buf
        try:
            rc = run(work, tgt, force=True)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert rc == 1 and "target file changed" in out and "red-02.jsonl has no blue-02.jsonl" in out, out
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work")
    ap.add_argument("--target")
    ap.add_argument("--rows", help="mode 2 etc.: findings as JSON Lines/array (5b and 5c only)")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.work and a.target):
        ap.error("--work and --target are required")
    return run(a.work, a.target, a.force, a.rows)


if __name__ == "__main__":
    sys.exit(main())
