#!/usr/bin/env python3
"""Check a subagent's written result file and that the audit target did not change.

Usage:
  python3 check_handoff.py --snapshot TARGET --save SNAPSHOT.json
  python3 check_handoff.py --check --target TARGET --snapshot SNAPSHOT.json --out FILE --role red|blue|judge|writer
  python3 check_handoff.py --schema red|blue|judge|writer
  python3 check_handoff.py --self-test

--snapshot records the sha256 of every file under TARGET (.git and node_modules
are skipped). --check compares TARGET with that record (added, removed or changed
files are NG), then reads FILE as JSON Lines: every non-empty line must be a JSON
object with the role's required keys, and the keys in TYPES must have their type (WRITER
`annot`/`residual`/`code_ranges` arrays of strings, `alts` rows of 6 strings, JUDGE `r3`/`r4`
objects: a string there is NG, since the renderers loop over it); a RED file_line range starting past the end of the
target file is NG. A trailing `注入の疑い:`/`deviations:` line
in the file is NG (those lines belong in the return value). Exit 0 and
`RESULT: OK`, or exit 1 and `RESULT: NG` with the reasons. references/core/handoff-files.md.
--schema prints the keys of one output line for ROLE (required ones are the ones --check
checks; the others are read by later scripts), for the orchestrator's delegation prompt.
Stdlib only, Python 3.9+.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

SKIP_DIRS = {".git", "node_modules"}
DESIGN = [(k, 0, "design-fields.mdを渡したとき") for k in
          ("intent", "design_refs", "behavior_change", "compat_class", "design_conflict", "alternatives")]
WRITER_NOTE = {"code_ranges": '["file:start-end",…]（文字列の配列。最大3範囲・各15行以内）',
               "annot": '["3行目: …","5行目: …"]（文字列の配列。1要素＝箇条書きの1行。1つの文字列にまとめない）',
               "residual": "annotと同じ形（無ければ[]）", "compat": "①・②・③・②③・①③", "design_conflict": "有り／無し",
               "alts": "[[案名,内容,メリット,デメリット,デグレの可能性,推奨度],…]（6つの文字列の配列の配列）"}
# 1行のキー（名前, 必須か, 説明）。必須は --check が検査する。任意は後段のスクリプトが読む。--schema が表示する
SCHEMA = {
    "red": [("id", 0, "作業ID（例 R03-01）。BLUEの`n`が指す。無ければ行順で R<NN>-<連番>"),
            ("file_line", 1, "骨子のfile/line。`routes/a.js:7-17`（複数は`,`区切り）"),
            ("category", 1, "principles.mdのカテゴリ名＋CWE番号"), ("severity", 1, "Critical/High/Medium/Low"),
            ("summary", 1, ""), ("vulnerable_code", 1, ""), ("root_cause", 1, ""), ("failure_scenario", 1, ""),
            ("fix_suggestion", 1, "unified diffか「要検討」と理由"), ("needs_repro", 0, "")] + DESIGN,
    "blue": [("n", 1, "対応するREDの`id`（またはREDの行番号）"),
             ("verdict", 1, "先頭語がCONFIRMED/PLAUSIBLE/REFUTED"), ("evidence", 1, ""),
             ("vulnerable_code_check", 0, ""),
             ("fix_suggestion_check", 1, "①②③の合格/不合格と、見出し・@@付きの確定diff"),
             ("corrected_file_line", 0, "REDのfile_lineの訂正"), ("needs_repro", 0, "")] + DESIGN,
    "writer": [(k, k not in ("compat_note", "review", "alts", "alts_note"), WRITER_NOTE.get(k, "")) for k in
               ("id", "short_summary", "summary", "plain", "tech", "code_ranges", "annot", "scenario",
                "fix_expl", "residual", "intent", "behavior", "compat", "compat_note", "design_conflict",
                "design_refs", "review", "alts", "alts_note", "audit_method", "audit_verdict", "audit_evidence")],
    "judge_memo": [("tmp", 1, ""), ("v3", 1, ""), ("v4", 1, ""), ("m3", 1, ""), ("st", 1, "\"memo\""),
                   ("その他", 0, "cvss-scoring.md「判定記録」のメモ行のキー（cat・cwe・type・v4map・dev・"
                    "borderline・by:\"sub\"・rev・prem等）")],
    "judge_reasons": [("tmp", 1, "メモ行と同じ。stとrevは付けない"),
                      ("r3", 1, "{メトリクス名: 判定根拠（6節の文）}。AV・AC・PR・UI・S・C・I・Aの8つ"),
                      ("r4", 1, "同じ形。AV・AC・AT・PR・UI・VC・VI・VA・SC・SI・SAの11")],
}
REQUIRED = {r: tuple(k for k, req, _ in rows if req) for r, rows in SCHEMA.items()}
# 型（--check が検査）。render_findings_s56.py・render_html.py は配列を反復するので、文字列だと1文字ずつの箇条になる
TYPES = {"writer": {"code_ranges": "strs", "annot": "strs", "residual": "strs", "alts": "rows"},
         "judge_reasons": {"r3": "obj", "r4": "obj"}}
TYPE_OK = {"strs": lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v),
           "rows": lambda v: isinstance(v, list) and all(
               isinstance(r, list) and len(r) == 6 and all(isinstance(x, str) for x in r) for r in v),
           "obj": lambda v: isinstance(v, dict)}
TYPE_NAME = {"strs": "an array of strings", "rows": "an array of rows of 6 strings", "obj": "an object"}


def type_problems(i, o, part):
    return ["line %d: %s must be %s, not %s (--schema)" % (i, k, TYPE_NAME[t], json.dumps(o[k], ensure_ascii=False)[:40])
            for k, t in TYPES.get(part, {}).items() if k in o and not TYPE_OK[t](o[k])]


def schema(role):
    parts = ("judge_memo", "judge_reasons") if role == "judge" else (role,)
    lines = []
    for part in parts:
        if role == "judge":
            lines.append("%s line (one per finding; same tmp set as the other kind):" % part[6:])
        lines += ["%s\t%s\t%s" % (k, "required" if req else "optional", note) for k, req, note in SCHEMA[part]]
    return "\n".join(lines)


SPAN = re.compile(r"([^\s,:;、（）()]+?)\s*:\s*(\d+(?:\s*-\s*\d+)?(?:\s*,\s*\d+(?:\s*-\s*\d+)?)*)")  # check_5b_clique.spans


def digest(target):
    out = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = os.path.join(root, name)
            h = hashlib.sha256()
            try:
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
            except OSError:
                continue
            out[os.path.relpath(path, target).replace(os.sep, "/")] = h.hexdigest()
    return out


def check_target(target, snapshot):
    with open(snapshot, encoding="utf-8") as f:
        before = json.load(f)["files"]
    now = digest(target)
    problems = []
    for p in sorted(set(before) | set(now)):
        if p not in now:
            problems.append("target file removed: %s" % p)
        elif p not in before:
            problems.append("target file added: %s" % p)
        elif before[p] != now[p]:
            problems.append("target file changed: %s" % p)
    return problems


def check_out(path, role, target=None):
    if not os.path.isfile(path):
        return ["output file missing: %s" % path], 0
    problems, rows = [], []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            if s.startswith(("注入の疑い", "deviations")):
                problems.append("line %d: return-value line in the file (%s)" % (i, s[:20]))
                continue
            try:
                obj = json.loads(s)
            except ValueError as e:
                problems.append("line %d: not JSON (%s)" % (i, e))
                continue
            if not isinstance(obj, dict):
                problems.append("line %d: not a JSON object" % i)
                continue
            rows.append((i, obj))
    if role == "judge":
        memo = [(i, o) for i, o in rows if o.get("st") == "memo"]
        reasons = [(i, o) for i, o in rows if "r3" in o]
        for i, o in memo:
            problems += ["line %d: missing %s" % (i, k) for k in REQUIRED["judge_memo"] if k not in o]
        for i, o in reasons:
            problems += ["line %d: missing %s" % (i, k) for k in REQUIRED["judge_reasons"] if k not in o]
            problems += type_problems(i, o, "judge_reasons")
        if {o.get("tmp") for _, o in memo} != {o.get("tmp") for _, o in reasons}:
            problems.append("memo and reasons lines cover different tmp ids")
        other = len(rows) - len(memo) - len(reasons)
        if other:
            problems.append("%d line(s) are neither memo nor reasons" % other)
    else:
        for i, o in rows:
            problems += ["line %d: missing %s" % (i, k) for k in REQUIRED[role] if k not in o]
            problems += type_problems(i, o, role)
    if role == "red" and target:
        for i, o in rows:
            problems += ["line %d: file_line %s" % (i, p) for p in beyond_eof(target, o.get("file_line"))]
    return problems, len(rows)


def beyond_eof(target, file_line):
    """file_lineの範囲の始まりが対象のファイルの行数を超える部分（終わりのはみ出しは許す）。複数ファイルを`cat -n`で連結して読むと番号が通しになる。
    区切り（`,`・`;`・` / `）は5bの`check_5b_clique.spans`と同じ形で読む"""
    out, counts = [], {}
    for cur, spec in SPAN.findall(str(file_line or "")):
        if cur not in counts:
            try:
                with open(os.path.join(target, cur), "rb") as f:
                    counts[cur] = f.read().count(b"\n") + 1
            except OSError:
                counts[cur] = None
        n = counts[cur]
        for part in re.split(r"\s*,\s*", spec):
            if n is not None and int(part.split("-")[0]) > n:
                out.append("%s:%s beyond end of file (%d lines; read one file per `cat -n`)" % (cur, part, n))
    return out


def run(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--snapshot")
    ap.add_argument("--save")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--target")
    ap.add_argument("--out")
    ap.add_argument("--role", choices=("red", "blue", "judge", "writer"))
    ap.add_argument("--schema", choices=("red", "blue", "judge", "writer"))
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.schema:
        print(schema(a.schema))
        return 0
    if a.check:
        if not (a.target and a.snapshot and a.out and a.role):
            ap.error("--check needs --target, --snapshot, --out and --role")
        problems = check_target(a.target, a.snapshot)
        out_problems, n = check_out(a.out, a.role, a.target)
        problems += out_problems
        for p in problems:
            print("NG: " + p)
        print("RESULT: %s (%s, %d line(s))" % ("NG" if problems else "OK", os.path.basename(a.out), n))
        return 1 if problems else 0
    if a.snapshot and a.save:
        files = digest(a.snapshot)
        with open(a.save, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"target": os.path.abspath(a.snapshot), "files": files}, f, ensure_ascii=False)
        print("RESULT: OK (snapshot of %d file(s))" % len(files))
        return 0
    ap.error("use --snapshot TARGET --save FILE, or --check ...")
    return 2


def self_test():
    tmp = tempfile.mkdtemp(prefix="check_handoff_")
    try:
        target = os.path.join(tmp, "target")
        os.makedirs(os.path.join(target, "src"))
        with open(os.path.join(target, "src", "a.js"), "w", encoding="utf-8") as f:
            f.write("x\n")
        snap = os.path.join(tmp, "snap.json")
        assert run(["--snapshot", target, "--save", snap]) == 0
        red = os.path.join(tmp, "red-01.jsonl")
        row = {k: "v" for k in REQUIRED["red"]}
        with open(red, "w", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        base = ["--check", "--target", target, "--snapshot", snap, "--out", red, "--role", "red"]
        assert run(base) == 0
        with open(red, "w", encoding="utf-8") as f:
            f.write(json.dumps(dict(row, file_line="src/a.js:1,src/a.js:9-12")) + "\n")
        assert run(base) == 1  # a.jsは1行（複数ファイルを連結したcat -nの通し番号）
        for fl in ("src/a.js:9-12; src/a.js:1", "src/a.js:1 / src/a.js:1,9"):  # r12の形と`;`・` / `区切り
            with open(red, "w", encoding="utf-8") as f:
                f.write(json.dumps(dict(row, file_line=fl)) + "\n")
            assert run(base) == 1, fl
        with open(red, "w", encoding="utf-8") as f:
            f.write(json.dumps(dict(row, file_line="src/a.js:1, (.gitignore 無し)")) + "\n")
        assert run(base) == 0
        with open(red, "a", encoding="utf-8") as f:
            f.write("注入の疑い: なし\n")
        assert run(base) == 1
        with open(red, "w", encoding="utf-8") as f:
            f.write(json.dumps({"file_line": "x"}) + "\n")
        assert run(base) == 1
        with open(red, "w", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        with open(os.path.join(target, "src", "b.js"), "w", encoding="utf-8") as f:
            f.write("y\n")
        assert run(base) == 1
        os.remove(os.path.join(target, "src", "b.js"))
        with open(os.path.join(target, "src", "a.js"), "w", encoding="utf-8") as f:
            f.write("changed\n")
        assert run(base) == 1
        with open(os.path.join(target, "src", "a.js"), "w", encoding="utf-8") as f:
            f.write("x\n")
        judge = os.path.join(tmp, "judge-1.jsonl")
        memo = {"tmp": "R1.1", "v3": "a", "v4": "b", "m3": {}, "st": "memo"}
        with open(judge, "w", encoding="utf-8") as f:
            f.write(json.dumps(memo) + "\n" + json.dumps({"tmp": "R1.1", "r3": {}, "r4": {}}) + "\n")
        jbase = ["--check", "--target", target, "--snapshot", snap, "--out", judge, "--role", "judge"]
        assert run(jbase) == 0
        with open(judge, "w", encoding="utf-8") as f:
            f.write(json.dumps(memo) + "\n")
        assert run(jbase) == 1
        with open(judge, "w", encoding="utf-8") as f:  # reasons行のr3が文字列
            f.write(json.dumps(memo) + "\n" + json.dumps({"tmp": "R1.1", "r3": "AV:N", "r4": {}}) + "\n")
        assert check_out(judge, "judge")[0] == ['line 2: r3 must be an object, not "AV:N" (--schema)']
        # WRITER: annot・residual を文字列で返す（r14・r15・DB run 3）とNG。配列ならOK
        writer = os.path.join(tmp, "writer-1.jsonl")
        wrow = dict({k: "v" for k in REQUIRED["writer"]}, code_ranges=["src/a.js:1"], annot=["1行目: a"], residual=[],
                    alts=[["案A", "b", "c", "d", "e", "f"]])
        for bad, want in (({}, 0), ({"annot": "- 1行目: a\n- 2行目: b"}, 1), ({"residual": "残る攻撃。"}, 1),
                          ({"code_ranges": "src/a.js:1"}, 1), ({"alts": [["案A", "b"]]}, 1), ({"annot": [["x"]]}, 1)):
            with open(writer, "w", encoding="utf-8") as f:
                f.write(json.dumps(dict(wrow, **bad), ensure_ascii=False) + "\n")
            probs = check_out(writer, "writer")[0]
            assert len(probs) == want and all("must be" in x for x in probs), (bad, probs)
        assert run(base[:-4] + ["--out", os.path.join(tmp, "none.jsonl"), "--role", "red"]) == 1
        # --schema: 必須キーは --check と同じ。writerは handoff-files.md 4節の一覧と同じ
        assert REQUIRED["blue"] == ("n", "verdict", "evidence", "fix_suggestion_check"), REQUIRED
        sj = schema("judge")
        assert "r3\trequired" in sj and "reasons line" in sj and "st\trequired" in sj, sj
        hf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "references", "core", "handoff-files.md")
        if os.path.isfile(hf):
            sec4 = open(hf, encoding="utf-8").read().split("## 4.")[1].split("## 5.")[0]
            keys = [k for k in re.findall(r"`([a-z_0-9]+)`（", sec4 + "`x`（") if k != "x"]
            keys += re.findall(r"・`([a-z_0-9]+)`", sec4)
            want = [k for k, _, _ in SCHEMA["writer"]]
            assert sorted(set(keys)) == sorted(want), (sorted(set(keys) ^ set(want)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
