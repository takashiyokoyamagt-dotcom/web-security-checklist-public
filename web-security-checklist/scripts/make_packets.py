#!/usr/bin/env python3
"""CVSS-JUDGE・WRITERに渡す入力パケットを、保存済みのファイルだけから作る（モード3。handoff-files.md）。

Usage:
  python3 make_packets.py --work WORK --target TARGET --role judge  --mask-file FILE [--batch 10] [--force]
  python3 make_packets.py --work WORK --target TARGET --role writer --mask-file FILE --idmap idmap.json [--batch 10] [--force]
  python3 make_packets.py --self-test

入力（WORK）: `out/red-NN.jsonl`・`out/blue-NN.jsonl`・`members.json`・`findings-log.jsonl`
（`aggregate_findings.py`の出力）。writerはさらに`cvss-raw-output.jsonl`・`5b-pair-table.md`と、
`--idmap`（`make_idmap.py --out-json`。構成一時IDを昇順に+で連結→5.N）。
出力: `WORK/<role>-in/batch-K.jsonl`（1項目＝JSON1行、`--batch`件ずつ。writerは最終番号順、judgeは`members.json`順）。
1項目のキー:
- 共通: `id`（作業用ID）・`tmp`（構成一時IDの昇順+連結。`cvss-decisions.jsonl`の`tmp`）・`members`
  （REDの`file_line`・`category`・`summary`・`vulnerable_code`・`root_cause`・`failure_scenario`、BLUEの`verdict`・
  `evidence`・`vulnerable_code_check`・`needs_repro`。writerはBLUEの`fix_suggestion_check`と設計の項目も。
  代表の`fix_suggestion_check.diff`が`representative_diff`と同じなら「（確定diffと同じ。省略）」にする）。
- writer: `final`（5.N）・`cvss_v3`・`cvss_v4`（`cvss-raw-output.jsonl`の主行）・`representative`（代表の構成ID:
  CONFIRMEDを先に、REDの重大度の高い順、`members.json`の順）・`representative_diff`（代表のBLUE確定diff）・
  `chain`・`same`（5b-pair-table.mdの「連鎖切断」「同一箇所」の相手の`{"n":"5.M","summary":…}`）・
  `code`（finding-final.md 5d補足の該当コード。各構成のREDの`vulnerable_code`を`file_line`のファイルで
  `locate_snippet.py`と同じ方法で照合し、一致した範囲を`{"file","start_line","end_line","chunks","code"}`で。
  一致しないものは`{"file","matched":false,"hint":…}`。WRITERが実ファイルを読んで書く）・
  `synth`（`synth-out.jsonl`があるとき。その項目の行から`work_id`・`members`を除いたもの。`fix_suggestion`が最終の修正案、
  `intent`〜`open_points`が群の新項目の最終版。WRITERに`synth-out.jsonl`を読ませなくてよい）。
秘密値は`render_findings_s56.py`と同じく、対象の設定ファイルから集めた値と`--mask-file`の値を`<マスク>`にする。
指示書の本文（役割・文体・出力キー・Arbiterの補足）はパケットに入れない。既存の出力先があれば`--force`が無い限り rc2。
判断を含まない。Stdlib only, Python 3.9+.
"""
import argparse
import glob
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_5b_clique as c5b  # noqa: E402
import check_secret_leak  # noqa: E402
import locate_snippet  # noqa: E402

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
RED_K = ("file_line", "category", "summary", "vulnerable_code", "root_cause", "failure_scenario")
BLUE_K = ("verdict", "evidence", "vulnerable_code_check", "needs_repro")
DESIGN_K = ("intent", "design_refs", "behavior_change", "compat_class", "design_conflict", "alternatives")


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(s) for s in (l.strip() for l in f) if s]


def sid(s):
    return re.sub(r"[^0-9A-Za-z.]", "", str(s))


class Masker:
    def __init__(self, target, mask_file):
        cands, _, _ = check_secret_leak.collect(target, 8)
        vals = set(cands)
        with open(mask_file, encoding="utf-8") as f:
            vals |= {l.rstrip("\n") for l in f if l.strip()}
        self.vals = sorted(vals, key=len, reverse=True)

    def __call__(self, x):
        if isinstance(x, str):
            for v in self.vals:
                x = x.replace(v, "<マスク>")
            return x
        if isinstance(x, list):
            return [self(v) for v in x]
        if isinstance(x, dict):
            return {k: self(v) for k, v in x.items()}
        return x


def load_outputs(work):
    red, blue, rids = {}, {}, {}
    for p in sorted(glob.glob(os.path.join(work, "out", "red-*.jsonl"))):
        nn = re.search(r"red-(\d+)\.jsonl$", p)
        if not nn:
            continue
        for k, r in enumerate(load_jsonl(p), 1):
            key = sid(r.get("id") or "R%s-%02d" % (nn.group(1), k))
            red[key] = r
            rids.setdefault(nn.group(1), []).append(key)
    for p in sorted(glob.glob(os.path.join(work, "out", "blue-*.jsonl"))):
        nn = re.search(r"blue-(\d+)\.jsonl$", p)
        if nn:
            ids = rids.get(nn.group(1), [])
            for b in load_jsonl(p):
                key = sid(b.get("n"))
                if key not in red and key.isdigit() and 1 <= int(key) <= len(ids):
                    key = ids[int(key) - 1]  # nをREDの行番号（1始まり）で書いた場合（aggregate_findingsと同じ）
                blue[key] = b
    return red, blue


def member(m, red, blue, writer):
    r, b = red.get(m, {}), blue.get(m, {})
    out = {"member": m}
    out.update({k: r.get(k) for k in RED_K})
    out.update({k: b.get(k) for k in BLUE_K})
    if writer:
        out["fix_suggestion_check"] = b.get("fix_suggestion_check")
        out.update({k: b.get(k, r.get(k)) for k in DESIGN_K if k in b or k in r})
    return out


SAME_DIFF = "（確定diffと同じ。省略）"


def drop_same_diff(check, diff):
    """BLUEの`fix_suggestion_check`の`diff`が確定diffと同じなら、その欄だけ省略の印にする（情報は失わない）"""
    if isinstance(check, dict) and diff and str(check.get("diff") or "").strip() == str(diff).strip():
        return {**check, "diff": SAME_DIFF}
    return check


def representative(ms, log):
    """代表の構成ID: CONFIRMEDを先に、REDの重大度の高い順、`members.json`の順。"""
    return sorted(ms, key=lambda m: (0 if log[m]["verdict"] == "CONFIRMED" else 1,
                                     SEV.get(str(log[m].get("severity", "")).lower(), 9), ms.index(m)))[0]


def read_lines(target, rel):
    try:
        return locate_snippet.read_target(target, rel)
    except Exception:  # noqa: BLE001  （repoの外・読めない）
        return None


# REDの`vulnerable_code`の、ファイルごとの見出し行（`routes/a.js:`・`--- db.js:9-14 ---`・`// server.js:12`等）
FILE_HEAD = re.compile(r"^\s*(?:-{2,}\s*|//\s*)?(\.?[\w./-]+\.[A-Za-z0-9]+)\s*(?:[:：]\s*([\d,\-\s/]*))?"
                       r"(?:（[^）]*）)?\s*[:：]?\s*(?:-{2,})?\s*$")


def sections(code):
    """[(ファイル or None, 見出しの行番号 or None, 断片)]。見出し行が無ければ全体を1つ"""
    out, cur, hint, buf = [], None, None, []
    for ln in code.split("\n"):
        m = FILE_HEAD.match(ln)
        if m:
            if any(x.strip() for x in buf):
                out.append((cur, hint, "\n".join(buf)))
            n = re.match(r"\d+", (m.group(2) or "").strip())
            f = m.group(1)
            cur, hint, buf = (f[2:] if f.startswith("./") else f), (int(n.group()) if n else None), []
        else:
            buf.append(ln)
    if any(x.strip() for x in buf):
        out.append((cur, hint, "\n".join(buf)))
    return out


def code_packets(target, rows):
    """5d補足の該当コード。断片（見出し行で分けたもの）ごとに、見出しのファイル（無ければ`file_line`の
    ファイルを順に）で照合する。照合できない断片は`matched:false`で1件だけ示す"""
    out, seen = [], set()
    for r in rows:
        sp = c5b.spans(r.get("file_line"))
        listed = list(sp) or re.findall(r"([\w./-]+\.[A-Za-z0-9]+)", str(r.get("file_line") or ""))[:1]
        for sf, shint, code in sections(r.get("vulnerable_code") or ""):
            files = [sf] if sf else listed
            found = None
            for f in files:
                lines = read_lines(target, f)
                if lines is None:
                    continue
                hint = shint or (min(sp[f]) if f in sp else None)
                res = locate_snippet.locate(lines, code, hint) if code.strip() else {"matched": False}
                if res.get("matched"):
                    found = (f, res, lines)
                    break
            if found:
                f, res, lines = found
                key = (f, res["start_line"], res["end_line"])
                if key not in seen:
                    seen.add(key)
                    out.append({"file": f, "start_line": res["start_line"], "end_line": res["end_line"],
                                "chunks": res["chunks"],
                                "code": "\n".join(lines[res["start_line"] - 1:res["end_line"]])})
            elif files:
                key = (files[0], "unmatched", r.get("file_line"))
                if key not in seen:
                    seen.add(key)
                    out.append({"file": files[0], "matched": False, "hint": r.get("file_line")})
    return out


def partners(work, unit_of, idmap_n, summary_of):
    chain, same = {}, {}
    path = os.path.join(work, "5b-pair-table.md")
    if not os.path.exists(path):
        return chain, same
    with open(path, encoding="utf-8") as f:
        for line in f:
            c = [x.strip() for x in line.strip().strip("|").split("|")]
            if len(c) < 3 or "-" not in c[0]:
                continue
            j = c[2]
            tgt = chain if j == "連鎖切断" else same if j == "同一箇所" else None
            a, _, b = c[0].partition("-")
            if tgt is None or a not in unit_of or b not in unit_of or unit_of[a] == unit_of[b]:
                continue
            ua, ub = unit_of[a], unit_of[b]
            tgt.setdefault(ua, set()).add(ub)
            tgt.setdefault(ub, set()).add(ua)

    def fmt(d):
        return {u: sorted(({"n": idmap_n[v], "summary": summary_of[v]} for v in vs),
                          key=lambda x: int(x["n"].split(".")[1])) for u, vs in d.items()}
    return fmt(chain), fmt(same)


def build(work, target, role, mask_file, idmap=None, batch=10):
    mask = Masker(target, mask_file)
    red, blue = load_outputs(work)
    with open(os.path.join(work, "members.json"), encoding="utf-8") as f:
        members = json.load(f)
    log = {r["tmp_id"]: r for r in load_jsonl(os.path.join(work, "findings-log.jsonl"))}
    problems = ["%s: not in out/red-*.jsonl" % m for ms in members.values() for m in ms if m not in red]
    problems += ["%s: not in out/blue-*.jsonl" % m for ms in members.values() for m in ms if m not in blue]
    if problems:
        return None, problems
    items = []
    if role == "judge":
        for u, ms in members.items():
            items.append({"id": u, "tmp": "+".join(sorted(ms)), "members": [member(m, red, blue, False) for m in ms]})
    else:
        with open(idmap, encoding="utf-8") as f:
            tmp_n = json.load(f)
        idmap_n = {u: tmp_n.get("+".join(sorted(ms))) for u, ms in members.items()}
        problems += ["%s: no final number in --idmap" % u for u, n in idmap_n.items() if not n]
        raw = {}
        for r in load_jsonl(os.path.join(work, "cvss-raw-output.jsonl")):
            if r.get("kind") != "alt":
                raw[r["id"]] = r["raw"]

        sp = os.path.join(work, "synth-out.jsonl")
        synth = {r.get("work_id"): r for r in load_jsonl(sp)} if os.path.isfile(sp) else {}
        reps = {u: representative(ms, log) for u, ms in members.items()}
        unit_of = {m: u for u, ms in members.items() for m in ms}
        chain, same = partners(work, unit_of, idmap_n, {u: red[reps[u]].get("summary") for u in members})
        for u, ms in members.items():
            tmp = "+".join(sorted(ms))
            rr = raw.get(tmp)
            if rr is None:
                problems.append("%s: no main row in cvss-raw-output.jsonl" % tmp)
                continue
            rows = [red[m] for m in ms]
            items.append({"id": u, "final": idmap_n[u], "tmp": tmp,
                          "verdict": "CONFIRMED" if any(log[m]["verdict"] == "CONFIRMED" for m in ms) else "PLAUSIBLE",
                          "cvss_v3": {k: rr.get("v3", {}).get(k) for k in ("base_score", "base_severity", "vector")},
                          "cvss_v4": {k: rr.get("v4", {}).get(k) for k in ("score", "severity", "vector")},
                          "representative": reps[u], "representative_diff": log[reps[u]].get("diff"),
                          "chain": chain.get(u, []), "same": same.get(u, []), "code": code_packets(target, rows),
                          "members": [member(m, red, blue, True) for m in ms]})
            if u in synth:  # 5c補足3: SYNTHの戻り値（最終の修正案と新項目）。WRITERに synth-out.jsonl を読ませない
                items[-1]["synth"] = {k: v for k, v in synth[u].items() if k not in ("work_id", "members")}
            rep = next(x for x in items[-1]["members"] if x["member"] == reps[u])
            rep["fix_suggestion_check"] = drop_same_diff(rep.get("fix_suggestion_check"), log[reps[u]].get("diff"))
        if problems:
            return None, problems
        items.sort(key=lambda x: int(x["final"].split(".")[1]))
    batches = [items[i:i + batch] for i in range(0, len(items), batch)]
    return [mask(b) for b in batches], []


def run(work, target, role, mask_file, idmap=None, batch=10, force=False):
    outdir = os.path.join(work, "%s-in" % role)
    if os.path.exists(outdir) and os.listdir(outdir) and not force:
        print("error: %s already exists (use --force)" % outdir)
        return 2
    batches, problems = build(work, target, role, mask_file, idmap, batch)
    if problems:
        for p in problems:
            print("NG: " + p)
        print("RESULT: NG (nothing written)")
        return 1
    os.makedirs(outdir, exist_ok=True)
    for old in glob.glob(os.path.join(outdir, "batch-*.jsonl")):
        os.remove(old)
    for k, b in enumerate(batches, 1):
        with open(os.path.join(outdir, "batch-%d.jsonl" % k), "w", encoding="utf-8", newline="\n") as f:
            f.write("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in b))
        print("%s-in/batch-%d.jsonl: %s" % (role, k, ",".join(x["id"] for x in b)))
    if role == "writer":
        um = sum(1 for b in batches for x in b for c in x["code"] if c.get("matched") is False)
        print("code packets not located (WRITER reads the file): %d" % um)
    return 0


def self_test():
    with tempfile.TemporaryDirectory() as d:
        tgt, work = os.path.join(d, "app"), os.path.join(d, "work")
        os.makedirs(os.path.join(tgt, "routes"))
        os.makedirs(os.path.join(work, "out"))
        with open(os.path.join(tgt, "routes", "a.js"), "w", encoding="utf-8") as f:
            f.write("const a = 1;\nfunction q(x) {\n  return db.all(`SELECT ${x}`);\n}\n")
        with open(os.path.join(tgt, "config.js"), "w", encoding="utf-8") as f:
            f.write("module.exports = { jwtSecret: 'super-secret-value-123' };\n")
        mf = os.path.join(d, "mask.txt")
        with open(mf, "w", encoding="utf-8") as f:
            f.write("")

        def put(name, rows):
            with open(os.path.join(work, name), "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
        red = [{"id": "R01-01", "file_line": "routes/a.js:3", "category": "x CWE-89", "severity": "Critical",
                "summary": "SQLi", "vulnerable_code": "function q(x) {\n  return db.all(`SELECT ${x}`);",
                "root_cause": "r", "failure_scenario": "f", "fix_suggestion": "-"},
               {"id": "R01-02", "file_line": "config.js:1", "category": "y CWE-798", "severity": "High",
                "summary": "secret super-secret-value-123", "vulnerable_code": "nope", "root_cause": "r",
                "failure_scenario": "f", "fix_suggestion": "-"}]
        blue = [{"n": "R01-01", "verdict": "CONFIRMED", "evidence": "e",
                 "fix_suggestion_check": {"result": "合格", "diff": "d1\n"}},
                {"n": 2, "verdict": "PLAUSIBLE", "evidence": "e", "fix_suggestion_check": "ok"}]  # 整数のn＝REDの行番号
        put("out/red-01.jsonl", red)
        put("out/blue-01.jsonl", blue)
        put("findings-log.jsonl", [{"tmp_id": "R0101", "verdict": "CONFIRMED", "severity": "Critical", "diff": "d1"},
                                   {"tmp_id": "R0102", "verdict": "PLAUSIBLE", "severity": "High", "diff": "d2"}])
        with open(os.path.join(work, "members.json"), "w", encoding="utf-8") as f:
            json.dump({"F1": ["R0101"], "F2": ["R0102"]}, f)
        with open(os.path.join(work, "5b-pair-table.md"), "w", encoding="utf-8") as f:
            f.write("| ペア | 共有CWE | 判定 |\n| --- | --- | --- |\n| R0101-R0102 | CWE-20 | 連鎖切断 |\n")
        put("cvss-raw-output.jsonl", [{"id": t, "raw": {"v3": {"base_score": 9.8, "base_severity": "CRITICAL", "vector": "v"},
                                                        "v4": {"score": 9.3, "severity": "Critical", "vector": "w"}}}
                                      for t in ("R0101", "R0102")])
        idm = os.path.join(work, "idmap.json")
        with open(idm, "w", encoding="utf-8") as f:
            json.dump({"R0101": "5.2", "R0102": "5.1"}, f)
        import io
        old, sys.stdout = sys.stdout, io.StringIO()
        try:
            assert run(work, tgt, "judge", mf, batch=1) == 0
            assert run(work, tgt, "judge", mf) == 2
            assert run(work, tgt, "writer", mf, idm) == 0
            assert "synth" not in load_jsonl(os.path.join(work, "writer-in", "batch-1.jsonl"))[0]  # synth-out無し
            put("synth-out.jsonl", [{"work_id": "F1", "members": ["R0101"], "fix_suggestion": "fd super-secret-value-123",
                                     "intent": "i", "open_points": ["o"]}])
            assert run(work, tgt, "writer", mf, idm, force=True) == 0
        finally:
            sys.stdout = old
        j = load_jsonl(os.path.join(work, "judge-in", "batch-2.jsonl"))
        assert j[0]["id"] == "F2" and j[0]["tmp"] == "R0102" and "<マスク>" in j[0]["members"][0]["summary"], j
        w = load_jsonl(os.path.join(work, "writer-in", "batch-1.jsonl"))
        assert [x["final"] for x in w] == ["5.1", "5.2"], w
        x = w[1]
        assert x["chain"] == [{"n": "5.1", "summary": "secret <マスク>"}] and x["representative"] == "R0101", x
        assert x["code"][0]["start_line"] == 2 and x["code"][0]["end_line"] == 3, x["code"]
        assert w[0]["code"][0]["matched"] is False, w[0]["code"]
        assert x["synth"] == {"fix_suggestion": "fd <マスク>", "intent": "i", "open_points": ["o"]} and "synth" not in w[0], x
        assert "super-secret" not in json.dumps(w, ensure_ascii=False)
        # 代表のBLUE検証欄のdiffがrepresentative_diffと同じなら省略の印。他の欄は残す
        assert x["members"][0]["fix_suggestion_check"] == {"result": "合格", "diff": SAME_DIFF}, x["members"]
        assert drop_same_diff({"diff": "other"}, "d1") == {"diff": "other"} and drop_same_diff("ok", "d1") == "ok"
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work")
    ap.add_argument("--target")
    ap.add_argument("--role", choices=("judge", "writer"))
    ap.add_argument("--mask-file")
    ap.add_argument("--idmap")
    ap.add_argument("--batch", type=int, default=10)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.work and a.target and a.role and a.mask_file) or (a.role == "writer" and not a.idmap) or a.batch < 1:
        ap.error("--work, --target, --role and --mask-file are required (writer also --idmap); --batch >= 1")
    return run(a.work, a.target, a.role, a.mask_file, a.idmap, a.batch, a.force)


if __name__ == "__main__":
    sys.exit(main())
