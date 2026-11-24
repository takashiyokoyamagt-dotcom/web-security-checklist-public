#!/usr/bin/env python3
"""findings.jsonl と sources.json を保存済みのファイルだけから作る（モード3。handoff-files.md 5節）。

Usage:
  python3 build_findings.py --work WORK --sources sources-in.json
      [--integrated 5c/integrated.diff --base F1 --base-audit audit.json [--not-merged F7,F9]] [--force]
  python3 build_findings.py --self-test

入力（WORK）: `members.json`・`final.json`・`findings-log.jsonl`・`cvss-decisions.jsonl`（有効行が確定行）・
`cvss-raw-output.jsonl`・`out/judge-K.jsonl`（reasons行。同じ`tmp`は後のファイルが優先: judge-3b は judge-3 の後）・
`out/writer-K.jsonl`・`5b-pair-table.md`・（あれば）`epss-kev.json`。
`--sources`: 5aの出典タグ（判断を含むのでArbiterが書く）。`{"F1":[{"type":"IPA","citation":"1章 SQLインジェクション"},…]}`。
  typeは`IPA`・`OWASP_ASVS`・`OWASP_CheatSheet`・`ISM`（DB項目の根拠のISM管理策。citationは`ISM-1277`等）・`SCA`。`CWE`（旧名`CWE_Top25`）は書かない（確定行の`cwe`のうち
  `references/sources/cwe-top25.md`の表にある番号をスクリプトが付ける。入力にあれば捨ててWARN）。全項目のキーが必要（空配列可）。
`--integrated`・`--base`: 5cの合成diffと、それを置く(a)の指摘の作業ID（最終番号5.Nも可）。`--base-audit`はその指摘の
  `audit`（`{"method","verdict","evidence"}`。Arbiterが統合diffの確認結果で書く）。`--not-merged`は合成に取り込んで
  いない指摘（注記を付けない）。`--base`が無ければ全指摘がBLUEの確定diffで、注記は付けない。
キーと出どころ: `n`・`key`・`members`・`severity`（確定行の`band`）・`verdict`・`unused`・`files`（WRITERの`code_ranges`）・
`categories`・`cwe`・`cwe_note`・`references`・`exploit_status`は集約と確定行、`cvss_v3`・`cvss_v4`は主行（区分は計算どおり。0.0はNoneで、Lowにするのは`severity`だけ）、`cvss_reasons`は
reasons行、`short_summary`・`summary_line`・`body`・`compat`・`design`・`audit`・`review`はWRITER、`xref`はペア表。`fix.diff`は、5c補足3でSYNTHが書いた`synth/<担当>/<work_id>/group.diff`があればそれ（群の合成diff。`source`は`synth`）、
無ければ代表（`make_packets.py`と同じ選び方）のBLUE確定diff（`prepare`の自動作成`synth/auto/`は同じ内容なので見ない）。
`exploit_status`は`SCA`タグを持つ指摘だけ、`epss-kev.json`の勧告のうちその指摘の構成のREDの概要・diffと
WRITERの`summary`・`tech`に勧告IDかCVEが出るもの（SCAの指摘が1件で、どれも出なければ全勧告）から作る。
WRITERの`code_ranges`・`annot`・`residual`（文字列の配列）と`alts`（行の配列）が文字列等で来たら、改行で分けてWARN
（render_findings_s56.as_lists。1文字ずつの箇条にしない）。
出力: `WORK/findings.jsonl`（5.N順）・`WORK/sources.json`（`{"5.N":[タグ…]}`。出典別レポート用）。
既存なら`--force`が無い限りrc2。NGがあれば何も書かずrc1。判断を含まない。Stdlib only, Python 3.9+.
"""
import argparse
import glob
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from make_packets import representative  # noqa: E402
from render_findings_s56 import as_lists  # noqa: E402

TYPES = ("IPA", "OWASP_ASVS", "OWASP_CheatSheet", "ISM", "SCA")
WRITER_K = ("id", "short_summary", "summary", "plain", "tech", "code_ranges", "annot", "scenario", "fix_expl",
            "residual", "intent", "behavior", "compat", "design_conflict", "design_refs", "audit_method",
            "audit_verdict", "audit_evidence")
BODY_K = ("summary", "plain", "tech", "code_ranges", "annot", "scenario", "fix_expl", "residual", "intent", "behavior")
COMPAT = ("①", "②", "③", "②③", "①③")  # render_findings_s56.py COMPAT_LABEL（①③は5b補足3の和集合）
NOTE = "(%sの修正案に統合済み。本diffは単独で適用する場合の参考)"
DROP = ("diff --git", "index ", "new file mode")


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(s) for s in (l.strip() for l in f) if s]


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cwe_table(path=None):
    path = path or os.path.join(HERE, "..", "references", "sources", "cwe-top25.md")
    with open(path, encoding="utf-8") as f:
        return {int(m.group(1)) for m in re.finditer(r"^\| CWE-(\d+) \|", f.read(), re.M)}


def batch_key(p):
    m = re.search(r"-(\d+)([a-z]*)\.jsonl$", p)
    return (int(m.group(1)), m.group(2)) if m else (10 ** 9, p)


def ref_str(s):
    t, c = s["type"], s["citation"]
    return {"IPA": "IPA " + c, "OWASP_ASVS": "OWASP ASVS " + c, "OWASP_CheatSheet": 'OWASP Cheat Sheet "%s"' % c, "ISM": c,
            "SCA": "SCA: " + c}.get(t, c)


def pairs(path, unit_of, num):
    chain, same = {}, {}
    if not os.path.exists(path):
        return chain, same
    with open(path, encoding="utf-8") as f:
        for line in f:
            c = [x.strip() for x in line.strip().strip("|").split("|")]
            if len(c) < 3 or not re.fullmatch(r"[0-9A-Za-z.]+-[0-9A-Za-z.]+", c[0]):
                continue
            tgt = chain if c[2] == "連鎖切断" else same if c[2] == "同一箇所" else None
            a, b = c[0].split("-")
            if tgt is None or a not in unit_of or b not in unit_of or unit_of[a] == unit_of[b]:
                continue
            ua, ub = unit_of[a], unit_of[b]
            tgt.setdefault(ua, set()).add(num[ub])
            tgt.setdefault(ub, set()).add(num[ua])
    return chain, same


def exploit_status(entries):
    if not entries:
        return None
    ids = "、".join(e["id"] for e in entries)
    items = [it for e in entries for it in e.get("items") or []]
    vals = [(it["epss"], it["cve"]) for it in items if isinstance(it.get("epss"), (int, float))]
    if vals:
        best = max(vals)
        epss = "%.5f（%s）" % best
    else:
        errs = sorted({str(it.get("epss_error") or e.get("error")) for e in entries for it in e.get("items") or []
                       if it.get("epss_status") not in ("ok", "not_found")})
        epss = "未取得（%s）" % "、".join(errs) if errs else "該当なし"
    kev = sorted({it["cve"] for it in items if it.get("kev")})
    return "対象: %s。最大EPSS %s、KEV掲載 %d件%s。詳細は8節" % (ids, epss, len(kev), "（%s）" % "、".join(kev) if kev else "")


def build(work, sources, integrated=None, base=None, base_audit=None, not_merged=(), table=None):
    ng, warn = [], []
    J = lambda n: os.path.join(work, n)  # noqa: E731
    members, final = load_json(J("members.json")), load_json(J("final.json"))
    log = {r["tmp_id"]: r for r in load_jsonl(J("findings-log.jsonl"))}
    dec = {}
    for o in load_jsonl(J("cvss-decisions.jsonl")):
        if o.get("tmp") is not None and (o["tmp"] not in dec or o.get("rev", 0) >= dec[o["tmp"]].get("rev", 0)):
            dec[o["tmp"]] = o
    raw = {r["id"]: r["raw"] for r in load_jsonl(J("cvss-raw-output.jsonl")) if r.get("kind") != "alt"}
    reasons = {}
    for p in sorted(glob.glob(J(os.path.join("out", "judge-*.jsonl"))), key=batch_key):
        for o in load_jsonl(p):
            if "r3" in o:
                reasons[o["tmp"]] = {"r3": o["r3"], "r4": o.get("r4")}
    writer = {}
    for p in sorted(glob.glob(J(os.path.join("out", "writer-*.jsonl"))), key=batch_key):
        for o in load_jsonl(p):
            writer[o.get("id")] = o
    ek = load_json(J("epss-kev.json")).get("entries", []) if os.path.exists(J("epss-kev.json")) else []
    top = table if table is not None else cwe_table()
    num = {}
    for u in members:
        m = re.fullmatch(r"5\.(\d+)", str(final.get(u, "")))
        if m:
            num[u] = int(m.group(1))
        else:
            ng.append("%s: no final number in final.json" % u)
    if base is not None and base not in members:
        by_final = [u for u in members if str(final.get(u)) == str(base)]
        if len(by_final) == 1:
            base = by_final[0]  # 最終番号（5.N）で渡された場合
        else:
            ng.append("--base %s: not in members.json" % base)
            return [], {}, ng, warn
    if base is not None and not (integrated and base_audit):
        ng.append("--base needs --integrated and --base-audit")
    ng += ["--not-merged %s: not in members.json" % u for u in not_merged if u not in members]
    synth = {}  # SYNTHが書いた group.diff（synth/<担当>/<work_id>/。prepareの自動作成 synth/auto/ は除く）
    for p in glob.glob(J(os.path.join("synth", "**", "group.diff")), recursive=True):
        parts = os.path.relpath(p, J("synth")).split(os.sep)
        if parts[0] != "auto":
            synth.setdefault(parts[-2], []).append(p)
    unit_of = {m: u for u, ms in members.items() for m in ms}
    chain, same = pairs(J("5b-pair-table.md"), unit_of, num) if not ng else ({}, {})
    recs, srcs = [], {}
    for u, ms in members.items():
        tmp = "+".join(sorted(ms))
        d, rr, w = dec.get(tmp), raw.get(tmp), writer.get(u)
        miss = [n for n, x in (("final row in cvss-decisions.jsonl", d and d.get("st") == "final"),
                               ("main row in cvss-raw-output.jsonl", rr), ("reasons row in out/judge-*.jsonl", tmp in reasons),
                               ("row in out/writer-*.jsonl", w), ("key in --sources", u in sources)) if not x]
        miss += ["%s in findings-log.jsonl" % m for m in ms if m not in log]
        if w:
            miss += ["writer key %s" % k for k in WRITER_K if k not in w]
        if miss or u not in num:
            ng += ["%s (%s): no %s" % (u, tmp, x) for x in miss]
            continue
        warn += ["writer " + x for x in as_lists(w, u)]  # 文字列のannot・residual等（check_handoff.pyではNG）を行で分ける
        tags = []
        for s in sources[u]:
            if s.get("type") in ("CWE", "CWE_Top25"):
                warn.append("%s: %s tag in --sources ignored (added from cwe-top25.md)" % (u, s["type"]))
            elif s.get("type") not in TYPES or not s.get("citation"):
                ng.append("%s: bad source tag %s" % (u, json.dumps(s, ensure_ascii=False)))
            elif {"type": s["type"], "citation": s["citation"]} not in tags:
                tags.append({"type": s["type"], "citation": s["citation"]})
        cw = sorted({int(x.split("-")[1]) for x in d.get("cwe") or [] if re.fullmatch(r"CWE-\d+", str(x))})
        tags = ([s for s in tags if s["type"] != "SCA"] + [{"type": "CWE", "citation": "CWE-%d" % c} for c in cw if c in top]
                + [s for s in tags if s["type"] == "SCA"])
        if w["compat"] not in COMPAT:
            ng.append("%s: writer compat %r is not one of %s" % (u, w["compat"], "・".join(COMPAT)))
        n = num[u]
        srcs["5.%d" % n] = tags
        rep = representative(ms, log)
        if u == base:
            with open(integrated, encoding="utf-8") as f:
                body = "\n".join(l for l in f.read().split("\n") if not l.startswith(DROP))
            fix = {"diff": body.rstrip("\n"), "note": "", "source": "integrated"}
            audit = load_json(base_audit)
            if not all(audit.get(k) for k in ("method", "verdict", "evidence")):
                ng.append("--base-audit: method/verdict/evidence required")
        else:
            note = NOTE % ("5.%d" % num[base]) if base is not None and u not in not_merged else ""
            fix = {"diff": (log[rep].get("diff") or "").rstrip("\n"), "note": note, "source": "blue"}
            sp = synth.get(u, [])
            if len(sp) > 1:
                ng.append("%s: several SYNTH group.diff (%s)" % (u, ", ".join(sp)))
            elif sp:
                with open(sp[0], encoding="utf-8") as f:
                    body = "\n".join(l for l in f.read().split("\n") if not l.startswith(DROP))
                fix = {"diff": body.rstrip("\n"), "note": note, "source": "synth"}
            audit = {"method": w["audit_method"], "verdict": w["audit_verdict"], "evidence": w["audit_evidence"]}
        files = []
        for cr in w["code_ranges"]:
            f, _, lines = str(cr).rpartition(":")
            files.append({"file": f, "lines": lines})
        rec = {"n": n, "key": u, "members": sorted(ms), "severity": d["band"],
               "verdict": "CONFIRMED" if any(log[m]["verdict"] == "CONFIRMED" for m in ms) else "PLAUSIBLE",
               "unused": bool(d.get("unused", False)), "files": files,
               "categories": [c.strip() for c in re.split("[、,]", d.get("cat") or "") if c.strip()],
               "cwe": ["CWE-%d" % c for c in cw], "references": [ref_str(s) for s in tags], "exploit_status": None,
               "cvss_v3": {"score": rr["v3"]["base_score"], "severity": rr["v3"]["base_severity"], "vector": rr["v3"]["vector"]},
               "cvss_v4": {"score": rr["v4"]["score"], "severity": rr["v4"]["severity"], "vector": rr["v4"]["vector"]},
               "cvss_reasons": reasons[tmp], "short_summary": w["short_summary"], "summary_line": w["summary"],
               "body": dict({k: w[k] for k in BODY_K}, alts=w.get("alts") or [], alts_note=w.get("alts_note", "")),
               "compat": {"classes": w["compat"], "note": w.get("compat_note", "")},
               "design": {"conflict": w["design_conflict"] == "有り", "refs_note": w["design_refs"]},
               "audit": audit, "fix": fix, "review": w.get("review", ""),
               "xref": {"chain": sorted(chain.get(u, ())), "same": sorted(same.get(u, ()))}}
        if d.get("cwe_note"):
            rec["cwe_note"] = d["cwe_note"]
        recs.append(rec)
    sca = [r for r in recs if any(s["type"] == "SCA" for s in srcs["5.%d" % r["n"]])]
    for r in sca:
        text = " ".join([log[m].get("summary") or "" for m in r["members"]] + [log[m].get("diff") or "" for m in r["members"]]
                        + [r["summary_line"], r["body"]["tech"]])
        hit = [e for e in ek if e["id"] in text or any(c in text for c in e.get("cves") or [])]
        if not hit and len(sca) == 1:
            hit = ek
        r["exploit_status"] = exploit_status(hit)
        if ek and not hit:
            warn.append("5.%d: SCA tag but no advisory of epss-kev.json found in its text (exploit_status null)" % r["n"])
    recs.sort(key=lambda r: r["n"])
    return recs, srcs, ng, warn


def run(work, sources_path, integrated=None, base=None, base_audit=None, not_merged=(), force=False):
    outs = [os.path.join(work, n) for n in ("findings.jsonl", "sources.json")]
    if any(os.path.exists(p) for p in outs) and not force:
        print("error: findings.jsonl or sources.json already exists (use --force)")
        return 2
    recs, srcs, ng, warn = build(work, load_json(sources_path), integrated, base, base_audit, not_merged)
    for x in warn:
        print("WARN: " + x)
    for x in ng:
        print("NG: " + x)
    if ng:
        return 1
    with open(outs[0], "w", encoding="utf-8", newline="\n") as f:
        f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in recs)
    with open(outs[1], "w", encoding="utf-8", newline="\n") as f:
        json.dump(srcs, f, ensure_ascii=False, indent=1)
        f.write("\n")
    cnt = {}
    for r in recs:
        cnt[r["severity"]] = cnt.get(r["severity"], 0) + 1
    print("findings.jsonl: %d record(s) %s; sources.json written" % (len(recs), json.dumps(cnt, ensure_ascii=False)))
    return 0


def self_test():
    def wj(path, rows):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)

    with tempfile.TemporaryDirectory() as d:
        J = lambda n: os.path.join(d, n)  # noqa: E731
        with open(J("members.json"), "w", encoding="utf-8") as f:
            json.dump({"F1": ["A1", "B1"], "F2": ["C1"]}, f)
        with open(J("final.json"), "w", encoding="utf-8") as f:
            json.dump({"F1": "5.1", "F2": "5.2"}, f)
        wj(J("findings-log.jsonl"), [
            {"tmp_id": "A1", "verdict": "PLAUSIBLE", "severity": "high", "summary": "s", "diff": "--- a\n+++ b\n-x\n+y\n"},
            {"tmp_id": "B1", "verdict": "CONFIRMED", "severity": "low", "summary": "t", "diff": "--- a\n+++ b\n-p\n+q\n"},
            {"tmp_id": "C1", "verdict": "CONFIRMED", "severity": "medium", "summary": "lodash GHSA-aaaa-bbbb-cccc", "diff": ""}])
        wj(J("cvss-decisions.jsonl"), [
            {"tmp": "A1+B1", "st": "memo", "rev": 1, "cwe": ["CWE-89"]},
            {"tmp": "A1+B1", "st": "final", "rev": 2, "band": "High", "cat": "入力値検証、データベース", "cwe": ["CWE-89", "CWE-1321"]},
            {"tmp": "C1", "st": "final", "rev": 2, "band": "Low", "cat": "依存関係管理", "cwe": ["CWE-1104"]}])
        v = {"v3": {"base_score": 7.5, "base_severity": "High", "vector": "CVSS:3.1/x"},
             "v4": {"score": 8.7, "severity": "High", "vector": "CVSS:4.0/x"}}
        v0 = {"v3": {"base_score": 0.0, "base_severity": "None", "vector": "CVSS:3.1/z"},
              "v4": {"score": 0.0, "severity": "None", "vector": "CVSS:4.0/z"}}
        wj(J("cvss-raw-output.jsonl"), [{"id": "A1+B1", "raw": v}, {"id": "A1+B1", "kind": "alt", "of": "AC", "raw": {}},
                                        {"id": "C1", "raw": v0}])
        wj(J("out/judge-1.jsonl"), [{"tmp": "A1+B1", "r3": {"AV": "old"}, "r4": {}}, {"tmp": "C1", "r3": {"AV": "c"}, "r4": {}}])
        wj(J("out/judge-1b.jsonl"), [{"tmp": "A1+B1", "r3": {"AV": "new"}, "r4": {}}])
        w = {k: "x" for k in WRITER_K}
        w.update(code_ranges=["db.js:3-5"], annot=[], residual=[], compat="①", design_conflict="無し")
        wj(J("out/writer-1.jsonl"), [dict(w, id="F1"), dict(w, id="F2", code_ranges=["package.json:7"])])
        with open(J("5b-pair-table.md"), "w", encoding="utf-8") as f:
            f.write("| ペア | 共有CWE | 判定 | 注記 |\n| --- | --- | --- | --- |\n| A1-B1 | 89 | 統合 | |\n"
                    "| B1-C1 | 20 | 連鎖切断 | |\n")
        with open(J("epss-kev.json"), "w", encoding="utf-8") as f:
            json.dump({"entries": [{"id": "GHSA-aaaa-bbbb-cccc", "cves": ["CVE-1"], "items": [
                {"cve": "CVE-1", "epss": 0.5, "epss_status": "ok", "kev": True}]},
                {"id": "GHSA-zzzz-zzzz-zzzz", "cves": ["CVE-2"], "items": [{"cve": "CVE-2", "epss": 0.9, "kev": False}]}]}, f)
        src = {"F1": [{"type": "IPA", "citation": "1章 SQLインジェクション"}, {"type": "CWE_Top25", "citation": "CWE-1"}],
               "F2": [{"type": "SCA", "citation": "npm audit"}]}
        recs, srcs, ng, warn = build(d, src, table={89, 1104})
        assert not ng, ng
        assert len(warn) == 1 and "CWE_Top25" in warn[0], warn
        # WRITERが annot・residual を文字列で返した（r14・r15・DB run 3）: 行で分けてWARN。1文字ずつにしない
        wj(J("out/writer-2.jsonl"), [dict(w, id="F2", code_ranges="package.json:7", annot="- 7行目: a\n\n- 8行目: b",
                                          residual="残る攻撃は1文。")])
        recs_s, _, ng_s, warn_s = build(d, src, table={89, 1104})
        b2 = recs_s[1]["body"]
        assert not ng_s and b2["annot"] == ["7行目: a", "8行目: b"] and b2["residual"] == ["残る攻撃は1文。"], b2
        assert recs_s[1]["files"] == [{"file": "package.json", "lines": "7"}], recs_s[1]["files"]
        assert sum("is a string" in x for x in warn_s) == 3, warn_s
        os.remove(J("out/writer-2.jsonl"))
        r1, r2 = recs
        # 0.0: 重大度（帯）はLow、スコア欄の区分は計算どおりNone（cvss-scoring.md）
        assert r2["severity"] == "Low" and r2["cvss_v3"]["severity"] == "None" and r2["cvss_v4"]["severity"] == "None", r2
        assert r1["verdict"] == "CONFIRMED" and r1["fix"]["diff"].endswith("+q") and r1["fix"]["note"] == "", r1["fix"]
        # 5c補足3: SYNTHの群diffがあれば群の推奨diffにする（prepareの自動作成 synth/auto/ は見ない）
        for sub, body in ((os.path.join("K1", "F1"), "diff --git a/db.js b/db.js\n--- a/db.js\n+++ b/db.js\n@@ -1 +1 @@\n-x\n+s\n"),
                          (os.path.join("auto", "F2"), "--- a/p\n+++ b/p\n@@ -1 +1 @@\n-a\n+AUTO\n")):
            os.makedirs(J(os.path.join("synth", sub)))
            with open(J(os.path.join("synth", sub, "group.diff")), "w", encoding="utf-8") as f:
                f.write(body)
        recs2, _, ng, _ = build(d, src, table={89, 1104})
        assert not ng and recs2[0]["fix"] == {"diff": "--- a/db.js\n+++ b/db.js\n@@ -1 +1 @@\n-x\n+s", "note": "",
                                              "source": "synth"}, recs2[0]["fix"]
        assert recs2[1]["fix"]["source"] == "blue" and "AUTO" not in recs2[1]["fix"]["diff"], recs2[1]["fix"]
        os.makedirs(J(os.path.join("synth", "K2", "F1")))
        with open(J(os.path.join("synth", "K2", "F1", "group.diff")), "w", encoding="utf-8") as f:
            f.write("x\n")
        assert any("several SYNTH group.diff" in x for x in build(d, src, table={89, 1104})[2])
        shutil.rmtree(J("synth"))
        assert r1["cvss_reasons"]["r3"]["AV"] == "new" and r1["cwe"] == ["CWE-89", "CWE-1321"], r1
        assert r1["references"] == ["IPA 1章 SQLインジェクション", "CWE-89"], r1["references"]
        assert r1["xref"] == {"chain": [2], "same": []} and r2["xref"]["chain"] == [1]
        assert r2["exploit_status"] == "対象: GHSA-aaaa-bbbb-cccc。最大EPSS 0.50000（CVE-1）、KEV掲載 1件（CVE-1）。詳細は8節", r2
        assert r1["files"] == [{"file": "db.js", "lines": "3-5"}] and srcs["5.2"][0] == {"type": "CWE", "citation": "CWE-1104"}, srcs
        with open(J("int.diff"), "w", encoding="utf-8") as f:
            f.write("diff --git a/db.js b/db.js\nindex 1..2\n--- a/db.js\n+++ b/db.js\n@@ -1 +1 @@\n-x\n+z\n")
        with open(J("audit.json"), "w", encoding="utf-8") as f:
            json.dump({"method": "m", "verdict": "v", "evidence": "e"}, f)
        recs, _, ng, _ = build(d, src, J("int.diff"), "F1", J("audit.json"), table={89})
        assert not ng and recs[0]["fix"]["source"] == "integrated" and recs[0]["fix"]["diff"].startswith("--- a/db.js")
        assert recs[1]["fix"]["note"] == NOTE % "5.1", recs[1]["fix"]
        recs, _, ng, _ = build(d, src, J("int.diff"), "5.1", J("audit.json"), table={89})  # 最終番号でも可
        assert not ng and recs[0]["fix"]["source"] == "integrated", ng
        _, _, ng, _ = build(d, src, J("int.diff"), "5.9", J("audit.json"), table={89})
        assert ng == ["--base 5.9: not in members.json"], ng
        recs, _, ng, _ = build(d, src, J("int.diff"), "F1", J("audit.json"), ("F2",), table={89})
        assert recs[1]["fix"]["note"] == ""
        _, _, ng, _ = build(d, {"F1": []}, table={89})
        assert any("F2" in x and "--sources" in x for x in ng), ng
        _, _, ng, _ = build(d, dict(src, F2=[{"type": "OWASP", "citation": "x"}]), table={89})
        assert any("bad source tag" in x for x in ng), ng
        wj(J("out/writer-2.jsonl"), [dict(w, id="F2", code_ranges=["package.json:7"], compat="①②")])
        _, _, ng, _ = build(d, src, table={89})
        assert any("compat" in x and "F2" in x for x in ng), ng
        wj(J("out/writer-2.jsonl"), [dict(w, id="F2", code_ranges=["package.json:7"], compat="①③")])
        _, _, ng, _ = build(d, src, table={89})
        assert not any("compat" in x for x in ng), ng
        os.remove(J("out/writer-2.jsonl"))
        recs, _, _, _ = build(d, dict(src, F2=[{"type": "SCA", "citation": "npm audit"}, {"type": "IPA", "citation": "x"}]), table={1104})
        assert [s.split(":")[0].split(" ")[0] for s in recs[1]["references"]] == ["IPA", "CWE-1104", "SCA"], recs[1]["references"]
        assert exploit_status([{"id": "G", "items": [{"cve": "C", "epss": None, "epss_status": "not_found"}]}]) == \
            "対象: G。最大EPSS 該当なし、KEV掲載 0件。詳細は8節"
        assert 89 in cwe_table() and 1104 in cwe_table() and 1321 not in cwe_table()
        with open(J("src.json"), "w", encoding="utf-8") as f:
            json.dump(src, f)
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            assert run(d, J("src.json")) == 0 and run(d, J("src.json")) == 2
        assert len(load_jsonl(J("findings.jsonl"))) == 2 and "5.1" in load_json(J("sources.json"))
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work")
    ap.add_argument("--sources")
    ap.add_argument("--integrated")
    ap.add_argument("--base")
    ap.add_argument("--base-audit")
    ap.add_argument("--not-merged", default="")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.work and a.sources):
        ap.error("--work and --sources are required")
    nm = tuple(x for x in a.not_merged.split(",") if x)
    return run(a.work, a.sources, a.integrated, a.base, a.base_audit, nm, a.force)


if __name__ == "__main__":
    sys.exit(main())
