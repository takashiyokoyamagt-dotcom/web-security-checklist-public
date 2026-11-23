#!/usr/bin/env python3
"""5f-2の③④（cvss-scoring.md「判定記録」）: 有効なメモ行からCVSSを一括算出し、確定行を追記する。

Usage:
  python3 cvss_finalize.py --work WORK raw     # ③ 主ベクターと別案を calculate_cvss.py で算出し cvss-raw-output.jsonl へ
  python3 cvss_finalize.py --work WORK final   # ④ sbs・band・attn・grp・v4diff を埋めた確定行を cvss-decisions.jsonl へ
  python3 cvss_finalize.py --work WORK number [--force]  # 最終番号 final.json（make_idmap.py の --final）
  python3 cvss_finalize.py --self-test

WORK は`cvss-decisions.jsonl`の保存先。対象は各`tmp`の有効行（最大rev）がメモ行（`st:"memo"`）のもの。
raw: 主ベクター（v3・v4）を1回、`borderline`の各メトリクスについて別案（主ベクターの当該1メトリクスを
`m3`の5要素目の`alt`に差し替えたv3.1）を1回ずつ算出し、`check_cvss_decisions.py --append-raw`で追記する
（逐次。並列に呼ばない）。メモ行の別案の`score`（"6.5/Medium"）と算出値が違えば`WARN: alt mismatch`を出す
（rc0。メモ行を`rev+1`で直してから再実行する）。既に主行がある`tmp`は飛ばす。
final: 各`tmp`の最後の主行と別案行から次を決め、確定行を`check_cvss_decisions.py --append`で追記する。
- `band`: v3.1の`base_severity`（環境メトリクスは扱わない）。None→Low。v3.1が算出エラーなら確定行を書かずNG。
- `sbs`: 別案のいずれかでv3.1の帯が変われば true。
- `v4diff`: v3.1の帯とv4.0の`severity`（None→Low）が違い、両方算出できたときだけ。`cause`は`v4map`が`std`なら
  `spec`、それ以外は`judgment`。`why`はv4.0で既定値でない（AT:P・UI:P/A・SC/SI/SAがN以外）メトリクス名と帯。
  `spec`の妥当性（版の基準の違いで説明できるか）は判断を含むので、`why`を読んで違えばArbiterが`rev+1`で直す。
- `attn`: sbs か v4diff.cause=judgment なら high、`borderline`が空でなければ low、ほかは none（`attn_why`付き）。
- `grp`: `<type>|<CWE番号の昇順>`（同一CWE・同一類型は同名。例 `表外|CWE-20,CWE-770`）。
- `rev`は既存の最大+1、`st:"final"`・`by:"arbiter"`・`calc:"std"`・`id`/`raw`はnull（`--fill-ids`で後埋め）。
number: `members.json`の各項目を、確定行の`band`（Critical→Low）、v3.1の基準値の降順、`members.json`の順で
並べて`5.1`から振り、`final.json`（`{"F1":"5.2"}`）に書く。確定行か主行が無い項目があればNG。既存なら`--force`が無い限りrc2。
出力は件数と WARN/NG の行だけ。Stdlib only, Python 3.9+（算出は calculate_cvss.py の依存が要る）.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
V4_NONDEFAULT = (("AT", "N"), ("UI", "N"), ("SC", "N"), ("SI", "N"), ("SA", "N"))


def env():
    return dict(os.environ, PYTHONIOENCODING="utf-8")


def load(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(s) for s in (l.strip() for l in f) if s]


def effective(rows):
    out = {}
    for o in rows:
        t = o.get("tmp")
        if t is not None and (t not in out or o.get("rev", 0) >= out[t].get("rev", 0)):
            out[t] = o
    return out


def max_rev(rows):
    out = {}
    for o in rows:
        out[o["tmp"]] = max(out.get(o["tmp"], 0), o.get("rev", 0))
    return out


def band(sev):
    s = str(sev or "")
    return "Low" if s.lower() in ("none", "") else s[:1].upper() + s[1:].lower()


def calc(v3, v4=None):
    a = [sys.executable, os.path.join(HERE, "calculate_cvss.py"), "--v3-vector", v3]
    if v4:
        a += ["--v4-vector", v4]
    p = subprocess.run(a, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", errors="replace", env=env())
    return p.returncode, p.stdout, p.stderr


def append_raw(work, out, tmp, of=None):
    a = [sys.executable, os.path.join(HERE, "check_cvss_decisions.py"), "--append-raw",
         os.path.join(work, "cvss-raw-output.jsonl"), "--id", tmp]
    if of:
        a += ["--kind", "alt", "--of", of]
    p = subprocess.run(a, input=out, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8",
                       errors="replace", env=env())
    return p.returncode, p.stdout


def swap(v3, metric, val):
    return re.sub(r"(/%s:)[A-Z]" % re.escape(metric), lambda m: m.group(1) + val, v3)


def do_raw(work):
    dec = load(os.path.join(work, "cvss-decisions.jsonl"))
    have = {r["id"] for r in load(os.path.join(work, "cvss-raw-output.jsonl")) if r.get("kind") != "alt"}
    todo = [o for t, o in sorted(effective(dec).items()) if o.get("st") == "memo" and t not in have]
    ng, warn, n_main, n_alt = [], [], 0, 0
    for o in todo:
        tmp = o["tmp"]
        rc, out, err = calc(o["v3"], o.get("v4") if o.get("v4") and o.get("v4") != "未算出" else None)
        if rc != 0 or not out.strip().startswith("{"):
            ng.append("%s: calculate_cvss.py rc%d %s" % (tmp, rc, (err or out).strip()[:200]))
            continue
        rc, msg = append_raw(work, out, tmp)
        if rc:
            ng.append("%s: --append-raw %s" % (tmp, msg.strip()[:200]))
            continue
        n_main += 1
        for m in o.get("borderline") or []:
            spec = (o.get("m3") or {}).get(m)
            alt = spec[4] if isinstance(spec, list) and len(spec) > 4 and isinstance(spec[4], dict) else None
            if not alt or not alt.get("alt"):
                ng.append("%s: borderline %s has no alt in m3" % (tmp, m))
                continue
            rc, aout, err = calc(swap(o["v3"], m, alt["alt"]))
            if rc != 0:
                ng.append("%s/%s: calculate_cvss.py rc%d %s" % (tmp, m, rc, (err or aout).strip()[:200]))
                continue
            rc, msg = append_raw(work, aout, tmp, m)
            if rc:
                ng.append("%s/%s: --append-raw %s" % (tmp, m, msg.strip()[:200]))
                continue
            n_alt += 1
            j = json.loads(aout).get("v3", {})
            got = "%s/%s" % (j.get("base_score"), band(j.get("base_severity")))
            ok = {got, "%s/%s" % (j.get("base_score"), j.get("base_severity"))}
            if str(alt.get("score", "")).replace(" ", "") not in ok:
                warn.append("alt mismatch %s %s: memo %s, calculated %s" % (tmp, m, alt.get("score"), got))
    for w in warn:
        print("WARN: " + w)
    for x in ng:
        print("NG: " + x)
    print("raw: %d main + %d alt appended (%d tmp already had a main row)" % (n_main, n_alt, len(have)))
    return 1 if ng else 0


def v4_nondefault(v4):
    out = []
    for m, d in V4_NONDEFAULT:
        mm = re.search(r"/%s:([A-Z])" % m, v4 or "")
        if mm and mm.group(1) != d:
            out.append("%s:%s" % (m, mm.group(1)))
    return out


def final_row(o, mains, alts, rev):
    raw = mains[-1]["raw"]
    v3, v4 = raw.get("v3") or {}, raw.get("v4") or {}
    if "error" in v3 or "base_severity" not in v3:
        return None, "v3.1 not calculated (%s)" % v3.get("error", "no v3")
    b3 = band(v3["base_severity"])
    sbs = any(band((a["raw"].get("v3") or {}).get("base_severity")) != b3 for a in alts
              if "base_severity" in (a["raw"].get("v3") or {}))
    f = {k: v for k, v in o.items() if k not in ("seq", "ts", "rev_why")}
    cwes = sorted({str(c) for c in o.get("cwe") or []}, key=lambda c: int(re.sub(r"\D", "", c) or 0))
    f.update(rev=rev, st="final", by="arbiter", id=None, raw=None, calc="std", band=b3, sbs=sbs,
             grp="%s|%s" % (o.get("type") or "表外", ",".join(cwes)))
    f.pop("v4diff", None)
    if "error" not in v4 and "severity" in v4:
        b4 = band(v4["severity"])
        if b4 != b3:
            cause = "spec" if o.get("v4map") == "std" else "judgment"
            names = v4_nondefault(o.get("v4"))
            f["v4diff"] = {"cause": cause, "why": "%s（v3.1:%s→v4.0:%s）" % (
                "・".join(names) if names else "VC/VI/VAの算定式の違い", b3, b4)}
    if sbs or f.get("v4diff", {}).get("cause") == "judgment":
        f["attn"], f["attn_why"] = "high", "別案でv3.1の帯が変わる" if sbs else "v4.0との帯の差の原因が判断"
    elif o.get("borderline"):
        f["attn"], f["attn_why"] = "low", "迷・例外・逸脱のメトリクスあり（%s）" % ",".join(o["borderline"])
    else:
        f["attn"] = "none"
        f.pop("attn_why", None)
    return f, None


def do_final(work):
    path = os.path.join(work, "cvss-decisions.jsonl")
    dec = load(path)
    raws = {}
    for r in load(os.path.join(work, "cvss-raw-output.jsonl")):
        raws.setdefault(r["id"], []).append(r)
    revs = max_rev(dec)
    rows, ng = [], []
    for tmp, o in sorted(effective(dec).items()):
        if o.get("st") != "memo":
            continue
        rs = raws.get(tmp, [])
        mains = [r for r in rs if r.get("kind") != "alt"]
        if not mains:
            ng.append("%s: no main row in cvss-raw-output.jsonl (run raw first)" % tmp)
            continue
        alts = [r for r in rs if r.get("kind") == "alt"]
        missing = set(o.get("borderline") or []) - {a.get("of") for a in alts}
        if missing:
            ng.append("%s: no alt row for %s" % (tmp, ",".join(sorted(missing))))
            continue
        f, err = final_row(o, mains, alts, revs[tmp] + 1)
        if err:
            ng.append("%s: %s" % (tmp, err))
            continue
        rows.append(f)
    if rows:
        p = subprocess.run([sys.executable, os.path.join(HERE, "check_cvss_decisions.py"), "--append", path],
                           input="".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", env=env())
        if p.returncode:
            ng.append("--append rc%d: %s" % (p.returncode, p.stdout.strip()[-400:]))
            rows = []
    for x in ng:
        print("NG: " + x)
    cnt = {}
    for r in rows:
        cnt[r["band"]] = cnt.get(r["band"], 0) + 1
    print("final: %d row(s) appended %s; attn high %d, sbs %d, v4diff %d" % (
        len(rows), json.dumps(cnt, ensure_ascii=False), sum(r["attn"] == "high" for r in rows),
        sum(bool(r["sbs"]) for r in rows), sum("v4diff" in r for r in rows)))
    return 1 if ng else 0


BAND_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def numbering(members, dec, raws):
    eff = effective(dec)
    keys, ng = {}, []
    for i, (u, ms) in enumerate(members.items()):
        tmp = "+".join(sorted(ms))
        o = eff.get(tmp)
        mains = [r for r in raws.get(tmp, []) if r.get("kind") != "alt"]
        if not o or o.get("st") != "final" or not mains:
            ng.append("%s (%s): no final row or main raw row" % (u, tmp))
            continue
        keys[u] = (BAND_ORDER.get(o.get("band"), 9), -float(mains[-1]["raw"].get("v3", {}).get("base_score") or 0), i)
    order = sorted(keys, key=keys.get)
    return {u: "5.%d" % k for k, u in enumerate(order, 1)}, ng


def do_number(work, force=False):
    out = os.path.join(work, "final.json")
    if os.path.exists(out) and not force:
        print("error: %s already exists (use --force)" % out)
        return 2
    with open(os.path.join(work, "members.json"), encoding="utf-8") as f:
        members = json.load(f)
    raws = {}
    for r in load(os.path.join(work, "cvss-raw-output.jsonl")):
        raws.setdefault(r["id"], []).append(r)
    fin, ng = numbering(members, load(os.path.join(work, "cvss-decisions.jsonl")), raws)
    for x in ng:
        print("NG: " + x)
    if ng:
        return 1
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(fin, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("number: %d item(s) -> final.json" % len(fin))
    return 0


def self_test():
    o = {"tmp": "A1", "cat": "x", "cwe": ["CWE-89"], "type": "表外", "v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "v4": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "v4map": "std",
         "m3": {"AC": ["L", "a.js:1", "f", "迷:x", {"alt": "H", "score": "5.9/Medium", "why": "w"}]},
         "dev": [], "borderline": ["AC"], "by": "sub", "rev": 1, "st": "memo", "seq": 3, "ts": "t"}
    mains = [{"raw": {"v3": {"base_score": 7.5, "base_severity": "High"}, "v4": {"score": 6.3, "severity": "Medium"}}}]
    alts = [{"kind": "alt", "of": "AC", "raw": {"v3": {"base_score": 5.9, "base_severity": "Medium"}}}]
    f, err = final_row(o, mains, alts, 2)
    assert err is None and f["band"] == "High" and f["sbs"] is True and f["attn"] == "high", f
    assert f["grp"] == "表外|CWE-89" and f["rev"] == 2 and f["st"] == "final" and "seq" not in f, f
    assert f["v4diff"] == {"cause": "spec", "why": "AT:P（v3.1:High→v4.0:Medium）"}, f
    o2 = dict(o, borderline=[], v4map="AT:Pを逸脱", type="防御不足")
    f, _ = final_row(o2, mains, [], 2)
    assert f["sbs"] is False and f["attn"] == "high" and f["v4diff"]["cause"] == "judgment" and f["grp"] == "防御不足|CWE-89", f
    mains0 = [{"raw": {"v3": {"base_score": 0.0, "base_severity": "None"}, "v4": {"error": "x"}}}]
    f, _ = final_row(dict(o, borderline=[]), mains0, [], 2)
    assert f["band"] == "Low" and "v4diff" not in f and f["attn"] == "none", f
    f, err = final_row(o, [{"raw": {"v3": {"error": "bad"}}}], [], 2)
    assert f is None and "not calculated" in err
    assert swap("CVSS:3.1/AV:N/AC:L/PR:N", "AC", "H") == "CVSS:3.1/AV:N/AC:H/PR:N"
    assert v4_nondefault("CVSS:4.0/AV:N/AT:N/UI:P/SC:L/SI:N/SA:N") == ["UI:P", "SC:L"]
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "cvss-decisions.jsonl"), "w", encoding="utf-8") as fp:
            fp.write(json.dumps(dict(o, rev=1)) + "\n" + json.dumps(dict(o, rev=2, rev_why="x")) + "\n")
        eff = effective(load(os.path.join(d, "cvss-decisions.jsonl")))
        assert eff["A1"]["rev"] == 2 and max_rev(load(os.path.join(d, "cvss-decisions.jsonl")))["A1"] == 2
        import io
        old, sys.stdout = sys.stdout, io.StringIO()
        try:
            rc = do_final(d)
            out = sys.stdout.getvalue()
        finally:
            sys.stdout = old
        assert rc == 1 and "no main row" in out, out
    mem = {"F1": ["A1"], "F2": ["B1", "B2"], "F3": ["C1"]}
    dec2 = [{"tmp": "A1", "st": "final", "band": "Medium", "rev": 2}, {"tmp": "B1+B2", "st": "final", "band": "High", "rev": 2},
            {"tmp": "C1", "st": "final", "band": "Medium", "rev": 2}]
    rw = {"A1": [{"raw": {"v3": {"base_score": 5.3}}}], "B1+B2": [{"raw": {"v3": {"base_score": 7.5}}}],
          "C1": [{"raw": {"v3": {"base_score": 6.5}}}]}
    fin, ng = numbering(mem, dec2, rw)
    assert not ng and fin == {"F2": "5.1", "F3": "5.2", "F1": "5.3"}, fin
    fin, ng = numbering(mem, dec2[:2], rw)
    assert ng and "F3" in ng[0], ng
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step", nargs="?", choices=("raw", "final", "number"))
    ap.add_argument("--work")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.work and a.step):
        ap.error("--work and raw|final|number are required")
    if a.step == "number":
        return do_number(a.work, a.force)
    return do_raw(a.work) if a.step == "raw" else do_final(a.work)


if __name__ == "__main__":
    sys.exit(main())
