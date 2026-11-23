#!/usr/bin/env python3
"""Check manifest.json against the skill documents and measure read load per reader.

Stdlib only (Python 3.9+). Deterministic. Exit 0 = no problems, 1 = problems.
Sources compared with the manifest, in both directions:
  SKILL.md (mode 2 list, mode 2 gate M4, G0 list, gate list, mode 2 conditional reads),
  references/modes/mode3-full-audit.md (gate markers), scripts/check_docs_integrity.py
  (GATE_FILES, G0_FILES, G0_BUDGET, MODE2_FILES, MODE2_GATE_FILES, CONDITIONAL_GATES, TOKEN_FILES),
  references/core/agent-roles.md (role table).
Bytes are raw file bytes with CRLF normalised to LF. A glob entry (references/lang/*.md)
is a class: the largest matching file is counted.
"""
import argparse
import glob
import importlib.util
import json
import os
import re
import sys

PATH_RE = re.compile(r"`((?:references|assets)/[A-Za-z0-9_./*-]+\.md)`")
MARKER_RE = re.compile(r"<!--gate:(\w+)(.*?)-->")
TOKEN_RE = re.compile(r"GATE-TOKEN:((G\d[A-Z]?)-[0-9a-f]{6})")
MARGIN = 16  # bytes a budget may sit above the measured value without a raised_reason
BASELINE = "scripts/read-budget-baseline.json"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ROLE_RE = re.compile(r"^\|\s*([A-Z][A-Z0-9-]+)[\s（(|]")
SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def read_text(root, rel):
    return read_bytes(os.path.join(root, rel)).decode("utf-8")


def size_of(root, rel):
    """(bytes, note). A glob counts its largest match."""
    if "*" in rel:
        ms = sorted(glob.glob(os.path.join(root, rel)))
        if not ms:
            return None, ""
        sizes = [(len(read_bytes(p)), p) for p in ms]
        n, best = max(sizes, key=lambda t: (t[0], t[1]))
        return n, "largest of %d: %s" % (len(ms), os.path.basename(best))
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        return None, ""
    return len(read_bytes(p)), ""


def load_integrity(root):
    p = os.path.join(root, "scripts", "check_docs_integrity.py")
    spec = importlib.util.spec_from_file_location("_cdi_for_budget", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def numbered_list(lines, header):
    out, on = [], False
    for ln in lines:
        if not on:
            on = header in ln
            continue
        m = re.match(r"^\d+\.\s+`([^`]+)`", ln)
        if m:
            out.append(m.group(1))
        elif out:
            break
    return out


def count_unverified(o):
    if isinstance(o, dict):
        return (1 if o.get("unverified") is True else 0) + sum(count_unverified(v) for v in o.values())
    if isinstance(o, list):
        return sum(count_unverified(v) for v in o)
    return 0


def validate_structure(m, ng):
    def need(cond, msg):
        if not cond:
            ng.append("[structure] " + msg)
        return cond

    if not need(isinstance(m, dict), "manifest is not an object"):
        return False
    for k in ("schema_version", "skill", "conditions", "modes", "roles", "budgets", "environments"):
        need(k in m, "missing key " + k)
    if ng:
        return False
    need(m.get("schema_version") == 1, "schema_version must be 1")
    need(isinstance(m["skill"], dict) and isinstance(m["skill"].get("version"), str), "skill.version missing")
    need(sorted(m["modes"]) == ["1", "2", "3"], "modes must be exactly 1, 2, 3")
    for k, md in sorted(m["modes"].items()):
        steps = md.get("steps") if isinstance(md, dict) else None
        if not need(isinstance(steps, list) and steps, "mode %s has no steps" % k):
            continue
        for i, s in enumerate(steps):
            for f in ("name", "required", "conditional", "gate", "gate_token"):
                need(f in s, "mode %s step %d missing %s" % (k, i, f))
            for c in s.get("conditional", []):
                need(c.get("condition_id") in m["conditions"], "mode %s step %s: unknown condition id %s" % (k, s.get("name"), c.get("condition_id")))
    for n, r in sorted(m["roles"].items()):
        need(isinstance(r.get("reads"), list), "role %s: reads missing" % n)
        for x in r.get("reads", []):
            need(x.get("scope") in ("full", "section"), "role %s: read %s needs scope full|section" % (n, x.get("file")))
        if r.get("unverified"):
            need(bool(r.get("reason")), "role %s: unverified without reason" % n)
        for x in r.get("reads", []):
            cid = x.get("condition_id")
            need(cid is None or cid in m["conditions"], "role %s: unknown condition id %s" % (n, cid))
    for e, ev in sorted(m["environments"].items()):
        if ev.get("unverified"):
            need(bool(ev.get("reason")), "environment %s: unverified without reason" % e)
    for grp in ("orchestrator", "roles"):
        for n, v in sorted(m["budgets"].get(grp, {}).items()):
            need(isinstance(v.get("bytes"), int) and v.get("basis") in ("required", "worst"), "budget %s/%s malformed" % (grp, n))
            rr = v.get("raised_reason")
            if rr is not None:
                need(isinstance(rr, dict) and DATE_RE.match(str(rr.get("date", ""))) and rr.get("approver") and rr.get("text"),
                     "budget %s/%s: raised_reason needs date (YYYY-MM-DD), approver, text" % (grp, n))
    return not ng


def check(root, m):
    ng, info = [], []
    if not validate_structure(m, ng):
        return ng, info, [], {}
    cdi = load_integrity(root)
    skill = read_text(root, "SKILL.md").split("\n")

    def step(mode, name):
        return next((s for s in m["modes"][mode]["steps"] if s["name"] == name), None)

    def diff(label, mine, doc):
        a, b = list(mine), list(doc)
        if a != b:
            ng.append("[%s] manifest-only %s; doc-only %s%s" % (
                label, sorted(set(a) - set(b)), sorted(set(b) - set(a)), "; order differs" if set(a) == set(b) else ""))

    # every referenced file exists
    seen = set()
    refs = []
    for k, md in m["modes"].items():
        for s in md["steps"]:
            refs += [(f, "mode %s %s" % (k, s["name"])) for f in s["required"] + [c["file"] for c in s["conditional"]]]
            refs += [(t["file"], "token " + t["id"]) for t in s["gate_token"] or []]
    for n, r in m["roles"].items():
        refs += [(x["file"], "role " + n) for x in r["reads"]]
    for f, who in refs:
        if f not in seen:
            seen.add(f)
            if size_of(root, f)[0] is None:
                ng.append("[missing-file] %s (%s)" % (f, who))
    for cid, c in sorted(m["conditions"].items()):
        if not os.path.isfile(os.path.join(root, c["source"])):
            ng.append("[missing-file] %s (condition %s)" % (c["source"], cid))
        elif c["text"] not in read_text(root, c["source"]):
            ng.append("[condition-text] %s: text not found in %s" % (cid, c["source"]))

    # mode 1 and 2
    s2 = step("2", "required6")
    diff("mode2-list", s2["required"] if s2 else [], numbered_list(skill, "必読ファイル（モード2"))
    diff("mode2-list-checker", s2["required"] if s2 else [], cdi.MODE2_FILES)
    m4 = step("2", "M4")
    m4doc = [PATH_RE.findall(ln) for ln in skill if ln.startswith("**" + cdi.MODE2_GATE_KEY)]
    diff("mode2-gate", m4["required"] if m4 else [], m4doc[0] if len(m4doc) == 1 else [])
    diff("mode2-gate-checker", m4["required"] if m4 else [], cdi.MODE2_GATE_FILES)
    if m4:
        if m4["gate"] != "M4":
            ng.append("[mode2-gate] step M4 must have gate M4")
        for t in m4["gate_token"] or []:
            found = TOKEN_RE.findall(read_text(root, t["file"])) if size_of(root, t["file"])[0] is not None else []
            if [(x[1], x[0]) for x in found] != [(t["id"], t.get("value"))]:
                ng.append("[mode2-gate-token] %s: manifest %s/%s vs file %s" % (t["file"], t["id"], t.get("value"), [x[0] for x in found]))
        if sorted(t["file"] for t in m4["gate_token"] or []) != sorted(m4["required"]):
            ng.append("[mode2-gate-token] M4 needs one token per gate file")
    for mode in ("1", "2"):
        sk, pr = step(mode, "skill"), step(mode, "principles")
        if not sk or sk["required"] != ["SKILL.md"] or not pr or pr["required"] != ["references/checklists/principles.md"]:
            ng.append("[mode%s-core] steps skill/principles must be SKILL.md and references/checklists/principles.md" % mode)
    if not any("モード1・2" in ln and "principles.md" in ln for ln in skill):
        ng.append("[mode12-principles] SKILL.md no longer says modes 1 and 2 read principles.md")
    doc_c = []
    for ln in skill:
        if "条件付き必読（モード2のみ）" in ln or re.match(r"^\([a-d]\) ", ln):
            t = re.sub(r"（[^）]*）", "", ln)
            t = t.split("→", 1)[1] if "→" in t else ""
            t = t.split("。", 1)[0]
            t = re.sub(r"`(mode\d)", r"`references/\1", t)
            doc_c += PATH_RE.findall(t)
    c2 = step("2", "conditional")
    diff("mode2-conditional", sorted(set(x["file"] for x in c2["conditional"])) if c2 else [], sorted(set(doc_c)))

    # G0
    g0 = step("3", "G0")
    diff("g0-list-skill", g0["required"][1:] if g0 else [], numbered_list(skill, "必読ファイル（G0"))
    diff("g0-files", g0["required"] if g0 else [], cdi.G0_FILES)
    got = m["budgets"]["orchestrator"].get("mode3:G0", {}).get("bytes")
    if got != cdi.G0_BUDGET:
        ng.append("[g0-budget] manifest mode3:G0 budget %s != G0_BUDGET %s" % (got, cdi.G0_BUDGET))

    # gates
    gsteps = [s for s in m["modes"]["3"]["steps"] if s["name"] != "G0"]
    gids = [s["gate"] for s in gsteps]
    if gids != list(cdi.GATE_ORDER):
        ng.append("[gate-order] manifest %s vs GATE_ORDER %s" % (gids, list(cdi.GATE_ORDER)))
    gdoc = {}
    for ln in skill:
        mm = re.match(r"^- (G\d)（[^）]*）[:：]\s*(.*)$", ln)
        if mm:
            t = re.sub(r"（[^）]*）", "", mm.group(2)).split("。")[0]
            gdoc[mm.group(1)] = PATH_RE.findall(re.sub(r"`(mode\d)", r"`references/\1", t))
    marks = []
    for ln in read_text(root, "references/modes/mode3-full-audit.md").split("\n"):
        mm = MARKER_RE.search(ln)
        if mm:
            attrs = mm.group(2).split()
            files = [x for a in attrs if a.startswith("files=") for x in a[6:].split(",") if x]
            marks.append((mm.group(1), "conditional" in attrs, files))
    if [x[0] for x in marks] != gids:
        ng.append("[gate-marker-order] markers %s vs manifest %s" % ([x[0] for x in marks], gids))
    mk = {g: (c, f) for g, c, f in marks}
    for s in gsteps:
        g = s["gate"]
        cond_gate = g in cdi.CONDITIONAL_GATES
        mine = [c["file"] for c in s["conditional"]] if cond_gate else list(s["required"])
        if tuple(mine) != tuple(cdi.GATE_FILES.get(g, ())):
            ng.append("[gate-files-checker] %s manifest %s vs GATE_FILES %s" % (g, mine, list(cdi.GATE_FILES.get(g, ()))))
        if g in mk and tuple(mine) != tuple(mk[g][1]):
            ng.append("[gate-files-marker] %s manifest %s vs marker %s" % (g, mine, mk[g][1]))
        if g in mk and mk[g][0] != cond_gate:
            ng.append("[gate-conditional] %s marker conditional=%s vs checker" % (g, mk[g][0]))
        if cond_gate != bool(s["conditional"]):
            ng.append("[gate-conditional] %s manifest conditional differs from CONDITIONAL_GATES" % g)
        if g not in gdoc and not mine:
            pass
        elif g not in gdoc:
            ng.append("[gate-skill-missing] SKILL.md has no list line for %s" % g)
        elif gdoc[g] != mine:
            ng.append("[gate-files-skill] %s manifest %s vs SKILL.md %s" % (g, mine, gdoc[g]))
        toks = s["gate_token"] or []
        exp = sorted(f for f, tg in cdi.TOKEN_FILES.items() if tg == g)
        if sorted(t["file"] for t in toks) != exp:
            ng.append("[gate-token] %s token files %s vs TOKEN_FILES %s" % (g, sorted(t["file"] for t in toks), exp))
        for t in toks:
            if size_of(root, t["file"])[0] is None:
                continue
            found = TOKEN_RE.findall(read_text(root, t["file"]))
            if [(x[1], x[0]) for x in found] != [(t["id"], t.get("value"))]:
                ng.append("[gate-token] %s: manifest %s/%s vs file %s" % (t["file"], t["id"], t.get("value"), [x[0] for x in found]))
    for g in sorted(gdoc):
        if g not in gids:
            ng.append("[gate-skill-extra] SKILL.md lists %s, absent from manifest" % g)

    # roles
    doc_roles = []
    for ln in read_text(root, "references/core/agent-roles.md").split("\n"):
        mm = ROLE_RE.match(ln)
        if mm and mm.group(1) != "RO":
            doc_roles.append(mm.group(1))
    if sorted(doc_roles) != sorted(m["roles"]):
        ng.append("[role] manifest-only %s; doc-only %s" % (sorted(set(m["roles"]) - set(doc_roles)), sorted(set(doc_roles) - set(m["roles"]))))

    # measurement
    rows = []
    rows.append(("mode1", "orchestrator", "required", [f for s in m["modes"]["1"]["steps"] for f in s["required"]]))
    acc = []
    for s in m["modes"]["2"]["steps"]:  # mode2 = before the first gate (M4); mode2:<gate> = cumulative after it
        if s["gate"]:
            if not any(r[0] == "mode2" for r in rows):
                rows.append(("mode2", "orchestrator", "required", list(acc)))
            acc += s["required"]
            rows.append(("mode2:" + s["gate"], "orchestrator", "required", list(acc)))
        else:
            acc += s["required"]
    if not any(r[0] == "mode2" for r in rows):
        rows.append(("mode2", "orchestrator", "required", list(acc)))
    acc = []
    for s in m["modes"]["3"]["steps"]:
        acc += s["required"]
        rows.append(("mode3:" + s["name"], "orchestrator", "required", list(acc)))
    for n in sorted(m["roles"]):
        rows.append((n, "roles", "worst", [x["file"] for x in m["roles"][n]["reads"]]))
    try:
        base = json.loads(read_bytes(os.path.join(root, BASELINE)).decode("utf-8"))["budgets"]
    except (OSError, ValueError, KeyError):
        base = None
        ng.append("[baseline] %s missing or unreadable" % BASELINE)
    warns = []
    out = []
    for name, grp, basis, files in rows:
        total, nts = 0, []
        for f in dict.fromkeys(files):
            n, nt = size_of(root, f)
            total += n or 0
            if nt:
                nts.append("%s (%s)" % (f, nt))
        b = m["budgets"].get(grp, {}).get(name)
        budget = b["bytes"] if b else None
        if b is None:
            ng.append("[budget-missing] no budget for %s/%s" % (grp, name))
        elif b["basis"] != basis:
            ng.append("[budget-basis] %s/%s basis %s != %s" % (grp, name, b["basis"], basis))
        if grp == "roles":
            for x in m["roles"][name]["reads"]:
                if x["scope"] == "section" and x.get("section_bytes") is None:
                    nts.append("%s (section read: whole file counted; section estimate null)" % x["file"])
        status = "ok"
        if b is not None:
            bb = (base or {}).get(grp, {}).get(name)
            if base is not None and bb is None:
                ng.append("[baseline] %s/%s absent from %s" % (grp, name, BASELINE))
            over_margin = budget > total + MARGIN
            over_base = bb is not None and budget > bb["bytes"]
            if over_margin or over_base:
                if b.get("raised_reason"):
                    rr = b["raised_reason"]
                    warns.append("%s/%s budget %s (measured %s, baseline %s): %s, %s, %s" % (
                        grp, name, format(budget, ","), format(total, ","), "n/a" if bb is None else format(bb["bytes"], ","), rr["date"], rr["approver"], rr["text"]))
                else:
                    ng.append("[budget-raised] %s/%s budget %s exceeds %s without raised_reason" % (
                        grp, name, format(budget, ","), "measured+%d (%s)" % (MARGIN, format(total + MARGIN, ",")) if over_margin else "baseline %s" % format(bb["bytes"], ",")))
        if budget is not None and total > budget:
            status = "OVER"
            ng.append("[budget] %s/%s %s bytes > budget %s" % (grp, name, format(total, ","), format(budget, ",")))
        out.append({"reader": name, "group": grp, "basis": basis, "bytes": total, "budget": budget,
                    "status": status, "files": len(set(files)), "notes": nts})
    extra = set(m["budgets"].get("orchestrator", {})) - {r["reader"] for r in out if r["group"] == "orchestrator"}
    extra |= set(m["budgets"].get("roles", {})) - set(m["roles"])
    if extra:
        ng.append("[budget-extra] budgets for unknown readers %s" % sorted(extra))
    return ng, info, out, {"unverified": count_unverified(m), "warnings": warns}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate manifest.json and measure read load per reader.")
    ap.add_argument("--root", default=SKILL_DIR)
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--brief", action="store_true", help="only problems and totals")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    root = os.path.abspath(a.root)
    mp = a.manifest or os.path.join(root, "manifest.json")
    try:
        m = json.loads(read_bytes(mp).decode("utf-8"))
        ng, info, rows, extra = check(root, m)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        ng, info, rows, extra = ["[load] %s: %s" % (type(e).__name__, e)], [], [], {}
    if a.json:
        print(json.dumps({"ok": not ng, "problems": ng, "readers": rows, **extra}, ensure_ascii=False, indent=2, sort_keys=True))
        return 1 if ng else 0
    if not a.brief:
        print("%-14s %-12s %-8s %10s %10s %9s  %s" % ("reader", "group", "basis", "bytes", "budget", "margin", "status"))
        for r in rows:
            bd, mg = ("", "") if r["budget"] is None else (format(r["budget"], ","), format(r["budget"] - r["bytes"], ","))
            print("%-14s %-12s %-8s %10s %10s %9s  %s" % (r["reader"], r["group"], r["basis"], format(r["bytes"], ","), bd, mg, r["status"]))
            for n in r["notes"]:
                print("    note: " + n)
    for w in extra.get("warnings", []):
        print("WARN raised budget: " + w)
    for p in ng:
        print("NG " + p)
    by = {r["reader"]: r["bytes"] for r in rows if r["group"] == "orchestrator"}
    print("totals: mode1 %s, mode2 %s (M4 %s), mode3(all gates) %s, G0 %s; unverified items %s; problems %d" % (
        *(format(by.get(k, 0), ",") for k in ("mode1", "mode2", "mode2:M4", "mode3:G7", "mode3:G0")), extra.get("unverified", "?"), len(ng)))
    return 1 if ng else 0


if __name__ == "__main__":
    sys.exit(main())
