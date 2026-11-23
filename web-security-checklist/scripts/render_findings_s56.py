#!/usr/bin/env python3
"""Render report sections 5 (finding details) and 6 (CVSS rationale) from findings.jsonl.

Usage: python3 render_findings_s56.py FINDINGS.jsonl --target TARGET_DIR --mask-file FILE [--out FILE]

P1 provisional (measure 1). The script makes no judgment: every sentence comes
from a field of the record, and the only computed text is fixed wording (block
titles, the link to section 6, the cross-reference sentence built from `xref`).
Code excerpts are read from TARGET_DIR with `body.code_ranges`. Secret values
are collected from TARGET_DIR with the rules of check_secret_leak.py, and literal
strings in --mask-file (one per line) are added; all are replaced with <マスク>.
A record that lacks a required field stops the run with an error (no silent
fallback). `body.annot`/`residual`/`code_ranges` are arrays of strings and `body.alts` an
array of rows; a string there is split by line instead of one bullet per character, with
a WARN on stderr (as_lists; check_handoff.py --check makes it NG). Stdlib only, Python 3.9+. Schema: references/core/handoff-files.md 5.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_secret_leak  # noqa: E402

MASK = "<マスク>"
COMPAT_LABEL = {
    "①": "①（正常な利用での挙動は変えない）",
    "②": "②（APIまたはデータ形式が変わる）",
    "③": "③（運用の変更が要る）",
    "②③": "②③（APIまたはデータ形式が変わる、運用の変更が要る）",
    "①③": "①③（正常な利用での挙動は変えない、運用の変更が要る）",  # 5b補足3の和集合
}
CONFLICT_YES = "衝突あり（設計方針に従えない。代替案は下記）"
CONFLICT_NO = "衝突なし（設計方針に従う）"
LANG = {".js": "js", ".ts": "ts", ".sql": "sql", ".tf": "hcl", ".yml": "yaml", ".yaml": "yaml",
        ".conf": "ini", ".json": "json", ".py": "python", ".ejs": "html", ".html": "html"}
V3 = [("AV", "AV（攻撃元区分）"), ("AC", "AC（攻撃条件の複雑さ）"), ("PR", "PR（必要な権限）"),
      ("UI", "UI（ユーザー関与）"), ("S", "S（スコープ）"), ("C", "C（機密性への影響）"),
      ("I", "I（完全性への影響）"), ("A", "A（可用性への影響）")]
V4 = [("AV", "AV（攻撃元区分）"), ("AC", "AC（攻撃条件の複雑さ）"), ("AT", "AT（攻撃条件・前提）"),
      ("PR", "PR（必要な権限）"), ("UI", "UI（ユーザー関与）"), ("VC", "VC（脆弱コンポーネントの機密性）"),
      ("VI", "VI（脆弱コンポーネントの完全性）"), ("VA", "VA（脆弱コンポーネントの可用性）"),
      ("SC", "SC（波及先の機密性）"), ("SI", "SI（波及先の完全性）"), ("SA", "SA（波及先の可用性）")]
REQUIRED = ("n", "severity", "short_summary", "files", "categories", "verdict", "cvss_v3", "cvss_v4",
            "references", "compat", "design", "body", "fix", "audit", "cvss_reasons")
BODY_REQUIRED = ("summary", "plain", "tech", "code_ranges", "annot", "scenario", "fix_expl",
                 "residual", "intent", "behavior")


LIST_KEYS = ("code_ranges", "annot", "residual")  # 文字列の配列（check_handoff.py SCHEMA writer）
BULLET = re.compile(r"^\s*(?:[-*]\s+|・\s*)")


def as_lists(d, label):
    """WRITERの配列のキー（LIST_KEYS・alts）が配列で来なかったときに直し、直した内容（WARN用）を返す。
    文字列を for で回すと1文字ずつの箇条になるので、文字列は改行で分ける（行頭の`- `・`* `・`・`と空行は除く）。
    配列でない要素は文字列に、altsの行が配列でなければ1セルの行にする。None は空配列。型の規定は handoff-files.md 4節"""
    out = []
    for k in LIST_KEYS:
        v = d.get(k, [])
        if isinstance(v, str):
            d[k] = [s for s in (BULLET.sub("", x).strip() for x in v.splitlines()) if s]
            out.append("%s: %s is a string, split into %d item(s) by line" % (label, k, len(d[k])))
        elif v is None:
            d[k] = []
            out.append("%s: %s is null, used []" % (label, k))
        elif not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            d[k] = [x if isinstance(x, str) else json.dumps(x, ensure_ascii=False) for x in (v if isinstance(v, list) else [v])]
            out.append("%s: %s has non-string item(s), converted to strings" % (label, k))
    alts = d.get("alts")
    if alts and (not isinstance(alts, list) or not all(isinstance(r, list) for r in alts)):
        d["alts"] = [r if isinstance(r, list) else [str(r)] for r in (alts if isinstance(alts, list) else [alts])]
        out.append("%s: alts is not an array of rows, non-array row(s) made one cell" % label)
    return [x + " (handoff-files.md 4: array)" for x in out]


class RecordError(Exception):
    pass


def load_sources(path):
    """sources.json。旧名のタグ`CWE_Top25`（保存済みの実行）は`CWE`として読む。"""
    with open(path, encoding="utf-8") as f:
        srcs = json.load(f)
    return {k: [dict(s, type="CWE") if s.get("type") == "CWE_Top25" else s for s in v] for k, v in srcs.items()}


def slug(heading):
    """GitHub-style anchor. Same rule as p1_report_roundtrip.slug."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def heading(rec, section=5):
    return "%d.%d [%s] %s" % (section, rec["n"], rec["severity"], rec["short_summary"])


def check(rec):
    missing = [k for k in REQUIRED if k not in rec]
    missing += ["body." + k for k in BODY_REQUIRED if k not in rec.get("body", {})]
    if missing:
        raise RecordError("5.%s: missing %s" % (rec.get("n", "?"), ", ".join(missing)))


def fmt_files(files):
    return ", ".join("`%s:%s`" % (f["file"], f["lines"]) if f.get("lines") else "`%s`" % f["file"] for f in files)


def fmt_cvss(c):
    return "%s（%s）`%s`" % (c["score"], c["severity"], c["vector"])


def meta_table(rec):
    design = rec["design"]
    compat = rec["compat"]
    rows = [
        ("ファイル", fmt_files(rec["files"])),
        ("カテゴリ", "%s (%s)" % ("、".join(rec["categories"]), ", ".join(rec.get("cwe", [])) or rec.get("cwe_note", ""))),
        ("判定", rec["verdict"]),
        ("CVSS v3.1", fmt_cvss(rec["cvss_v3"])),
        ("CVSS v4.0", fmt_cvss(rec["cvss_v4"])),
        ("根拠", " / ".join(rec["references"])),
        ("互換性の区分", COMPAT_LABEL[compat["classes"]] + ("。" + compat["note"] if compat.get("note") else "")),
        ("設計方針との整合", (CONFLICT_YES if design["conflict"] else CONFLICT_NO)
         + ("。" + design["refs_note"] if design.get("refs_note") else "")),
    ]
    if rec.get("exploit_status"):
        rows.append(("悪用状況（EPSS/KEV）", rec["exploit_status"]))
    return ["| 項目 | 内容 |", "| --- | --- |"] + ["| %s | %s |" % r for r in rows]


def read_range(target, spec):
    path, _, lines = spec.rpartition(":")
    parts = lines.split("-")
    start, end = int(parts[0]), int(parts[-1])
    full = os.path.join(target, path)
    with open(full, encoding="utf-8") as f:
        text = f.read().split("\n")
    if end > len(text):
        raise RecordError("code range past end of file: %s" % spec)
    head = "// %s:%d-%d" % (path, start, end) if start != end else "// %s:%d" % (path, start)
    return [head] + text[start - 1:end]


def code_block(rec, target):
    ranges = rec["body"]["code_ranges"]
    lang = LANG.get(os.path.splitext(ranges[0].rpartition(":")[0])[1], "text") if ranges else "text"
    lines = []
    for spec in ranges:
        lines += read_range(target, spec)
    return ["```" + lang] + lines + ["```"]


def xref_text(rec, by_n):
    x = rec.get("xref") or {}
    out = ""
    name = lambda n: "5.%d（%s）" % (n, by_n[n]["short_summary"])
    if x.get("chain"):
        out += (" 同じ攻撃連鎖の別箇所を断つ指摘は " + "、".join(name(n) for n in sorted(x["chain"]))
                + " である。併用すると連鎖が二重に断たれ、本指摘の修正のみでは当該箇所に限って解消する。")
    if x.get("same"):
        out += (" 同一箇所の別の欠陥として " + "、".join(name(n) for n in sorted(x["same"]))
                + " がある。本指摘に固有の欠陥は「" + rec["body"]["summary"] + "」である。")
    return out


def render_s5(rec, by_n, target):
    b = rec["body"]
    n = rec["n"]
    out = ["### " + heading(rec), ""] + meta_table(rec) + [""]
    out.append("メトリクスごとの判定根拠は本節では繰り返さず、「6. リスク分析」の対応する6.%d節に記載する（[6.%dのリスク分析を見る](#%s)）。"
               % (n, n, slug(heading(rec, 6))))
    out.append("")
    out += ["**概要**", "", b["summary"], ""]
    out += ["**わかりやすい解説（専門知識を前提としない説明）**", "", b["plain"], ""]
    out += ["**技術的詳細解説**", "", b["tech"], ""]
    out += ["**該当コード**", ""] + code_block(rec, target) + [""]
    out += ["**該当コードの問題点**", ""] + ["- " + a for a in b["annot"]] + [""]
    out += ["**攻撃シナリオ**", "", b["scenario"], ""]
    fix = rec["fix"]
    diff = fix["diff"].rstrip("\n").split("\n") + ([fix["note"]] if fix.get("note") else [])
    out += ["**推奨される修正**", "", "```diff"] + diff + ["```", ""]
    out += ["**修正内容の解説**", "", b["fix_expl"] + xref_text(rec, by_n), ""]
    if b["residual"]:
        out += ["**修正後に残るリスクと別経路**", ""] + ["- " + r for r in b["residual"]] + [""]
    out += ["**元の処理の意図と、修正による挙動の変化**", "",
            "- 元の処理の意図: " + b["intent"], "- 修正による挙動の変化: " + b["behavior"], ""]
    if b.get("alts"):
        out += ["**設計方針に従えない場合の代替案**", "",
                "| 案 | 内容 | メリット | デメリット（互換性・運用・工数・残るリスク） | デグレの可能性 | 推奨度 |",
                "| --- | --- | --- | --- | --- | --- |"]
        out += ["| " + " | ".join(a) + " |" for a in b["alts"]]
        out += ["", b.get("alts_note", ""), ""]
    a = rec["audit"]
    out += ["**修正案の監査レビュー**", "", "| 項目 | 内容 |", "| --- | --- |",
            "| 検証方式 | %s |" % a["method"], "| 判定 | %s |" % a["verdict"], "| 検証根拠 | %s |" % a["evidence"], ""]
    return out


def metric(vector, key):
    m = re.search(r"/%s:([A-Z]+)" % key, vector)
    if not m:
        raise RecordError("metric %s not in %s" % (key, vector))
    return m.group(1)


def render_s6(rec):
    r = rec["cvss_reasons"]
    v3, v4 = rec["cvss_v3"], rec["cvss_v4"]
    out = ["### " + heading(rec, 6), "", "[5.%dの指摘に戻る](#%s)" % (rec["n"], slug(heading(rec))), ""]
    out += ["**CVSS v3.1**", "", "| メトリクス | 値 | 判定根拠 |", "| --- | --- | --- |"]
    out += ["| %s | %s | %s |" % (label, metric(v3["vector"], k), r["r3"][k]) for k, label in V3]
    out += ["", "- ベクター文字列: `%s`" % v3["vector"], "- ベーススコア: %s（%s）" % (v3["score"], v3["severity"]), ""]
    out += ["**CVSS v4.0**", "", "| メトリクス | 値 | 判定根拠 |", "| --- | --- | --- |"]
    out += ["| %s | %s | %s |" % (label, metric(v4["vector"], k), r["r4"][k]) for k, label in V4]
    out += ["", "- ベクター文字列: `%s`" % v4["vector"], "- スコア: %s（%s）" % (v4["score"], v4["severity"]), ""]
    return out


def render(records, target, masks):
    by_n = {r["n"]: r for r in records}
    for r in records:
        check(r)
        for w in as_lists(r["body"], "5.%s" % r["n"]):
            print("WARN: " + w, file=sys.stderr)
    s5, s6 = [], []
    for r in sorted(records, key=lambda x: x["n"]):
        s5 += render_s5(r, by_n, target)
        s6 += render_s6(r)
    text = "\n".join(s5) + "\n" + "\n".join(s6)
    for m in masks:
        text = text.replace(m, MASK)
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("findings")
    ap.add_argument("--target", required=True)
    ap.add_argument("--mask-file", required=True,
                    help="secret values outside config files, one per line (the --extra-file of "
                         "check_secret_leak.py; may be empty). Required because the automatic "
                         "collection reads config files only")
    ap.add_argument("--out")
    a = ap.parse_args()
    with open(a.findings, encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()]
    cands, _, _ = check_secret_leak.collect(a.target, 8)
    masks = set(cands)
    with open(a.mask_file, encoding="utf-8") as f:
        masks |= {l.rstrip("\n") for l in f if l.strip()}
    masks = sorted(masks, key=len, reverse=True)
    try:
        text = render(records, a.target, masks)
    except (RecordError, KeyError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
