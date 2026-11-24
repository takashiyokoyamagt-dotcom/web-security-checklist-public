#!/usr/bin/env python3
"""統合レポートのHTML版（モード3手順6。references/modes/mode3-html.md）を、組み立てたMarkdownと findings.jsonl から作る。

Usage:
  python3 render_html.py --work WORK --report REPORT.md --target TARGET --mask-file FILE --out REPORT.html [--force]
  python3 render_html.py --self-test

`assets/templates/report_shell.html`（mode3-html.mdの配色・構成・出典タブ・diff色分け・5↔6のリンク・件数の実行時算出を実装済み）に、
`WORK/findings.jsonl`・`WORK/sources.json`から作った指摘データ（`FINDINGS`）と、Markdownの表紙・改訂履歴・1節の文章と注記・
2・3節・4節の設計方針の要約・6節冒頭・7〜12節をHTMLにしたもの（`STATIC`）を埋め込む。Markdown内の5.N・6.N・節への
リンクはHTMLのアンカーに付け替える。`</script`はエスケープし、秘密値は render_findings_s56.py と同じく伏せる。
出力はローカル保存用（`<!doctype html>`と`<meta charset="utf-8">`付き）。Artifactで公開するときは artifact-design を読んでから。
既存の出力があれば`--force`が無い限りrc2。判断を含まない。Stdlib only, Python 3.9+.
"""
import argparse
import contextlib
import html
import io
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import render_findings_s56 as R  # noqa: E402
from make_packets import Masker  # noqa: E402
from assemble_report import TOC  # noqa: E402

SHELL = os.path.join(HERE, "..", "assets", "templates", "report_shell.html")
TITLE = "セキュリティ監査報告書"


def section(md, num):
    m = re.search(r"^## %d\. .*?$(.*?)(?=^## \d+\. |\Z)" % num, md, re.S | re.M)
    return m.group(1).strip("\n") if m else ""


def between(md, start, end):
    a = md.find(start)
    if a < 0:
        return ""
    a += len(start)
    b = md.find(end, a)
    return md[a:b if b >= 0 else len(md)].strip("\n")


def make_inline(anchors):
    def fix(href):
        return anchors.get(href[1:], href[1:])

    def inline(t):
        t = html.escape(t, quote=False)
        t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
        t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
        t = re.sub(r"\[([^\]]+)\]\(#([^)]+)\)", lambda m: '<a href="#%s">%s</a>' % (fix("#" + m.group(2)), m.group(1)), t)
        t = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<a href="\2" target="_blank" rel="noopener noreferrer">\1</a>', t)
        t = re.sub(r"\[([^\]]+)\]\(([^)#:]+\.(?:md|html))\)", r'<a href="\2">\1</a>', t)
        return t
    return inline


def md2html(text, inline, table_class=None):
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        l = lines[i]
        if l.startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.append("<pre>%s</pre>" % html.escape("\n".join(lines[i + 1:j]), quote=False))
            i = j + 1
            continue
        if l.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in re.split(r"(?<!\\)\|", lines[i].strip().strip("|"))])
                i += 1
            hd, body = rows[0], [r for r in rows[1:] if not re.fullmatch(r"[-: ]+", "".join(r))]
            cls = ' class="%s"' % table_class if table_class else ""
            out.append('<div class="tw"><table%s><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
                cls, "".join("<th>%s</th>" % inline(c) for c in hd),
                "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % inline(c.replace("\\|", "|")) for c in r) for r in body)))
            continue
        if re.match(r"^\s*(- |\d+\. )", l):
            tag = "ol" if re.match(r"^\s*\d+\. ", l) else "ul"
            items = []
            while i < len(lines) and (re.match(r"^\s*(- |\d+\. )", lines[i]) or (lines[i].startswith("   ") and items)):
                if re.match(r"^\s*(- |\d+\. )", lines[i]):
                    items.append(re.sub(r"^\s*(- |\d+\. )", "", lines[i]))
                else:
                    items[-1] += " " + lines[i].strip()
                i += 1
            out.append("<%s>%s</%s>" % (tag, "".join("<li>%s</li>" % inline(x) for x in items), tag))
            continue
        m = re.match(r"^(#{3,4}) (.*)$", l)
        if m:
            out.append("<h%d>%s</h%d>" % (len(m.group(1)), inline(m.group(2)), len(m.group(1))))
        elif l.strip() and l.strip() != "---" and not l.startswith("<!--"):
            out.append("<p>%s</p>" % inline(l))
        i += 1
    return "\n".join(out)


def build(recs, srcs, md, target, mask):
    by_n = {r["n"]: r for r in recs}
    anchors = {}
    for r in recs:
        anchors[R.slug(R.heading(r))] = "f%d" % r["n"]
        anchors[R.slug(R.heading(r, 6))] = "r%d" % r["n"]
    for i, (_, s) in enumerate(TOC, 1):
        anchors[s] = "s%d" % i
    inline = make_inline(anchors)
    F = []
    for r in recs:
        b = r["body"]
        for w in R.as_lists(b, "5.%s" % r["n"]):  # 文字列のannot等で1文字ずつの<li>にしない（JSの.mapは配列が要る）
            print("WARN: " + w)
        F.append(mask({
            "n": r["n"], "cvssV3Severity": r["severity"], "v3": r["cvss_v3"]["score"], "v3vec": r["cvss_v3"]["vector"],
            "v3sev": r["cvss_v3"]["severity"], "v4": r["cvss_v4"]["score"], "v4vec": r["cvss_v4"]["vector"],
            "v4sev": r["cvss_v4"]["severity"], "unused": bool(r.get("unused")), "title": r["short_summary"],
            "files": R.fmt_files(r["files"]).replace("`", ""), "cats": "、".join(r["categories"]),
            "cwe": ", ".join(r.get("cwe") or []) or r.get("cwe_note", ""), "verdict": r["verdict"],
            "refs": " / ".join(r["references"]), "types": sorted({s["type"] for s in srcs.get("5.%d" % r["n"], [])}),
            "compat": R.COMPAT_LABEL[r["compat"]["classes"]] + ("。" + r["compat"]["note"] if r["compat"].get("note") else ""),
            "design": (R.CONFLICT_YES if r["design"]["conflict"] else R.CONFLICT_NO)
            + ("。" + r["design"]["refs_note"] if r["design"].get("refs_note") else ""),
            "exploit": r.get("exploit_status") or "", "summary": b["summary"], "plain": b["plain"], "tech": b["tech"],
            "code": "\n".join(R.code_block(r, target)[1:-1]), "annot": b["annot"], "scenario": b["scenario"],
            "fix": r["fix"]["diff"] + ("\n" + r["fix"]["note"] if r["fix"].get("note") else ""),
            "fixExpl": b["fix_expl"] + R.xref_text(r, by_n), "residual": b["residual"], "intent": b["intent"],
            "behavior": b["behavior"], "alts": b.get("alts") or [], "altsNote": b.get("alts_note", ""),
            "audit": [r["audit"]["method"], r["audit"]["verdict"], r["audit"]["evidence"]],
            "r3": [[lab, R.metric(r["cvss_v3"]["vector"], k), r["cvss_reasons"]["r3"][k]] for k, lab in R.V3],
            "r4": [[lab, R.metric(r["cvss_v4"]["vector"], k), r["cvss_reasons"]["r4"][k]] for k, lab in R.V4]}))
    md = mask(md)  # HTMLにする前に伏せる（エスケープ後は一致しないことがある）
    s1 = section(md, 1)
    t = s1.find("| 重大度 | 件数 |")
    t_end = s1.find("\n\n", t) if t >= 0 else -1
    s4 = section(md, 4)
    k4 = s4.find("**設計方針との整合（要約）**")
    s6 = section(md, 6)
    k6 = s6.find("\n### 6.")
    static = {"cover": md2html(between(md, "\n", "## 改訂履歴").split("\n", 1)[-1], inline, "cover"),
              "rev": md2html(between(md, "## 改訂履歴", "## 目次"), inline),
              "1s": md2html(s1[:t] if t >= 0 else s1, inline),
              "1n": md2html(s1[t_end:] if t >= 0 and t_end >= 0 else "", inline),
              "4d": md2html(s4[k4:] if k4 >= 0 else "", inline),
              "6c": md2html(s6[:k6] if k6 >= 0 else s6, inline)}
    for n in (2, 3, 7, 8, 9, 10, 11, 12):
        static[str(n)] = md2html(section(md, n), inline)
    static = {k: mask(v) for k, v in static.items()}
    with open(SHELL, encoding="utf-8") as f:
        page = f.read()
    js = lambda o: json.dumps(o, ensure_ascii=False).replace("</", "<\\/")  # noqa: E731
    for ph in ("/*FINDINGS*/[]", "/*STATIC*/{}", "/*TITLE*/"):
        if ph not in page:
            raise ValueError("placeholder %s not in %s" % (ph, SHELL))
    return page.replace("/*FINDINGS*/[]", js(F)).replace("/*STATIC*/{}", js(static)).replace("/*TITLE*/", TITLE)


def run(work, report, target, mask_file, out, force=False):
    if os.path.exists(out) and not force:
        print("error: %s already exists (use --force)" % out)
        return 2
    with open(os.path.join(work, "findings.jsonl"), encoding="utf-8") as f:
        recs = sorted((json.loads(l) for l in f if l.strip()), key=lambda r: r["n"])
    srcs = R.load_sources(os.path.join(work, "sources.json"))
    with open(report, encoding="utf-8") as f:
        md = f.read().replace("\r\n", "\n")
    try:
        page = build(recs, srcs, md, target, Masker(target, mask_file))
    except (R.RecordError, ValueError, KeyError) as e:
        print("error: %s" % e)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)
    print("written %s (%d bytes, %d findings)" % (out, len(page.encode("utf-8")), len(recs)))
    return 0


def self_test():
    rec = {"n": 1, "severity": "High", "short_summary": "SQLi", "files": [{"file": "a.js", "lines": "1"}], "categories": ["入力値検証"],
           "cwe": ["CWE-89"], "verdict": "CONFIRMED", "unused": False, "references": ["IPA x"],
           "cvss_v3": {"score": 7.5, "severity": "High", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
           "cvss_v4": {"score": 8.7, "severity": "High", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
           "cvss_reasons": {"r3": {k: "r" for k, _ in R.V3}, "r4": {k: "r" for k, _ in R.V4}},
           "body": {"summary": "s</script>x", "plain": "p", "tech": "t", "code_ranges": ["a.js:1"], "annot": ["SECRETVALUE1"],
                    "scenario": "sc", "fix_expl": "f", "residual": [], "intent": "i", "behavior": "b", "alts": [], "alts_note": ""},
           "compat": {"classes": "①", "note": ""}, "design": {"conflict": False, "refs_note": ""},
           "audit": {"method": "m", "verdict": "v", "evidence": "e"}, "fix": {"diff": "-a\n+b", "note": ""},
           "xref": {"chain": [], "same": []}}
    md = ("# Webアプリケーション セキュリティ監査報告書\n\n| 項目 | 内容 |\n| --- | --- |\n| 対象システム／リポジトリ | app |\n\n"
          "## 改訂履歴\n\n| 版 | 日付 |\n| --- | --- |\n| 1.0 | d |\n\n## 目次\n\n1. x\n\n## 1. エグゼクティブサマリー\n\n要約である。\n\n"
          "| 重大度 | 件数 |\n| --- | --- |\n| High | 1 |\n\n注記行。\n\n## 2. 実施メタデータ\n\n| 項目 | 内容 |\n| --- | --- |\n| 解析 | t |\n\n"
          "## 4. 指摘サマリー\n\n| No. |\n| --- |\n| [5.1](#51-high-sqli) |\n\n**設計方針との整合（要約）**\n\n| 項目 | 件数 |\n| --- | --- |\n| ① | 1 |\n\n"
          "## 6. リスク分析（CVSSメトリクス詳細）\n\n**CVSS整合性確認**: 整合。\n\n### 6.1 [High] SQLi\n\nx\n\n"
          "## 7. 要確認事項（Plausible判定）\n\n- [5.1](#51-high-sqli)（High）: a | b\n\n## 11. 出典別レポート\n\n- [IPA](security-audit-report-ipa.md)\n")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.js"), "w", encoding="utf-8") as f:
            f.write("const k = 'SECRETVALUE1';\n")
        with open(os.path.join(d, "mask.txt"), "w", encoding="utf-8") as f:
            f.write("SECRETVALUE1\n")
        page = build([rec], {"5.1": [{"type": "IPA", "citation": "x"}]}, md, d, Masker(d, os.path.join(d, "mask.txt")))
        rs = json.loads(json.dumps(rec))  # 文字列の annot・residual（JSの.mapは配列が要る）は行で分けた配列にする
        rs["body"].update(annot="- 1行目: a\n- 1行目: b", residual="残る攻撃。")
        with contextlib.redirect_stdout(io.StringIO()) as so:
            ps = build([rs], {"5.1": [{"type": "IPA", "citation": "x"}]}, md, d, Masker(d, os.path.join(d, "mask.txt")))
        assert '"annot": ["1行目: a", "1行目: b"]' in ps and '"residual": ["残る攻撃。"]' in ps, ps[ps.index("const FINDINGS"):][:600]
        assert so.getvalue().count("WARN: 5.1: ") == 2, so.getvalue()
    assert page.startswith("<!doctype html>") and '<meta charset="utf-8">' in page
    assert "SECRETVALUE1" not in page and "<マスク>" in page
    data = page[page.index("const FINDINGS = "):page.index("const esc")]
    assert "</script" not in data and "<\\/script>" in data
    st = json.loads(re.search(r"const STATIC = (\{.*?\});\n", page).group(1).replace("<\\/", "</"))
    assert '<table class="cover">' in st["cover"] and "app" in st["cover"] and "1.0" in st["rev"]
    assert st["1s"] == "<p>要約である。</p>" and st["1n"] == "<p>注記行。</p>", (st["1s"], st["1n"])
    assert "<strong>設計方針との整合（要約）</strong>" in st["4d"] and "整合。" in st["6c"] and "6.1" not in st["6c"]
    assert '<a href="#f1">5.1</a>' in st["7"] and '<a href="security-audit-report-ipa.md">IPA</a>' in st["11"]
    assert '"types": ["IPA"]' in data and "<title>セキュリティ監査報告書</title>" in page
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ("--work", "--report", "--target", "--mask-file", "--out"):
        ap.add_argument(k)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    need = [k for k in ("work", "report", "target", "mask_file", "out") if not getattr(a, k)]
    if need:
        ap.error("required: " + ", ".join("--" + k.replace("_", "-") for k in need))
    return run(a.work, a.report, a.target, a.mask_file, a.out, a.force)


if __name__ == "__main__":
    sys.exit(main())
