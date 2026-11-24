#!/usr/bin/env python3
"""出典別レポート（モード3手順7。assets/templates/report_template_by_source.md）を findings.jsonl と sources.json から作る。

Usage:
  python3 render_by_source.py --work WORK --target TARGET --mask-file FILE --out-dir REPORTS
      --repo-name NAME --date YYYY-MM-DD [--unified security-audit-report.md] [--sca-raw sca-scan.txt] [--force]
  python3 render_by_source.py --self-test

入力: `WORK/findings.jsonl`・`WORK/sources.json`（`build_findings.py`の出力）、（あれば）`WORK/epss-kev.json`。
`--sca-raw`は`run_sca_scan.sh`の出力を保存したファイル（`== EPSS/KEV ==`より前を3.2の生出力に、`EPSS/KEV:`行を
EPSS・KEVの要約に使う）。SCAタグの指摘があるのに無ければNG。
指摘の詳細は`render_findings_s56.py`の5.Nと同じ部品で作り、表だけを出典別の形（統合レポート上の番号・この出典での根拠）
にする。グループは出典ごとの規定（IPAは1章の11脆弱性名の順＋2章、ASVSは章番号、Cheat Sheetは初出順のシート名、
CWEは番号順で補助の表のものに「（Top 25外・補助）」）。各グループ内は5.N順。未使用の指摘は判定に「（未使用・実質問題なし）」。
該当0件の出典はファイルを作らない。出力: `<out-dir>/security-audit-report-<slug>.md`と、統合レポート末尾の
「出典別レポート」節に貼る行（作ったファイルと、作らなかった出典）を標準出力へ。秘密値は`render_findings_s56.py`と
同じく伏せる。既存の出力があれば`--force`が無い限りrc2。判断を含まない。Stdlib only, Python 3.9+.
"""
import argparse
import collections
import contextlib
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

SOURCES = (("IPA", "ipa", "IPA「安全なウェブサイトの作り方」", "脆弱性名"),
           ("OWASP_ASVS", "owasp-asvs", "OWASP ASVS", "章番号"),
           ("OWASP_CheatSheet", "owasp-cheatsheets", "OWASP Cheat Sheet Series", "シート名"),
           ("CWE", "cwe-top25", "CWE", "CWE番号"),
           ("ISM", "ism", "ISM（Information Security Manual）データベースの管理策", "管理策ID"),
           ("SCA", "sca", "SCA（依存関係の既知脆弱性）", None))
# references/sources/ipa-secure-website.md 1章の11脆弱性名（テンプレートの表記）と、citationを当てる語
IPA_GROUPS = (("SQLインジェクション", "SQLインジェクション"), ("OSコマンドインジェクション", "OSコマンド"),
              ("パス名パラメータ未検証", "パス名パラメータ"), ("セッション管理不備", "セッション管理"),
              ("クロスサイトスクリプティング", "クロスサイト・?スクリプティング"), ("CSRF", "CSRF|リクエスト・?フォージェリ"),
              ("HTTPヘッダインジェクション", "HTTPヘッダ"), ("メールヘッダインジェクション", "メールヘッダ"),
              ("クリックジャッキング", "クリックジャッキング"), ("バッファオーバーフロー", "バッファ"),
              ("アクセス制御や認可制御の不備", "アクセス制御|認可制御"))
IPA_CH2 = "2章 ウェブサイトの安全性向上のための取り組み"
ASVS_NAMES = {1: "Encoding and Sanitization", 2: "Validation and Business Logic", 3: "Web Frontend Security",
              4: "API and Web Service", 5: "File Handling", 6: "Authentication", 7: "Session Management",
              8: "Authorization", 9: "Self-contained Tokens", 10: "OAuth and OIDC", 11: "Cryptography",
              12: "Secure Communication", 13: "Configuration", 14: "Data Protection",
              15: "Secure Coding and Architecture", 16: "Security Logging and Error Handling", 17: "WebRTC"}


def aux_cwes(path=None):
    path = path or os.path.join(HERE, "..", "references", "sources", "cwe-top25.md")
    with open(path, encoding="utf-8") as f:
        text = f.read()
    i = text.find("## 補助")
    return {int(m.group(1)) for m in re.finditer(r"^\| CWE-(\d+) \|", text[i:], re.M)} if i >= 0 else set()


def ipa_group(citation):
    if citation.startswith("2章"):
        return IPA_CH2
    for name, pat in IPA_GROUPS:
        if re.search(pat, citation):
            return name
    return None


def groups(t, recs, srcs, aux):
    """[(group_name, [(rec, citation_text)])]、groupの順は出典ごとの規定。"""
    tagged = [(r, s) for r in recs for s in srcs["5.%d" % r["n"]] if s["type"] == t]
    g, warn = collections.OrderedDict(), []
    if t == "IPA":
        order = [n for n, _ in IPA_GROUPS] + [IPA_CH2]
        tmp = collections.defaultdict(list)
        for r, s in tagged:
            name = ipa_group(s["citation"])
            if name is None:
                warn.append("5.%d: IPA citation %r matches no 1章 name; grouped by itself" % (r["n"], s["citation"]))
                name = s["citation"]
                order.append(name)
            tmp[name].append((r, s["citation"] + "（IPA）"))
        for name in order:
            if tmp.get(name):
                g[name] = tmp[name]
    elif t == "OWASP_ASVS":
        tmp = collections.defaultdict(list)
        for r, s in tagged:
            m = re.search(r"V(\d+)", s["citation"])
            if not m:
                warn.append("5.%d: ASVS citation %r has no chapter" % (r["n"], s["citation"]))
                continue
            tmp[int(m.group(1))].append((r, s["citation"]))
        for ch in sorted(tmp):
            g["V%d: %s" % (ch, ASVS_NAMES.get(ch, ""))] = tmp[ch]
    elif t == "OWASP_CheatSheet":
        for r, s in tagged:
            g.setdefault('"%s"' % s["citation"], []).append((r, 'OWASP Cheat Sheet "%s"' % s["citation"]))
    elif t == "ISM":
        tmp = collections.defaultdict(list)
        for r, s in tagged:
            m = re.match(r"ISM-(\d{4})$", s["citation"].strip())
            if not m:
                warn.append("5.%d: ISM citation %r is not ISM-NNNN" % (r["n"], s["citation"]))
                continue
            tmp[int(m.group(1))].append((r, s["citation"].strip()))
        for c in sorted(tmp):
            g["ISM-%04d" % c] = tmp[c]
    elif t == "CWE":
        tmp = collections.defaultdict(list)
        for r, s in tagged:
            tmp[int(s["citation"].split("-")[1])].append((r, s["citation"]))
        for c in sorted(tmp):
            g["CWE-%d%s" % (c, "（Top 25外・補助）" if c in aux else "")] = tmp[c]
    return [(k, sorted(v, key=lambda x: x[0]["n"])) for k, v in g.items()], warn


def finding_block(r, num, citation, by_n, target):
    lines = R.render_s5(r, by_n, target)
    body = lines[lines.index("**概要**"):]
    meta = {}
    for row in R.meta_table(r)[2:]:
        k, _, v = row.strip().strip("|").partition("|")
        meta[k.strip()] = v.strip()
    verdict = r["verdict"] + ("（未使用・実質問題なし）" if r.get("unused") else "")
    c3, c4 = r["cvss_v3"], r["cvss_v4"]
    out = ["#### %s [%s] %s" % (num, r["severity"], r["short_summary"]), "", "| 項目 | 内容 |", "| --- | --- |",
           "| ファイル | %s |" % meta["ファイル"], "| 判定 | %s |" % verdict,
           "| CVSS v3.1 | %s（%s） / ベクター: `%s` |" % (c3["score"], c3["severity"], c3["vector"]),
           "| CVSS v4.0 | %s（%s） / ベクター: `%s` |" % (c4["score"], c4["severity"], c4["vector"]),
           "| 統合レポート上の番号 | 5.%d（CVSSメトリクス単位の判定根拠は統合レポート6.%d） |" % (r["n"], r["n"]),
           "| この出典での根拠 | %s |" % citation, "| 互換性の区分 | %s |" % meta["互換性の区分"],
           "| 設計方針との整合 | %s |" % meta["設計方針との整合"]]
    if r.get("exploit_status"):
        out.append("| 悪用状況（EPSS/KEV） | %s |" % r["exploit_status"])
    return out + [""] + body


def sca_parts(sca_raw, ek):
    with open(sca_raw, encoding="utf-8") as f:
        text = f.read()
    i = text.find("== EPSS/KEV ==")
    raw = (text[:i] if i >= 0 else text).rstrip()
    m = re.search(r"^EPSS/KEV: (.*)$", text, re.M)
    summary = None
    if m:
        summary = "EPSS・KEV（悪用状況）: %s。" % m.group(1).rstrip("。")
        if ek:
            src = ek.get("sources") or {}
            summary += "取得日時 %s、KEVカタログ版 %s、EPSSの基準日 %s。" % (
                ek.get("retrieved_at"), (src.get("kev") or {}).get("catalog_version"), (src.get("epss") or {}).get("score_date"))
        summary += "勧告ごとの値は統合レポート8節を参照。"
        if ek and (ek.get("sources") or {}).get("epss", {}).get("attribution"):
            summary += ek["sources"]["epss"]["attribution"]
    return raw, summary


def render(recs, srcs, target, repo, date, unified, sca_raw=None, ek=None, aux=None):
    aux = aux_cwes() if aux is None else aux
    by_n = {r["n"]: r for r in recs}
    made, skipped, warn, ng = [], [], [], []
    for r in recs:
        warn += R.as_lists(r.get("body", {}), "5.%s" % r.get("n"))
    present = {t for t, *_ in SOURCES if any(s["type"] == t for v in srcs.values() for s in v)}
    missing = ["5.%d" % r["n"] for r in recs if "5.%d" % r["n"] not in srcs]
    if missing:
        return [], [], [], ["sources.json lacks " + ", ".join(missing)]
    if "SCA" in present and not sca_raw:
        return [], [], [], ["SCA tags exist but --sca-raw was not given"]
    texts = {}
    for t, slug_, disp, gh in SOURCES:
        if t not in present:
            skipped.append(disp)
            continue
        L = ["# セキュリティ監査報告書（%s観点）" % disp, "", "| 項目 | 内容 |", "| --- | --- |",
             "| 対象システム／リポジトリ | %s |" % repo,
             "| 本レポートの位置づけ | 統合レポート（`%s`）から%sの観点で根拠付けられる指摘のみを抽出し、%s自身の構成で並べ替えた抽出版 |" % (unified, disp, disp),
             "| 作成日 | %s |" % date, "| 機密区分 | 社外秘 |", "",
             "本レポートは、統合レポート（`%s`）で検出した指摘のうち、**%sの観点から根拠付けられるものだけ**を抽出し、%s自身の構成で並べ替えたものである。他の出典も含めた全体像・実施メタデータ（解析日時・使用エージェント構成等）は統合レポートを参照のこと。" % (unified, disp, disp),
             "", "## 目次", "", "1. [この観点でのサマリー](#1-この観点でのサマリー)"]
        if gh:
            L += ["2. [%s別の指摘](#2-%s別の指摘)" % (gh, R.slug(gh)), "3. [SCA（依存関係脆弱性）スキャン結果](#3-sca依存関係脆弱性スキャン結果)"]
        else:
            L += ["2. [SCA（依存関係脆弱性）スキャン結果](#3-sca依存関係脆弱性スキャン結果)"]
        L += ["", "---", ""]
        body, count = [], []
        if gh:
            gs, w = groups(t, recs, srcs, aux)
            warn += w
            body += ["## 2. %s別の指摘" % gh, ""]
            for gi, (gname, items) in enumerate(gs, 1):
                body += ["### 2.%d %s" % (gi, gname), ""]
                for ii, (r, cit) in enumerate(items, 1):
                    body += finding_block(r, "2.%d.%d" % (gi, ii), cit, by_n, target)
                    count.append(r)
            body += ["## 3. SCA（依存関係脆弱性）スキャン結果", "",
                     "依存関係の既知脆弱性のスキャン結果と個別指摘は、統合レポートの8節とSCA観点の出典別レポート（`security-audit-report-sca.md`）を参照のこと。"
                     if "SCA" in present else "依存関係の既知脆弱性のスキャン結果は、統合レポートの8節を参照のこと。", ""]
        else:
            raw, summary = sca_parts(sca_raw, ek)
            body += ["## 3. SCA（依存関係脆弱性）スキャン結果", "", "### 3.1 個別指摘", ""]
            items = [(r, s["citation"]) for r in recs for s in srcs["5.%d" % r["n"]] if s["type"] == "SCA"]
            for ii, (r, cit) in enumerate(items, 1):
                body += finding_block(r, "3.1.%d" % ii, "SCA: " + cit, by_n, target)
                count.append(r)
            body += ["### 3.2 スキャンツール生出力（付録）", "", "```text", raw, "```", ""]
            if summary:
                body += [summary, ""]
        c = collections.Counter(r["severity"] for r in count)
        L += ["## 1. この観点でのサマリー", "", "| 重大度 | 件数 |", "| --- | --- |"]
        L += ["| %s | %d |" % (s, c[s]) for s in ("Critical", "High", "Medium", "Low")]
        L += ["| 要確認 (Plausible) | %d |" % sum(1 for r in count if r["verdict"] == "PLAUSIBLE"), "",
              "件数は本レポートの指摘見出し（見出しレベル4）の数である。" + (
                  "1件の指摘が複数のグループに属する場合は、グループごとに数えている（重複を含む）。" if gh else ""), ""]
        texts[slug_] = (L + body, t, disp)
        made.append((disp, "security-audit-report-%s.md" % slug_, len(count), len({r["n"] for r in count})))
    out = {}
    for slug_, (L, t, disp) in texts.items():
        others = ", ".join("[%s](security-audit-report-%s.md)" % (d, s) for tt, s, d, _ in SOURCES if tt != t and s in texts)
        L = L + ["---", "", "統合レポート・他の出典別レポートへのリンク: [統合レポート](%s)%s" % (unified, ", " + others if others else ""), ""]
        out["security-audit-report-%s.md" % slug_] = "\n".join(L)
    return out, made, skipped, warn + ng


def run(work, target, mask_file, out_dir, repo, date, unified, sca_raw=None, force=False):
    with open(os.path.join(work, "findings.jsonl"), encoding="utf-8") as f:
        recs = sorted((json.loads(l) for l in f if l.strip()), key=lambda r: r["n"])
    srcs = R.load_sources(os.path.join(work, "sources.json"))
    ekp = os.path.join(work, "epss-kev.json")
    ek = None
    if os.path.exists(ekp):
        with open(ekp, encoding="utf-8") as f:
            ek = json.load(f)
    try:
        out, made, skipped, msgs = render(recs, srcs, target, repo, date, unified, sca_raw, ek)
    except R.RecordError as e:
        print("error: %s" % e)
        return 1
    if not out and msgs:
        for m in msgs:
            print("NG: " + m)
        return 1
    for m in msgs:
        print("WARN: " + m)
    exist = [n for n in out if os.path.exists(os.path.join(out_dir, n))]
    if exist and not force:
        print("error: %s already exist(s) (use --force)" % ", ".join(exist))
        return 2
    mask = Masker(target, mask_file)
    os.makedirs(out_dir, exist_ok=True)
    for name, text in out.items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(mask(text))
    print("## 出典別レポート（統合レポートの末尾に貼る）")
    for disp, name, n_head, n_uniq in made:
        print("- [%s](%s)（指摘見出し %d件、統合レポート上の指摘 %d件）" % (disp, name, n_head, n_uniq))
    if skipped:
        print("- 該当指摘が0件のため作成しなかった出典: " + "、".join(skipped))
    return 0


def self_test():
    rec = {"n": 1, "severity": "High", "short_summary": "SQLi", "files": [{"file": "a.js", "lines": "1-2"}],
           "categories": ["入力値検証"], "cwe": ["CWE-89"], "verdict": "CONFIRMED", "unused": False,
           "references": ["x"], "exploit_status": None,
           "cvss_v3": {"score": 7.5, "severity": "High", "vector": "CVSS:3.1/AV:N"},
           "cvss_v4": {"score": 8.7, "severity": "High", "vector": "CVSS:4.0/AV:N"},
           "cvss_reasons": {"r3": {}, "r4": {}}, "body": {"summary": "s", "plain": "p", "tech": "t", "code_ranges": ["a.js:1-2"],
                                                         "annot": ["a"], "scenario": "sc", "fix_expl": "f", "residual": [],
                                                         "intent": "i", "behavior": "b", "alts": [], "alts_note": ""},
           "compat": {"classes": "①", "note": ""}, "design": {"conflict": False, "refs_note": ""},
           "audit": {"method": "m", "verdict": "v", "evidence": "e"}, "fix": {"diff": "-a\n+b", "note": "", "source": "blue"},
           "xref": {"chain": [], "same": []}}
    rec2 = dict(rec, n=2, severity="Low", short_summary="dep", unused=True, exploit_status="対象: GHSA-x。…", cwe=["CWE-1104"])
    srcs = {"5.1": [{"type": "IPA", "citation": "1章 SQLインジェクション"}, {"type": "OWASP_ASVS", "citation": "v5.0 第1章(V1)"},
                    {"type": "CWE", "citation": "CWE-89"}, {"type": "ISM", "citation": "ISM-1277"}],
            "5.2": [{"type": "IPA", "citation": "2章 ウェブサイトの安全性向上のための取り組み（HTTPS化）"},
                    {"type": "CWE", "citation": "CWE-1104"}, {"type": "SCA", "citation": "npm audit"}]}
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "t"))
        with open(os.path.join(d, "t", "a.js"), "w", encoding="utf-8") as f:
            f.write("q = 'SELECT ' + x\nrun(q)\n")
        with open(os.path.join(d, "sca.txt"), "w", encoding="utf-8") as f:
            f.write("== npm audit ==\nlodash high\n== EPSS/KEV ==\nrow\nEPSS/KEV: 取得済み（CVE 1件、KEV掲載 0件）\n")
        out, made, skipped, msgs = render([rec, rec2], srcs, os.path.join(d, "t"), "app", "2026-01-01", "u.md",
                                          os.path.join(d, "sca.txt"), None, aux={1104})
        assert not msgs, msgs
        # 文字列の annot・residual（r14・r15・DB run 3）: 1文字ずつの箇条にせず行で分け、WARN（render_findings_s56.as_lists）
        rs = json.loads(json.dumps(dict(rec, n=3)))
        rs["body"].update(annot="- 1行目: 連結している\n- 2行目: 実行している", residual="残る攻撃。")
        rs["cvss_reasons"] = {"r3": {k: "r" for k, _ in R.V3}, "r4": {k: "r" for k, _ in R.V4}}
        rs["cvss_v3"]["vector"] = "CVSS:3.1/" + "/".join(k + ":N" for k, _ in R.V3)
        rs["cvss_v4"]["vector"] = "CVSS:4.0/" + "/".join(k + ":N" for k, _ in R.V4)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            s56 = R.render([json.loads(json.dumps(rs))], os.path.join(d, "t"), [])
        assert "- 1行目: 連結している\n- 2行目: 実行している\n" in s56 and "- 残る攻撃。\n" in s56, s56
        assert not re.search(r"^- .$", s56, re.M) and err.getvalue().count("WARN: 5.3: ") == 2, err.getvalue()
        out3, _, _, msgs3 = render([rs], {"5.3": [{"type": "IPA", "citation": "1章 SQLインジェクション"}]}, os.path.join(d, "t"),
                                   "app", "d", "u.md", None, None, aux=set())
        assert not re.search(r"^- .$", out3["security-audit-report-ipa.md"], re.M) and len(msgs3) == 2, msgs3
        assert sorted(out) == ["security-audit-report-%s.md" % s for s in ("cwe-top25", "ipa", "ism", "owasp-asvs", "sca")], sorted(out)
        assert skipped == ["OWASP Cheat Sheet Series"], skipped
        ipa = out["security-audit-report-ipa.md"]
        assert "### 2.1 SQLインジェクション" in ipa and "### 2.2 2章 ウェブサイトの安全性向上のための取り組み" in ipa, ipa
        assert "#### 2.2.1 [Low] dep" in ipa and "CONFIRMED（未使用・実質問題なし）" in ipa and "| 悪用状況（EPSS/KEV） |" in ipa
        assert "2. [脆弱性名別の指摘](#2-脆弱性名別の指摘)" in ipa and "| 統合レポート上の番号 | 5.1（" in ipa
        cwe = out["security-audit-report-cwe-top25.md"]
        assert "### 2.2 CWE-1104（Top 25外・補助）" in cwe and "### 2.1 CWE-89\n" in cwe
        ism = out["security-audit-report-ism.md"]
        assert "### 2.1 ISM-1277" in ism and "| この出典での根拠 | ISM-1277 |" in ism, ism
        _, _, _, msgs2 = render([rec], {"5.1": [{"type": "ISM", "citation": "1277"}]}, os.path.join(d, "t"), "app",
                                "2026-01-01", "u.md", os.path.join(d, "sca.txt"), None, aux={1104})
        assert any("ISM-NNNN" in m for m in msgs2), msgs2
        asvs = out["security-audit-report-owasp-asvs.md"]
        assert "### 2.1 V1: Encoding and Sanitization" in asvs and "| Critical | 0 |" in asvs and "| High | 1 |" in asvs
        sca = out["security-audit-report-sca.md"]
        assert "#### 3.1.1 [Low] dep" in sca and "lodash high" in sca and "row" not in sca.split("```text")[1].split("```")[0]
        assert "EPSS・KEV（悪用状況）: 取得済み（CVE 1件、KEV掲載 0件）。" in sca and "2. [SCA" in sca
        assert "[統合レポート](u.md), [IPA" in sca
        _, _, _, msgs = render([rec, rec2], srcs, os.path.join(d, "t"), "app", "d", "u.md", None, None, aux=set())
        assert msgs and "--sca-raw" in msgs[0]
        _, _, _, msgs = render([rec], {}, os.path.join(d, "t"), "app", "d", "u.md", None, None, aux=set())
        assert msgs and "lacks 5.1" in msgs[0]
        assert ipa_group("1章 パス名パラメータの未検証によるディレクトリ・トラバーサル") == "パス名パラメータ未検証"
        assert ipa_group("1章 CSRF（クロスサイト・リクエスト・フォージェリ）") == "CSRF"
        assert ipa_group("1章 クロスサイト・スクリプティング") == "クロスサイトスクリプティング"
        assert 1104 in aux_cwes() and 89 not in aux_cwes()
        assert "# セキュリティ監査報告書（CWE観点）" in cwe
        with open(os.path.join(d, "s.json"), "w", encoding="utf-8") as f:  # 旧名のタグ（保存済みの実行）
            json.dump({"5.1": [{"type": "CWE_Top25", "citation": "CWE-89"}]}, f)
        assert R.load_sources(os.path.join(d, "s.json")) == {"5.1": [{"type": "CWE", "citation": "CWE-89"}]}
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ("--work", "--target", "--mask-file", "--out-dir", "--repo-name", "--date", "--sca-raw"):
        ap.add_argument(k)
    ap.add_argument("--unified", default="security-audit-report.md")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    need = [k for k in ("work", "target", "mask_file", "out_dir", "repo_name", "date") if not getattr(a, k)]
    if need:
        ap.error("required: " + ", ".join("--" + k.replace("_", "-") for k in need))
    return run(a.work, a.target, a.mask_file, a.out_dir, a.repo_name, a.date, a.unified, a.sca_raw, a.force)


if __name__ == "__main__":
    sys.exit(main())
