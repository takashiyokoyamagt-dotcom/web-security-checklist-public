#!/usr/bin/env python3
"""統合レポート（Markdown。assets/templates/report_template.md）を、保存済みのデータとArbiterの文章から組み立てる（モード3手順5）。

Usage:
  python3 assemble_report.py --work WORK --prose report-prose.json --out REPORT.md
      [--by-source-dir DIR] [--sca-raw sca-scan.txt] [--force]
  python3 assemble_report.py --self-test

データ（WORK）: `findings.jsonl`・`sources.json`・`s56.md`（render_findings_s56.py）・`out/red-NN.jsonl`・
`out/blue-NN.jsonl`・（あれば）`epss-kev.json`。スクリプトが作るもの: 表紙・改訂履歴・目次・本書について、
1節の件数表と注記、2節の表（`meta_rows`の後に参照基準）、3節（カテゴリは principles.md の11の順。
`red-NN`が無いカテゴリは「未起動」）、4節の指摘サマリー表と設計方針の要約表、5・6節（s56.mdをそのまま）、
7節のPlausibleの一覧と未使用の一覧、8節のEPSS・KEVの表と取得日時、11節（`--by-source-dir`の出典別ファイル）。
Arbiterの文章（`--prose`。JSON。文字列はMarkdown）:
  必須: `repo_name`・`date`・`author`・`overall_summary`・`meta_rows`（[[項目,内容],…]。2節の参照基準以外）・
  `consistency_note`（6節冒頭）・`unreproduced`（7節「実機で再現できなかった主張」の本文）・`self_review`・`actions`・`disclaimer`
  任意: `report_id`（既定「(未採番)（<date> 実施分）」）・`execution_label`・`intro`・`plausible_intro`・`sca_text`（8節冒頭。
  SCA未実施ならその旨）・`epss_status`（無ければ`--sca-raw`の`EPSS/KEV:`行）・`design`（`{"decision":[N],"decision_note":…,
  "stale":[N],"violate":[N],"unclear":[N]}`。4節の要約の判断を含む行）・`unwritten`（未執筆項目の["U1（主題）",…]）・
  `s7_extra`（7節末尾に足す文章。未執筆項目の節等）・`by_source`（`--by-source-dir`が無いときの11節）・
  `ops_requests`（DBの運用の確認依頼。[[ID,確認依頼,理由],…]。12節の末尾に表で載せる。references/checklists/database/ops-requests.md）。
互換性の区分・衝突・要検討（WRITERの`review`が空でない指摘）は findings.jsonl から数える。並びは5.N順。
既存の出力があれば`--force`が無い限りrc2。Stdlib only, Python 3.9+.
"""
import argparse
import collections
import glob
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from render_findings_s56 import slug, heading  # noqa: E402

SEVS = ("Critical", "High", "Medium", "Low")
REQUIRED = ("repo_name", "date", "author", "overall_summary", "meta_rows", "consistency_note", "unreproduced",
            "self_review", "actions", "disclaimer")
TOC = (("エグゼクティブサマリー", "1-エグゼクティブサマリー"), ("実施メタデータ", "2-実施メタデータ"),
       ("カテゴリ別実施状況", "3-カテゴリ別実施状況"), ("指摘サマリー", "4-指摘サマリー"), ("指摘詳細", "5-指摘詳細重大度順"),
       ("リスク分析（CVSSメトリクス詳細）", "6-リスク分析cvssメトリクス詳細"), ("要確認事項（Plausible判定）", "7-要確認事項plausible判定"),
       ("SCA（依存関係脆弱性）スキャン結果", "8-sca依存関係脆弱性スキャン結果"), ("自己レビュー（見落とし確認）", "9-自己レビュー見落とし確認"),
       ("次のアクション（推奨優先順位）", "10-次のアクション推奨優先順位"), ("出典別レポート", "11-出典別レポート"),
       ("本報告書に関する留意事項", "12-本報告書に関する留意事項"))
EXEC_LABEL = "マルチエージェント監査レビュー（Red Team / Blue Team / Arbiter方式、総合監査モード）。各役割の説明は「本書について」参照"
INTRO = ("本報告書は、IPA「安全なウェブサイトの作り方」・OWASP ASVS・OWASP Cheat Sheet Series・CWE Top 25・依存関係のSCA（既知脆弱性の検査）を"
         "基準に、後述の3役割によるマルチエージェント監査レビューを実施した結果をまとめたものである。指摘ごとに、専門知識を前提としない解説と"
         "技術的な詳細解説の両方を併記し、技術者以外の読者にも内容を理解できるよう配慮している。重大度はCVSS v3.1の定量的区分を正とし、"
         "CVSS v4.0のスコアを併記する。")
STD_DECISION = "―（厳格度が標準のため5eの記録なし。設計方針に従えない場合は代替案の表を参照）"
SOURCE_FILES = (("ipa", "IPA「安全なウェブサイトの作り方」", "IPA"), ("owasp-asvs", "OWASP ASVS", "OWASP_ASVS"),
                ("owasp-cheatsheets", "OWASP Cheat Sheet Series", "OWASP_CheatSheet"), ("cwe-top25", "CWE", "CWE"),
                ("ism", "ISM（データベースの管理策）", "ISM"),
                ("sca", "SCA（依存関係の既知脆弱性）", "SCA"))


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(s) for s in (l.strip() for l in f) if s]


def categories(path=None):
    path = path or os.path.join(HERE, "..", "references", "checklists", "principles.md")
    with open(path, encoding="utf-8") as f:
        return [(int(m.group(1)), m.group(2)) for m in re.finditer(r"^## (\d+)\. (\S+) \(", f.read(), re.M)]


def ids(ns):
    return "、".join("5.%d" % n for n in ns) if ns else "―"


def link(r):
    return "[5.%d](#%s)" % (r["n"], slug(heading(r)))


def compat_class(r):
    c = r["compat"]["classes"]
    return "③" if "③" in c else "②" if "②" in c else "①"


def epss_rows(ek):
    rows = []
    for e in ek.get("entries", []):
        adv = "https://github.com/advisories/%s" % e["id"] if e["id"].startswith("GHSA-") else "https://osv.dev/vulnerability/%s" % e["id"]
        if e.get("status") in ("no_cve", "error"):
            why = (e.get("error") or "").split(" (")[0].replace("|", "\\|")
            cve = "CVEなし（対象外）" if e["status"] == "no_cve" else "不明（%s）" % why
            dash = "―" if e["status"] == "no_cve" else "未取得（同上）"
            rows.append("| %s | %s | %s | %s | %s | [勧告](%s) |" % (e["id"], cve, dash, dash, dash, adv))
            continue
        for it in e.get("items", []):
            u = it.get("urls") or {}
            urls = " ".join("[%s](%s)" % ("勧告" if k == "advisory" else k.upper(), v) for k, v in u.items() if v)
            st = it.get("epss_status")
            if st == "ok":
                ep, pc = it["epss"], it["percentile"]
            elif st == "not_found":
                ep = pc = "該当なし"
            else:
                ep = pc = "未取得（%s）" % str(it.get("epss_error") or "").split(" (")[0].replace("|", "\\|")
            if it.get("kev") is True:
                kev = "掲載（%s登録）" % it["kev_date_added"] if it.get("kev_date_added") else "掲載（登録日不明）"
            elif it.get("kev") is False:
                kev = "非掲載"
            else:
                kev = "未取得（%s）" % str((ek.get("sources") or {}).get("kev", {}).get("error") or "不明").split(" (")[0]
            rows.append("| %s | %s | %s | %s | %s | %s |" % (e["id"], it["cve"], ep, pc, kev, urls))
    return rows


def null_cell(ek, key):
    """nullの catalog_version（key="kev"）・score_date（"epss"）の欄: 取得失敗なら「未取得（理由）」、対象が無ければ
    「なし（理由）」（report_template.md 8節。fetch_epss_kev.py --check-report と同じ判定）"""
    ents = ek.get("entries") or []
    items = [i for e in ents for i in e.get("items") or []]
    osv = [e.get("error") or "OSV" for e in ents if e.get("status") == "error"] if not items else []
    if key == "kev":
        kerr = ((ek.get("sources") or {}).get("kev") or {}).get("error")
        err = [kerr] if kerr else osv
    else:
        err = [i.get("epss_error") or "EPSS" for i in items if i.get("epss_status") == "error"] or osv
    if err:
        return "未取得（%s）" % str(err[0]).split(" (")[0]
    if not ents:
        return "なし（脆弱性IDなし）"
    if not items:
        return "なし（対象のCVEなし）"
    return "なし（%s）" % ("カタログに版の記載なし" if key == "kev" else "全CVEがEPSSに該当なし")


def assemble(work, prose, by_source_dir=None, sca_raw=None):
    miss = [k for k in REQUIRED if not prose.get(k)]
    if miss:
        return None, ["--prose lacks " + ", ".join(miss)]
    J = lambda n: os.path.join(work, n)  # noqa: E731
    recs = sorted(load_jsonl(J("findings.jsonl")), key=lambda r: r["n"])
    with open(J("s56.md"), encoding="utf-8") as f:
        s56 = f.read()
    i6 = s56.find("\n### 6.")
    if i6 < 0:
        return None, ["s56.md has no ### 6.N section"]
    s5, s6 = s56[:i6].strip("\n"), s56[i6:].strip("\n")
    ek = None
    if os.path.exists(J("epss-kev.json")):
        with open(J("epss-kev.json"), encoding="utf-8") as f:
            ek = json.load(f)
    date = prose["date"]
    L = []
    A = L.append
    cnt = collections.Counter(r["severity"] for r in recs)
    npl = sum(1 for r in recs if r["verdict"] == "PLAUSIBLE")
    A("# Webアプリケーション セキュリティ監査報告書")
    A("")
    A("| 項目 | 内容 |")
    A("| --- | --- |")
    A("| 対象システム／リポジトリ | %s |" % prose["repo_name"])
    A("| 報告書番号 | %s |" % prose.get("report_id", "(未採番)（%s 実施分）" % date))
    A("| 作成日 | %s |" % date)
    A("| 実施体制 | %s |" % prose.get("execution_label", EXEC_LABEL))
    A("| 機密区分 | 社外秘 |")
    A("")
    L += ["## 改訂履歴", "", "| 版 | 日付 | 内容 | 作成者 |", "| --- | --- | --- | --- |",
          "| 1.0 | %s | 初版作成 | %s |" % (date, prose["author"]), "", "## 目次", ""]
    L += ["%d. [%s](#%s)" % (i, t, s) for i, (t, s) in enumerate(TOC, 1)]
    L += ["", "## 本書について", "", prose.get("intro", INTRO), "", "**実施体制（役割分担）**", "",
          "本報告書は、以下の3つの役割によるマルチエージェント監査で作成している。単一視点によるレビューでは見落としが出やすいため、指摘を出す役割と検証する役割を分離し、誤検知を減らしている。",
          "",
          "- **Red Team（検出担当）**: 攻撃者視点でコードの脆弱性を洗い出し、具体的な攻撃シナリオとともに指摘する。",
          "- **Blue Team（検証担当）**: Red Teamの指摘を、実コードの文脈（呼び出し元・ミドルウェア・既存の対策等）に照らして実際に悪用可能か検証し、誤検知を排除する。修正案が実際に機能するかの監査レビューもこの段階で行う。",
          "- **Arbiter（判定担当）**: Red Team・Blue Team双方の結果を集約し、重複の整理・最終的な重大度判定・本報告書の作成を行う。",
          "", "---", "", "## 1. エグゼクティブサマリー", "", prose["overall_summary"], "", "| 重大度 | 件数 |", "| --- | --- |"]
    L += ["| %s | %d |" % (s, cnt[s]) for s in SEVS]
    A("| 要確認 (Plausible / Blue Teamで確証に至らず) | %d |" % npl)
    A("")
    nz = sum(1 for r in recs if r["cvss_v3"]["score"] == 0)  # 0件なら注記を省く（cvss-scoring.md）
    A("上表の重大度別件数は5節の全%d件（Plausibleの%d件を含む）である。%s" % (
        len(recs), npl, "CVSS v3.1のスコアが0.0（None）の%d件はLowに数えている。" % nz if nz else ""))
    unused = [r["n"] for r in recs if r.get("unused")]
    if unused:
        A("うち参照0件で現状は未使用のため実質問題なし: %d件（%s）" % (len(unused), ids(unused)))
    if prose.get("unwritten"):
        A("上表は未執筆項目%sを含まない（7節参照）" % "、".join(prose["unwritten"]))
    L += ["", "## 2. 実施メタデータ", "", "| 項目 | 内容 |", "| --- | --- |"]
    L += ["| %s | %s |" % (k, v) for k, v in prose["meta_rows"]]
    A("| 参照基準 | IPA「安全なウェブサイトの作り方」, OWASP ASVS, OWASP Cheat Sheet Series, CWE Top 25, CVSS v3.1, CVSS v4.0 |")
    L += ["", "## 3. カテゴリ別実施状況", "", "| カテゴリ | 起動 | Confirmed件数 | 備考 |", "| --- | --- | --- | --- |"]
    for i, c in categories():
        rp, bp = J("out/red-%02d.jsonl" % i), J("out/blue-%02d.jsonl" % i)
        fin = sorted({r["n"] for r in recs if c in r["categories"]})
        if not os.path.exists(rp):
            A("| %s | 未起動 | 0 | 統合後の最終指摘: %s |" % (c, ids(fin) if fin else "なし"))
            continue
        red = load_jsonl(rp)
        blue = load_jsonl(bp) if os.path.exists(bp) else []
        v = collections.Counter(str(b.get("verdict", "")).split()[0] if b.get("verdict") else "" for b in blue)
        A("| %s | Red 1 / Blue %d | %d | Red指摘%d件（Blue判定: CONFIRMED %d・PLAUSIBLE %d・REFUTED %d）。統合後の最終指摘: %s |" % (
            c, 1 if os.path.exists(bp) else 0, v["CONFIRMED"], len(red), v["CONFIRMED"], v["PLAUSIBLE"], v["REFUTED"],
            "、".join("5.%d" % n for n in fin) or "なし"))
    L += ["", "Confirmed件数はBlue TeamがCONFIRMEDと判定したRed指摘の件数（統合前）である。統合（5b）により、複数カテゴリの指摘が1件の最終指摘にまとまっているため、カテゴリ別の件数の合計は5節の件数と一致しない。",
          "", "## 4. 指摘サマリー", "", "| No. | 重大度 | CVSS v3.1 | CVSS v4.0 | ファイル | 概要 | 判定 |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in recs:
        files = ", ".join("`%s:%s`" % (f["file"], f["lines"]) if f.get("lines") else "`%s`" % f["file"] for f in r["files"])
        A("| %s | %s | %s | %s | %s | %s | %s |" % (link(r), r["severity"], r["cvss_v3"]["score"], r["cvss_v4"]["score"], files,
                                                    r["short_summary"], r["verdict"] + ("（未使用・実質問題なし）" if r.get("unused") else "")))
    grp = collections.defaultdict(list)
    for r in recs:
        grp[compat_class(r)].append(r["n"])
    conf = [r["n"] for r in recs if r["design"]["conflict"]]
    rev = [r["n"] for r in recs if r.get("review")]
    d = prose.get("design") or {}
    dec = d.get("decision") or []
    dec_cell = ids(dec) if dec else d.get("decision_note", STD_DECISION if "decision" not in d else "―")
    L += ["", "**設計方針との整合（要約）**", "", "| 項目 | 件数 | 該当する指摘（5.N） |", "| --- | --- | --- |",
          "| 互換性の区分①（正常な利用での挙動は変えない） | %d | %s |" % (len(grp["①"]), ids(grp["①"])),
          "| 互換性の区分②（APIまたはデータ形式が変わる） | %d | %s |" % (len(grp["②"]), ids(grp["②"])),
          "| 互換性の区分③（運用の変更が要る） | %d | %s |" % (len(grp["③"]), ids(grp["③"])),
          "| 設計方針との衝突あり（設計方針に従えない。`design_conflict`有り） | %d | %s |" % (len(conf), ids(conf)),
          "| 修正案が「要検討」の指摘（コードだけでは直せず設計判断が要る。`fix_suggestion`） | %d | %s |" % (len(rev), ids(rev)),
          "| 利用者判断事項 | %d | %s |" % (len(dec), dec_cell)]
    for k, lab in (("stale", "設計書が古い"), ("violate", "コードが設計に反する"), ("unclear", "区別できない")):
        L.append("| 食い違い: %s | %d | %s |" % (lab, len(d.get(k) or []), ids(d.get(k) or [])))
    L += ["", "利用者判断事項は、貴社が決める必要のある事項である（設計方針に従うと脆弱性が残る場合や、修正で元の処理の意図が損なわれる場合に、どの案を採るか等）。内容は該当指摘の代替案のブロックと10節に記載する。設計書の有無は2節を参照。", ""]
    multi = sorted({r["compat"]["classes"] for r in recs if len(r["compat"]["classes"]) > 1}, reverse=True)
    if multi:
        L += ["区分の併記（%s）は最も大きい番号の区分に1回だけ数えている。" % "・".join(multi), ""]
    L += ["## 5. 指摘詳細（重大度順）", "", s5, "", "## 6. リスク分析（CVSSメトリクス詳細）", "",
          "**CVSS整合性確認**: " + prose["consistency_note"],
          "**判定記録**: 各指摘のメトリクス判定の証拠行・棄却した別案・レビュー要否は、2節記載の判定記録ファイルの`id`（本章の6.N）で参照できる（判定の理由文はこの章の`判定根拠`が正）。",
          "", s6, "", "## 7. 要確認事項（Plausible判定）", ""]
    pl = [r for r in recs if r["verdict"] == "PLAUSIBLE"]
    if prose.get("plausible_intro"):
        L += [prose["plausible_intro"], ""]
    if pl:
        L += ["- %s（%s、CVSS v3.1 %s）: %s" % (link(r), r["severity"], r["cvss_v3"]["score"], r["summary_line"]) for r in pl]
    else:
        L.append("- なし（Plausibleの指摘は無い）。")
    L += ["", "**実機で再現できなかった主張**", "", prose["unreproduced"], "", "**参照0件のコード・設定を採点した指摘**", ""]
    L += (["- %s（%s）: 現状は未使用のため実質問題なし。" % (link(r), r["short_summary"]) for r in recs if r.get("unused")]
          or ["- なし（判定質問を全て満たす未使用の指摘は無い）。"])
    if prose.get("s7_extra"):
        L += ["", prose["s7_extra"]]
    L += ["", "## 8. SCA（依存関係脆弱性）スキャン結果", ""]
    if prose.get("sca_text"):
        L += [prose["sca_text"], ""]
    status = prose.get("epss_status")
    if not status and sca_raw and os.path.exists(sca_raw):
        with open(sca_raw, encoding="utf-8") as f:
            m = re.search(r"^EPSS/KEV: (.*)$", f.read(), re.M)
        status = m.group(1).strip() if m else None
    if status:
        L += ["**EPSS・KEV（悪用状況）**: " + status, ""]
    if ek:
        rows = epss_rows(ek)
        if rows:
            L += ["| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |", "| --- | --- | --- | --- | --- | --- |"] + rows + [""]
        src = ek.get("sources") or {}
        kv, sd = (src.get("kev") or {}).get("catalog_version"), (src.get("epss") or {}).get("score_date")
        L += ["取得日時: %s、KEVカタログ版: %s、EPSSの基準日: %s。EPSS data from FIRST (https://www.first.org/epss/)" % (
            ek.get("retrieved_at"), kv or null_cell(ek, "kev"), sd or null_cell(ek, "epss")), ""]
        notes = []
        lim = src.get("id_limit") or {}
        if lim.get("excluded"):
            notes.append("- 件数上限で除外したID: %d件（%s）" % (lim["excluded"], "、".join(lim.get("excluded_ids") or [])))
        if (src.get("kev") or {}).get("error"):
            notes.append("- KEV未取得: %s" % src["kev"]["error"])
        if src.get("tls_ca"):
            notes.append("- CA証明書を切り替えて取得した: %s" % src["tls_ca"])
        if notes:
            L += notes + [""]
    L += ["## 9. 自己レビュー（見落とし確認）", "", prose["self_review"], "", "## 10. 次のアクション（推奨優先順位）", "",
          prose["actions"], "", "## 11. 出典別レポート", ""]
    if by_source_dir:
        made = [(disp, "security-audit-report-%s.md" % s) for s, disp, _ in SOURCE_FILES
                if os.path.exists(os.path.join(by_source_dir, "security-audit-report-%s.md" % s))]
        for disp, name in made:
            with open(os.path.join(by_source_dir, name), encoding="utf-8") as f:
                t = f.read()
            heads = len(re.findall(r"^#### ", t, re.M))
            uniq = len(set(re.findall(r"^\| 統合レポート上の番号 \| 5\.(\d+)", t, re.M)))
            L.append("- [%s](%s)（指摘見出し %d件、統合レポート上の指摘 %d件）" % (disp, name, heads, uniq))
        none = [disp for s, disp, _ in SOURCE_FILES if (disp, "security-audit-report-%s.md" % s) not in made]
        if none:
            L.append("- 該当指摘が0件のため作成しなかった出典: " + "、".join(none))
    else:
        L.append(prose.get("by_source") or "出典別レポートは作成していない。")
    L += ["", "## 12. 本報告書に関する留意事項", "", prose["disclaimer"], ""]
    ops = prose.get("ops_requests") or []
    if ops:
        if any(not isinstance(r, list) or len(r) != 3 or not all(str(x).strip() for x in r) for r in ops):
            return "", ["ops_requests: each row must be [ID, 確認依頼, 理由] with non-empty strings"]
        L += ["### 運用の確認依頼（データベース）", "",
              "リポジトリでは確かめられない事項。指摘ではなく、運用での確認をお願いするもの。", "",
              "| ID | 確認依頼 | 依頼の理由（リポジトリで見えたこと） |", "| --- | --- | --- |"]
        L += ["| %s | %s | %s |" % tuple(str(x).replace("|", "\\|").replace("\n", " ") for x in r) for r in ops]
        L.append("")
    return "\n".join(L), []


def run(work, prose_path, out, by_source_dir=None, sca_raw=None, force=False):
    if os.path.exists(out) and not force:
        print("error: %s already exists (use --force)" % out)
        return 2
    with open(prose_path, encoding="utf-8") as f:
        prose = json.load(f)
    text, ng = assemble(work, prose, by_source_dir, sca_raw)
    for x in ng:
        print("NG: " + x)
    if ng:
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("written %s (%d lines)" % (out, text.count("\n") + 1))
    return 0


def self_test():
    rec = {"n": 1, "severity": "High", "short_summary": "SQLi", "summary_line": "s", "verdict": "PLAUSIBLE", "unused": False,
           "files": [{"file": "a.js", "lines": "1-2"}], "categories": ["入力値検証"],
           "cvss_v3": {"score": 7.5}, "cvss_v4": {"score": 8.7}, "compat": {"classes": "②③"}, "design": {"conflict": True},
           "review": "x"}
    rec2 = dict(rec, n=2, severity="Low", short_summary="dep", verdict="CONFIRMED", unused=True, categories=["依存関係管理"],
                cvss_v3={"score": 0.0}, compat={"classes": "①"}, design={"conflict": False}, review="")
    prose = {k: "P-" + k for k in REQUIRED}
    prose["meta_rows"] = [["解析開始日時", "t0"]]
    with tempfile.TemporaryDirectory() as d:
        J = lambda n: os.path.join(d, n)  # noqa: E731
        os.makedirs(J("out"))
        with open(J("findings.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps(rec2, ensure_ascii=False) + "\n" + json.dumps(rec, ensure_ascii=False) + "\n")
        with open(J("s56.md"), "w", encoding="utf-8") as f:
            f.write("### 5.1 [High] SQLi\n\nbody\n\n### 6.1 [High] SQLi\n\nrisk\n")
        with open(J("out/red-01.jsonl"), "w", encoding="utf-8") as f:
            f.write('{"id":"R0101"}\n{"id":"R0102"}\n')
        with open(J("out/blue-01.jsonl"), "w", encoding="utf-8") as f:
            f.write('{"n":"R0101","verdict":"PLAUSIBLE 根拠"}\n{"n":"R0102","verdict":"REFUTED"}\n')
        with open(J("epss-kev.json"), "w", encoding="utf-8") as f:
            json.dump({"retrieved_at": "T", "sources": {"kev": {"catalog_version": "K"}, "epss": {"score_date": "E"}},
                       "entries": [{"id": "GHSA-a", "status": "ok", "items": [{"cve": "CVE-1", "epss": 0.1, "percentile": 0.2,
                                                                               "epss_status": "ok", "kev": True, "kev_date_added": None,
                                                                               "urls": {"epss": "u1", "advisory": "u2"}}]},
                                   {"id": "PYSEC-1", "status": "no_cve"}]}, f)
        bs = J("bs")
        os.makedirs(bs)
        open(os.path.join(bs, "security-audit-report-ipa.md"), "w").close()
        text, ng = assemble(d, prose, bs)
        assert not ng, ng
        assert "| Low | 1 |" in text and "| 要確認 (Plausible / Blue Teamで確証に至らず) | 1 |" in text
        assert "CVSS v3.1のスコアが0.0（None）の1件はLowに数えている。" in text and "実質問題なし: 1件（5.2）" in text
        assert "| 入力値検証 | Red 1 / Blue 1 | 0 | Red指摘2件（Blue判定: CONFIRMED 0・PLAUSIBLE 1・REFUTED 1）。統合後の最終指摘: 5.1 |" in text
        assert "| 認証 | 未起動 | 0 | 統合後の最終指摘: なし |" in text
        assert "| [5.1](#51-high-sqli) | High | 7.5 | 8.7 | `a.js:1-2` | SQLi | PLAUSIBLE |" in text
        assert "| dep | CONFIRMED（未使用・実質問題なし） |" in text
        assert "| 互換性の区分③（運用の変更が要る） | 1 | 5.1 |" in text and "| 互換性の区分①（正常な利用での挙動は変えない） | 1 | 5.2 |" in text
        assert "| 修正案が「要検討」の指摘（コードだけでは直せず設計判断が要る。`fix_suggestion`） | 1 | 5.1 |" in text
        assert "| 利用者判断事項 | 0 | " + STD_DECISION + " |" in text and "区分の併記（②③）" in text
        assert "- [5.1](#51-high-sqli)（High、CVSS v3.1 7.5）: s" in text and "- [5.2](#52-low-dep)（dep）: 現状は未使用" in text
        assert "| GHSA-a | CVE-1 | 0.1 | 0.2 | 掲載（登録日不明） | [EPSS](u1) [勧告](u2) |" in text
        assert "| PYSEC-1 | CVEなし（対象外） | ― | ― | ― | [勧告](https://osv.dev/vulnerability/PYSEC-1) |" in text
        assert "取得日時: T、KEVカタログ版: K、EPSSの基準日: E。" in text
        assert "- [IPA「安全なウェブサイトの作り方」](security-audit-report-ipa.md)（指摘見出し 0件、統合レポート上の指摘 0件）" in text and "作成しなかった出典: OWASP ASVS、" in text
        assert text.index("### 5.1") < text.index("## 6.") < text.index("### 6.1") < text.index("## 7.")
        _, ng = assemble(d, dict(prose, actions=""))
        assert ng and "actions" in ng[0]
        text, _ = assemble(d, dict(prose, design={"decision": [1], "stale": [2]}))
        assert "| 利用者判断事項 | 1 | 5.1 |" in text and "| 食い違い: 設計書が古い | 1 | 5.2 |" in text
        with open(J("findings.jsonl"), "w", encoding="utf-8") as f:  # 5b補足3の①③は③に数える
            f.write(json.dumps(dict(rec2, compat={"classes": "①③"}), ensure_ascii=False) + "\n" + json.dumps(rec, ensure_ascii=False) + "\n")
        text, _ = assemble(d, prose)
        assert "| 互換性の区分③（運用の変更が要る） | 2 | 5.1、5.2 |" in text
        assert "区分の併記（②③・①③）" in text
        with open(J("findings.jsonl"), "w", encoding="utf-8") as f:  # 0.0の指摘が無ければ件数の注記を省く
            f.write(json.dumps(dict(rec2, cvss_v3={"score": 3.1}), ensure_ascii=False) + "\n" + json.dumps(rec, ensure_ascii=False) + "\n")
        text, _ = assemble(d, prose)
        assert "含む）である。\n" in text and "0.0（None）" not in text
        text, ng = assemble(d, dict(prose, ops_requests=[["DB-OPS-03", "待受と規則の確認", "composeで5432を公開"]]))
        assert not ng and "### 運用の確認依頼（データベース）" in text
        assert "| DB-OPS-03 | 待受と規則の確認 | composeで5432を公開 |" in text
        assert text.index("## 12.") < text.index("### 運用の確認依頼")
        _, ng = assemble(d, dict(prose, ops_requests=[["DB-OPS-03", "", "x"]]))
        assert ng and "ops_requests" in ng[0]
        text, _ = assemble(d, prose)
        assert "運用の確認依頼" not in text
        # nullのKEVカタログ版・EPSSの基準日は理由付き。fetch_epss_kev.py --check-report の判定と突き合わせる
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import fetch_epss_kev as fek
        src = {"epss": {"api": "a", "score_date": None, "attribution": "x"},
               "kev": {"url": "k", "catalog_version": None, "date_released": None, "sha256": None, "error": None},
               "osv": {"api": "o"}, "tls_ca": None, "id_limit": {"max_ids": 200, "excluded": 0, "excluded_ids": [], "note": None}}
        for ents, want in (([], "KEVカタログ版: なし（脆弱性IDなし）、EPSSの基準日: なし（脆弱性IDなし）。"),
                           ([{"id": "GHSA-2222-3333-4444", "status": "error", "error": "OSV: タイムアウト (x)", "cves": [], "items": []}],
                            "KEVカタログ版: 未取得（OSV: タイムアウト）、EPSSの基準日: 未取得（OSV: タイムアウト）。"),
                           ([{"id": "PYSEC-2024-1", "status": "no_cve", "error": None, "cves": [], "items": []}],
                            "KEVカタログ版: なし（対象のCVEなし）、EPSSの基準日: なし（対象のCVEなし）。")):
            doc = {"schema": 1, "retrieved_at": "2026-11-22T00:00:00Z", "sources": src, "entries": ents}
            with open(J("epss-kev.json"), "w", encoding="utf-8") as f:
                json.dump(doc, f)
            text, _ = assemble(d, dict(prose, epss_status=fek.status_line(doc)[len("EPSS/KEV: "):]))
            assert want in text, want
            ng, _ = fek.check_report_text(text, doc)
            assert not ng, ng
        assert [c for _, c in categories()][:2] == ["入力値検証", "認証"] and len(categories()) == 11
    print("self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ("--work", "--prose", "--out", "--by-source-dir", "--sca-raw"):
        ap.add_argument(k)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.work and a.prose and a.out):
        ap.error("--work, --prose and --out are required")
    return run(a.work, a.prose, a.out, a.by_source_dir, a.sca_raw, a.force)


if __name__ == "__main__":
    sys.exit(main())
