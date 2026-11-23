#!/usr/bin/env python3
"""check_read_gates.py のテスト（合成JSONLのみ。実行: python -m unittest test_check_read_gates）"""
import contextlib, io, json, os, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_read_gates as crg  # noqa: E402

MANIFEST = os.path.join(HERE, "..", "manifest.json")
ROOT = "C:\\skills\\web-security-checklist\\"


def A(*blocks):
    return json.dumps({"type": "assistant", "message": {"content": list(blocks)}}, ensure_ascii=False)


_N = [0]


def read(rel, win=False, offset=None, limit=None, res=None, root=None):
    """res: None=正常な結果を自動付与 / "error" / "none"(tool_resultを付けない)"""
    base = root or (ROOT if win else "/skills/web-security-checklist/")
    p = base + (rel.replace("/", "\\") if win else rel)
    inp = {"file_path": p}
    if offset is not None:
        inp["offset"] = offset
    if limit is not None:
        inp["limit"] = limit
    _N[0] += 1
    b = {"type": "tool_use", "name": "Read", "id": "tu%d" % _N[0], "input": inp}
    if res:
        b["_res"] = res
    return b


def finish(lines):
    """各Readのtool_use_idに対応するuser行(tool_result)を直後に足す。"""
    out = []
    for ln in lines:
        out.append(ln)
        try:
            d = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(d, dict) or d.get("type") != "assistant" or not isinstance(d.get("message"), dict):
            continue
        c = d["message"].get("content")
        if not isinstance(c, list):
            continue
        for b in c:
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "Read" and b.get("_res") != "none":
                err = b.get("_res") == "error"
                out.append(json.dumps({"type": "user", "message": {"content": [
                    {"type": "tool_result", "tool_use_id": b["id"], "is_error": err,
                     "content": "denied" if err else "ok"}]}}))
    return out


def text(s):
    return {"type": "text", "text": s}


def agent(desc="Red Team 起動"):
    return {"type": "tool_use", "name": "Agent", "input": {"description": desc, "prompt": desc}}


def write(p):
    return {"type": "tool_use", "name": "Write", "input": {"file_path": p, "content": "x"}}


def mfiles(mode, key="required"):
    with open(MANIFEST, encoding="utf-8") as f:
        m = json.load(f)
    return [x for s in m["modes"][str(mode)]["steps"] for x in s.get(key, [])]


def mode3_lines(skip_read=None, token_before=False, drop_token=None, read_after_agent=None, win=False, extra=None):
    L = []
    reads = [f for f in mfiles(3) if f != skip_read and f != read_after_agent]
    # G6/G7 のファイルも含めて先に読む（Agent前）
    for f in reads:
        L.append(A(read(f, win)))
    toks = {"G1-7c41d9", "G2-0092ba", "G3A-9e018b", "G3B-d3e31e", "G3F-4b7e2c", "G5-12e8fa", "G6-a54483", "G7-c0eee4"}
    if drop_token:
        toks.discard(drop_token)
    L.append(A(text("GATE-TOKEN:" + " GATE-TOKEN:".join(sorted(toks))))) if not token_before else None
    L.append(A(text("G2: 設計書なし（探索: 直下、候補0件）")))
    L.append(A(agent()))
    if read_after_agent:
        L.append(A(read(read_after_agent, win)))
    L.append(A(agent("5d 5f CVSS 委任")))
    L.append(A(write("/out/security-audit-report.md")))
    L.append(A(write("/out/report.html")))
    L.append(A(write("/out/security-audit-report-ipa.md")))
    L.append(A(text("ゲート読了: G0 G1 G2 G3 G5 G6 G7 すべて通過")))
    if extra:
        L.extend(extra)
    return L


def m2_steps():
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)["modes"]["2"]["steps"]


def mode2_lines(skip=None, agent_first=None, final=None, gate_skip=None, drop_token=None, gate_after_5f=False):
    pre = [x for s in m2_steps() if not s.get("gate") for x in s["required"]]
    gate = [x for s in m2_steps() if s.get("gate") for x in s["required"]]
    toks = [t["value"] for s in m2_steps() if s.get("gate") for t in s["gate_token"]]
    L = []
    for f in pre:
        if f == skip or f == agent_first:
            continue
        L.append(A(read(f)))
    L.append(A(agent()))
    if agent_first:
        L.append(A(read(agent_first)))
    if gate_after_5f:
        L.append(A(agent("5f CVSS 委任")))
    for f in gate:  # ゲートM4: 手順4の前に読み、トークンを引用する
        if f != gate_skip:
            L.append(A(read(f)))
    L.append(A(text("GATE-TOKEN:" + " GATE-TOKEN:".join(x for x in toks if x != drop_token))))
    stems = [os.path.basename(f)[:-3] for f in pre + gate if f != "SKILL.md"]
    L.append(A(text(final if final is not None else "読了: " + ", ".join(stems))))
    return L


def idx_of(L, rel):
    return next(i for i, x in enumerate(L) if '"Read"' in x and rel in x)


FINDING = """### 5.{n} [High] テスト指摘

| 項目 | 内容 |
| --- | --- |
| CVSS v3.1 | 9.8（Critical） |
{v4}| 根拠 | CWE-89 |

**わかりやすい解説（専門知識を前提としない説明）**
a
**技術的詳細解説**
b
**該当コードの問題点**
c
**修正内容の解説**
d
**修正案の監査レビュー**
e
"""
V4 = "| CVSS v4.0 | 9.3（Critical） |\n"


def report(drop_ch=None, drop_v4_in=None, n=2):
    out = []
    for c in crg.CHAPTERS:
        if c[0] == drop_ch:
            continue
        out.append("## %d. %s\n" % (c[0], c[1]))
        if c[0] == 5:
            for i in range(1, n + 1):
                out.append(FINDING.format(n=i, v4="" if i == drop_v4_in else V4))
    return "\n".join(out)


class Base(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)

    def p(self, name, content):
        path = os.path.join(self.td.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def run_main(self, args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = crg.main(["--manifest", MANIFEST] + args)
        return rc, buf.getvalue()

    def tr(self, lines, name="s.jsonl"):
        return self.p(name, "\n".join(finish(lines)) + "\n")


class Mode3(Base):
    def test_all_compliant(self):
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(mode3_lines())])
        self.assertEqual(rc, 0, out)

    def test_windows_backslash_paths(self):
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(mode3_lines(win=True))])
        self.assertEqual(rc, 0, out)

    def test_file_read_after_agent(self):
        rc, out = self.run_main(["--mode", "3", "--transcript",
                                 self.tr(mode3_lines(read_after_agent="references/pipeline/finding-pipeline.md"))])
        self.assertEqual(rc, 1)
        self.assertIn("手順開始後に読了", out)

    def test_missing_token(self):
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(mode3_lines(drop_token="G3B-d3e31e"))])
        self.assertEqual(rc, 1)
        self.assertIn("トークン未引用: G3B", out)

    def test_token_before_read(self):
        L = [A(text("GATE-TOKEN:G1-7c41d9"))] + mode3_lines(drop_token="G1-7c41d9")
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(L)])
        self.assertEqual(rc, 1)
        self.assertIn("Read前にしか", out)

    def test_unread_file(self):
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(mode3_lines(skip_read="references/sources/cwe-top25.md"))])
        self.assertEqual(rc, 1)
        self.assertIn("未読: references/sources/cwe-top25.md", out)

    def test_unknown_lines_skipped(self):
        L = ["not json", json.dumps({"type": "user", "message": {"content": "hi"}}), "[1,2]",
             json.dumps({"type": "assistant", "message": 5})] + mode3_lines()
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(L)])
        self.assertEqual(rc, 0, out)
        self.assertIn("対象外 4行", out)

    def test_undetermined_no_agent_never_pass(self):
        L = [x for x in mode3_lines() if '"name": "Agent"' not in x]
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(L)])
        self.assertEqual(rc, 3, out)
        self.assertIn("UNDETERMINED [G0]", out)
        self.assertNotIn("PASS [G0]", out)

    def test_undetermined_g6_not_executed(self):
        L = [x for x in mode3_lines() if "report.html" not in x]
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(L)])
        self.assertEqual(rc, 3)
        self.assertIn("UNDETERMINED [G6]", out)

    def test_g2_conditional_unread_without_note_undetermined(self):
        L = [x for x in mode3_lines() if "設計書なし" not in x and "design-intent" not in x]
        L = [x for x in L if "G2-0092ba" not in x or True]
        rc, out = self.run_main(["--mode", "3", "--transcript", self.tr(L)])
        self.assertIn("[G2]", out)
        self.assertEqual(rc, 3, out) if "NG [" not in out else self.assertEqual(rc, 1)


class Mode2(Base):
    def test_compliant(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines())])
        # 条件付きファイルは condition unknown なので exit 3 が正しい
        self.assertEqual(rc, 3, out)
        self.assertIn("condition unknown", out)
        self.assertNotIn("NG [", out)

    def test_missing_file(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(skip="references/cvss/cvss.md"))])
        self.assertEqual(rc, 1)
        self.assertIn("未読: references/cvss/cvss.md", out)

    def test_read_after_agent(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(agent_first="references/core/agent-roles.md"))])
        self.assertEqual(rc, 1)

    def test_final_line_missing(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(final="完了しました"))])
        self.assertEqual(rc, 1)
        self.assertIn("「読了:」行が無い", out)

    def test_gate_m4_compliant(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines()), "--verbose"])
        self.assertIn("PASS [M4]", out)

    def test_gate_m4_unread(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(gate_skip="references/cvss/cvss-scoring.md"))])
        self.assertEqual(rc, 1)
        self.assertIn("NG [M4] 未読: references/cvss/cvss-scoring.md", out)

    def test_gate_m4_token_missing(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(drop_token="G3A-9e018b"))])
        self.assertEqual(rc, 1)
        self.assertIn("トークン未引用: G3A", out)

    def test_gate_m4_read_after_5f(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines(gate_after_5f=True))])
        self.assertEqual(rc, 1)
        self.assertIn("手順4以降に読了", out)

    def test_gate_m4_not_needed_without_agent(self):
        pre = [x for s in m2_steps() if not s.get("gate") for x in s["required"]]
        L = [A(read(f)) for f in pre] + [A(text("読了: " + ", ".join(os.path.basename(f)[:-3] for f in pre if f != "SKILL.md")))]
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(L)])
        self.assertNotIn("NG [", out)
        self.assertIn("UNDETERMINED [M4]", out)

    def test_report_given_makes_mode3_report_required(self):
        rc, out = self.run_main(["--mode", "2", "--transcript", self.tr(mode2_lines()),
                                 "--report", self.p("r.md", report())])
        self.assertEqual(rc, 1)
        self.assertIn("未読(条件成立", out)


class Outputs(Base):
    def test_report_ok(self):
        rc, out = self.run_main(["--mode", "3", "--report", self.p("r.md", report())])
        self.assertIn("RESULT", out)
        self.assertNotIn("NG [report", out)

    def test_missing_chapter(self):
        rc, out = self.run_main(["--mode", "3", "--report", self.p("r.md", report(drop_ch=10))])
        self.assertEqual(rc, 1)
        self.assertIn("必須の章が無い: 10.", out)

    def test_mode2_may_omit_ch9(self):
        rc, out = self.run_main(["--mode", "2", "--report", self.p("r.md", report(drop_ch=9))])
        self.assertNotIn("必須の章が無い", out)

    def test_missing_cvss_in_one_finding(self):
        rc, out = self.run_main(["--mode", "3", "--report", self.p("r.md", report(drop_v4_in=2, n=3))])
        self.assertEqual(rc, 1)
        self.assertIn("1/3件", out)
        self.assertIn("5.2: cvss40", out)

    def test_mode2_bullet_format(self):
        body = ("## 5. 指摘詳細\n[High] x\n- CVSS: v3.1 9.8（Critical） / v4.0 9.3（Critical）\n- 根拠: CWE-89\n"
                "- 該当コードの問題点: a\n- わかりやすい解説: b\n- 技術的詳細解説: c\n- 修正内容の解説: d\n"
                "- 修正案の監査レビュー: e\n")
        fs = crg.split_findings(body)
        self.assertEqual(len(fs), 1)
        res = crg.Result()
        crg.check_report(2, self.p("m2.md", body), res)
        self.assertFalse([i for i in res.items if i[1] == "report-findings" and i[0] != crg.PASS])

    def test_evidence(self):
        d = self.td.name
        rc, out = self.run_main(["--mode", "3", "--evidence-dir", d])
        self.assertEqual(rc, 1)
        self.p("cvss-raw-output.jsonl", "{}\n")
        self.p("cvss-decisions.jsonl", "{}\n")
        rc, out = self.run_main(["--mode", "3", "--evidence-dir", d])
        self.assertEqual(rc, 3, out)  # transcript無しはUNDETERMINED。NGは無い
        self.assertNotIn("NG [", out)
        os.remove(os.path.join(d, "cvss-decisions.jsonl"))
        rc, out = self.run_main(["--mode", "2", "--evidence-dir", d])
        self.assertEqual(rc, 3)

    def test_deterministic_and_json(self):
        a = ["--mode", "3", "--transcript", self.tr(mode3_lines()), "--json"]
        r1 = self.run_main(a)
        r2 = self.run_main(a)
        self.assertEqual(r1, r2)
        self.assertEqual(json.loads(r1[1])["exit"], 0)


class Hardening(Base):
    def m2(self, lines, extra=()):
        return self.run_main(["--mode", "2", "--transcript", self.tr(lines)] + list(extra))

    def test_fenced_chapter_and_cvss_ignored(self):
        body = report(drop_ch=10) + "\n```markdown\n## 10. 次のアクション\n```\n"
        rc, out = self.run_main(["--mode", "3", "--report", self.p("f.md", body)])
        self.assertIn("必須の章が無い: 10.", out)
        fenced = "## 5. 指摘詳細\n```text\n### 5.1 [High] x\n" + FINDING.format(n=1, v4=V4) + "```\n## 6. リスク分析\n"
        self.assertEqual(crg.split_findings(crg.strip_fences(fenced)), [])

    def test_cvss_prose_rejected(self):
        prose = FINDING.format(n=1, v4="").replace("| CVSS v3.1 | 9.8（Critical） |", "| CVSS | 3.1 9.8 |") + "メモ: v4.0 9.3 とされる\n"
        body = "## 5. 指摘詳細\n" + prose + "## 6. リスク分析\n"
        res = crg.Result()
        crg.check_report(3, self.p("p.md", body), res)
        self.assertTrue([i for i in res.items if i[0] == crg.NG and "cvss31" in i[2] and "cvss40" in i[2]])

    def test_errored_read_not_counted(self):
        L = mode2_lines()
        L[idx_of(L, "references/cvss/cvss.md")] = A(read("references/cvss/cvss.md", res="error"))
        rc, out = self.m2(L)
        self.assertEqual(rc, 1)
        self.assertIn("未読: references/cvss/cvss.md", out)

    def test_missing_tool_result_undetermined(self):
        L = mode2_lines()
        L[idx_of(L, "references/cvss/cvss.md")] = A(read("references/cvss/cvss.md", res="none"))
        rc, out = self.m2(L)
        self.assertEqual(rc, 3, out)
        self.assertIn("tool_result", out)

    def test_partial_read_undetermined_then_union_ok(self):
        with open(os.path.join(HERE, "..", "references", "cvss", "cvss.md"), "rb") as f:
            n = len(f.read().split(b"\n"))
        L = mode2_lines()
        L[idx_of(L, "references/cvss/cvss.md")] = A(read("references/cvss/cvss.md", offset=1, limit=5))
        rc, out = self.m2(L)
        self.assertEqual(rc, 3, out)
        self.assertIn("部分読み", out)
        L2 = mode2_lines()
        L2[idx_of(L2, "references/cvss/cvss.md")] = A(read("references/cvss/cvss.md", offset=1, limit=5), read("references/cvss/cvss.md", offset=3, limit=n + 5))
        rc, out = self.m2(L2)
        self.assertNotIn("部分読み", out)
        self.assertNotIn("NG [", out)

    def test_wrong_directory_does_not_satisfy(self):
        L = mode2_lines()
        L[idx_of(L, "references/cvss/cvss.md")] = A(read("references/cvss/cvss.md", root="/x/old/"))
        rc, out = self.m2(L)
        self.assertEqual(rc, 1)
        self.assertIn("未読: references/cvss/cvss.md", out)

    def test_endswith_and_in_mutants_killed(self):
        r = "/skills/web-security-checklist"
        rel = "references/cvss/cvss.md"
        self.assertTrue(crg.path_matches(r + "/" + rel, rel, r))
        self.assertFalse(crg.path_matches("/x/old/" + rel, rel, r))  # endswith だけの実装を殺す
        self.assertFalse(crg.path_matches(r + "/old/" + rel, rel, r))
        self.assertFalse(crg.path_matches(r + "/" + rel + ".bak", rel, r))  # in の実装を殺す
        self.assertFalse(crg.path_matches(r + "/references/../x/cvss.md", rel, r))
        self.assertTrue(crg.path_matches(r + "/x/../" + rel, rel, r))
        self.assertFalse(crg.path_matches(r + "/References/cvss.md", rel, r))  # 大小無視はドライブ文字のみ
        self.assertTrue(crg.path_matches("c:\\Skills\\w\\references\\cvss\\cvss.md", rel, "C:/Skills/w"))
        self.assertTrue(crg.path_matches("C:/Skills/w/references/lang/js.md", "references/lang/*.md", "c:\\Skills\\w"))
        self.assertFalse(crg.path_matches("C:/skills/w/references/cvss/cvss.md", rel, "C:/Skills/w"))

    def test_skill_root_param(self):
        L = mode2_lines()
        rc, out = self.m2(L, ["--skill-root", "/elsewhere/web-security-checklist"])
        self.assertEqual(rc, 1)  # 指定した根の下には読了が無い
        rc, out = self.m2(L, ["--skill-root", "/skills/web-security-checklist"])
        self.assertNotIn("NG [", out)

    def test_multiple_transcripts_in_order(self):
        L = mode2_lines()
        k = next(i for i, x in enumerate(L) if '"Agent"' in x)
        t1 = self.tr(L[:k], "a.jsonl")
        t2 = self.tr(L[k:], "b.jsonl")
        rc, out = self.run_main(["--mode", "2", "--transcript", t1, "--transcript", t2])
        self.assertNotIn("NG [", out)
        self.assertEqual(rc, 3)  # 条件付きは condition unknown のまま

    def test_compaction_marks_earlier_reads_stale(self):
        L = mode2_lines()
        k = next(i for i, x in enumerate(L) if '"Agent"' in x)
        L.insert(k, json.dumps({"type": "summary", "summary": "compacted"}))
        rc, out = self.m2(L)
        self.assertEqual(rc, 3, out)
        self.assertIn("stale", out)
        self.assertNotIn("NG [", out)


if __name__ == "__main__":
    unittest.main()
