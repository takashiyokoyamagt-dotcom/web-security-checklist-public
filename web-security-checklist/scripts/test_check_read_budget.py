import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import check_read_budget as crb  # noqa: E402


def copy_tree():
    d = tempfile.mkdtemp(prefix="crb_")
    for sub in ("references", "assets", "scripts"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(d, sub), ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("SKILL.md", "manifest.json"):
        shutil.copy(os.path.join(ROOT, f), os.path.join(d, f))
    return d


class Fixture(unittest.TestCase):
    def setUp(self):
        self.d = copy_tree()
        self.addCleanup(shutil.rmtree, self.d, True)

    def manifest(self):
        with open(os.path.join(self.d, "manifest.json"), encoding="utf-8") as f:
            return json.load(f)

    def run_check(self, m=None):
        m = m or self.manifest()
        ng, _, rows, _ = crb.check(self.d, m)
        return ng, rows

    def edit(self, rel, old, new):
        p = os.path.join(self.d, rel)
        with open(p, "rb") as f:
            t = f.read().decode("utf-8")
        self.assertIn(old, t)
        with open(p, "wb") as f:
            f.write(t.replace(old, new, 1).encode("utf-8"))

    def has(self, ng, code):
        self.assertTrue(any(x.startswith("[" + code + "]") for x in ng), (code, ng))

    def step(self, m, mode, name):
        return next(s for s in m["modes"][mode]["steps"] if s["name"] == name)

    def test_real_manifest_passes_with_exact_totals(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "check_read_budget.py"), "--json"], capture_output=True)
        out = json.loads(r.stdout.decode("utf-8"))
        self.assertEqual(r.returncode, 0, out["problems"])
        self.assertEqual(out["problems"], [])
        by = {x["reader"]: x["bytes"] for x in out["readers"]}
        self.assertEqual(by["mode3:R1"] - by["mode3:G0"], 0)
        self.assertEqual(by["mode3:G0"], 62940)  # P7モード2修正の後（旧63,288）
        self.assertEqual(by["mode2"], 86416)  # 手順4の前まで（ゲートM4の前。P7第5回修正の後、旧86,480）
        self.assertEqual(by["mode2:M4"], 170484)  # ゲートM4の後の累計（finding-final.mdを含む。P7第5回修正の後、旧170,548）
        self.assertEqual(by["mode3:G7"], 294609)  # P7第5回修正の後（旧294,618）
        self.assertEqual(os.path.getsize(os.path.join(ROOT, "SKILL.md")), 15274)  # P6第2弾とレビュー修正で15293から変更（その前は15718）

    def test_file_in_skill_md_missing_from_manifest(self):
        m = self.manifest()
        self.step(m, "2", "required6")["required"].remove("references/cvss/cvss.md")
        self.has(self.run_check(m)[0], "mode2-list")

    def test_extra_file_in_manifest(self):
        m = self.manifest()
        self.step(m, "2", "required6")["required"].append("references/checklists/database/sqli.md")
        self.has(self.run_check(m)[0], "mode2-list")
        m = self.manifest()
        self.step(m, "3", "G6")["required"].append("references/checklists/database/sqli.md")
        self.has(self.run_check(m)[0], "gate-files-checker")

    def test_mode2_gate_m4_mismatch(self):
        m = self.manifest()
        self.step(m, "2", "M4")["required"].pop()
        ng = self.run_check(m)[0]
        self.has(ng, "mode2-gate")
        self.has(ng, "mode2-gate-token")
        self.edit("SKILL.md", "と`references/cvss/cvss-scoring.md`（5fの判定基準", "と（5fの判定基準")
        self.has(self.run_check()[0], "mode2-gate")
        m = self.manifest()
        self.step(m, "2", "M4")["gate_token"][0]["value"] = "G3A-000000"
        self.has(self.run_check(m)[0], "mode2-gate-token")

    def test_missing_file(self):
        os.remove(os.path.join(self.d, "references", "sources", "cwe-top25.md"))
        self.has(self.run_check()[0], "missing-file")

    def test_budget_exceeded(self):
        m = self.manifest()
        m["budgets"]["orchestrator"]["mode2"]["bytes"] -= 1
        ng, _ = self.run_check(m)
        self.has(ng, "budget")
        m = self.manifest()
        m["budgets"]["roles"]["SYNTH"]["bytes"] -= 1
        self.has(self.run_check(m)[0], "budget")

    def test_g0_budget_must_equal_checker(self):
        m = self.manifest()
        m["budgets"]["orchestrator"]["mode3:G0"]["bytes"] = 70000
        self.has(self.run_check(m)[0], "g0-budget")

    def test_gate_token_mismatch(self):
        m = self.manifest()
        self.step(m, "3", "G1")["gate_token"][0]["id"] = "G9"
        self.has(self.run_check(m)[0], "gate-token")
        m = self.manifest()
        self.step(m, "3", "G3")["gate_token"].pop()
        self.has(self.run_check(m)[0], "gate-token")

    def test_gate_order_mismatch(self):
        m = self.manifest()
        st = m["modes"]["3"]["steps"]
        i = [s["name"] for s in st].index("G5")
        st[i], st[i + 1] = st[i + 1], st[i]
        ng, _ = self.run_check(m)
        self.has(ng, "gate-order")
        self.has(ng, "gate-marker-order")

    def test_gate_marker_changed_in_doc(self):
        self.edit("references/modes/mode3-full-audit.md", "<!--gate:G6 mode3-only files=references/modes/mode3-html.md-->", "<!--gate:G6 mode3-only files=references/modes/mode3-report.md-->")
        self.has(self.run_check()[0], "gate-files-marker")

    def test_unknown_role(self):
        m = self.manifest()
        m["roles"]["GHOST"] = {"reads": [], "source": "x"}
        m["budgets"]["roles"]["GHOST"] = {"basis": "worst", "bytes": 0}
        self.has(self.run_check(m)[0], "role")
        m = self.manifest()
        del m["roles"]["MECH"]
        del m["budgets"]["roles"]["MECH"]
        self.has(self.run_check(m)[0], "role")

    def test_structure_errors(self):
        m = self.manifest()
        del m["environments"]
        self.has(self.run_check(m)[0], "structure")
        m = self.manifest()
        m["roles"]["RED"]["unverified"] = True
        m["roles"]["RED"].pop("reason", None)
        self.has(self.run_check(m)[0], "structure")

    def test_skill_md_list_change_detected(self):
        self.edit("SKILL.md", "- G6（手順6の前）: `references/modes/mode3-html.md`", "- G6（手順6の前）: `references/modes/mode3-html.md`, `references/checklists/database/sqli.md`")
        self.has(self.run_check()[0], "gate-files-skill")

    def test_raised_budget_needs_reason(self):
        m = self.manifest()
        m["budgets"]["roles"]["SYNTH"]["bytes"] += 100
        self.has(self.run_check(m)[0], "budget-raised")
        m["budgets"]["roles"]["SYNTH"]["raised_reason"] = {"date": "2026-11-07", "approver": "reviewer", "text": "test"}
        ng, _, _, extra = crb.check(self.d, m)
        self.assertEqual(ng, [])
        self.assertEqual(len(extra["warnings"]), 1)
        self.assertIn("roles/SYNTH", extra["warnings"][0])
        m["budgets"]["roles"]["SYNTH"]["raised_reason"] = {"date": "soon", "approver": "", "text": "x"}
        self.has(self.run_check(m)[0], "structure")

    def test_budget_above_baseline_needs_reason(self):
        p = os.path.join(self.d, "scripts", "read-budget-baseline.json")
        with open(p, encoding="utf-8") as f:
            b = json.load(f)
        b["budgets"]["orchestrator"]["mode2"]["bytes"] -= 5  # manifest is within margin but above baseline
        with open(p, "w", encoding="utf-8") as f:
            json.dump(b, f)
        self.has(self.run_check()[0], "budget-raised")
        m = self.manifest()
        m["budgets"]["orchestrator"]["mode2"]["raised_reason"] = {"date": "2026-11-07", "approver": "reviewer", "text": "t"}
        ng, _, _, extra = crb.check(self.d, m)
        self.assertEqual((ng, len(extra["warnings"])), ([], 1))

    def test_baseline_missing_reader(self):
        p = os.path.join(self.d, "scripts", "read-budget-baseline.json")
        with open(p, encoding="utf-8") as f:
            b = json.load(f)
        del b["budgets"]["roles"]["RED"]
        with open(p, "w", encoding="utf-8") as f:
            json.dump(b, f)
        self.has(self.run_check()[0], "baseline")

    def test_gate_token_value_mismatch(self):
        m = self.manifest()
        tk = self.step(m, "3", "G5")["gate_token"][0]
        tk["value"] = tk["id"] + "-000000"
        self.has(self.run_check(m)[0], "gate-token")

    def test_lang_class_counts_largest(self):
        _, rows = self.run_check()
        by = {r["reader"]: r for r in rows}
        self.assertEqual(by["mode1"]["bytes"], os.path.getsize(os.path.join(ROOT, "SKILL.md")) + os.path.getsize(os.path.join(ROOT, "references", "checklists", "principles.md")))
        n, note = crb.size_of(ROOT, "references/lang/*.md")
        self.assertEqual(n, max(os.path.getsize(p) for p in [os.path.join(ROOT, "references", "lang", x) for x in os.listdir(os.path.join(ROOT, "references", "lang"))]))
        self.assertIn("largest", note)

    def test_determinism(self):
        outs = []
        for _ in range(2):
            r = subprocess.run([sys.executable, os.path.join(HERE, "check_read_budget.py")], capture_output=True)
            outs.append(hashlib.sha256(r.stdout).hexdigest())
        self.assertEqual(outs[0], outs[1])


if __name__ == "__main__":
    unittest.main()
