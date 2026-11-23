#!/usr/bin/env python3
"""detect_stack.py / run_sca_scan.py（bash版の移植）の検査（unittest・標準ライブラリのみ）。
実行: python test_portable_scripts.py
[1] 固定の期待値: スタックごと・DB検出ごとの一時フィクスチャ、unknown_stack の標準エラー。
[2] 同値性: `git show <移植前のコミット>:web-security-checklist/scripts/<name>.sh` で取り出した元のbash版を、OSの一時ディレクトリで
    bash で実行し、同じ入力で標準出力・標準エラー・終了コードを比べる（bash が無ければ skip）。
    環境変数 WSC_REQUIRE_ORIG=1 のときは、元のbash版を取り出せなければ skip せず失敗にする（CI用）。
    SCAはPATH上の偽ツール（Windowsでは .cmd、bash版用にシェルのshimも）と偽の fetch_epss_kev.py を使い、
    実スキャンやEPSS/KEVの通信はしない。
[3] 対象パスに空白・日本語・`;`・`$(...)`・バッククォートを含むときに、コマンドとして実行されないこと。
Python 3.9以上。"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
IS_WIN = os.name == "nt"
# 移植前（bash版）の最後のコミット。main はマージ後に移植版になるため、ブランチ名ではなくコミットで固定する。
ORIG_REF = "a4c5fc37fc0619f958bcab621a5d4d01c35f4558"
REQUIRE_ORIG = os.environ.get("WSC_REQUIRE_ORIG") == "1"

BASH = shutil.which("bash")
if BASH:
    try:  # WSL の bash.exe 等、動かないものは使わない
        _r = subprocess.run([BASH, "-c", "echo ok"], capture_output=True, timeout=30)
        if _r.stdout.strip() != b"ok":
            BASH = None
    except (OSError, subprocess.SubprocessError):
        BASH = None
CYGPATH = shutil.which("cygpath")
SKIP_BASH = "bash が無いため、元のシェル版との同値性は未検査"


def benv(extra=None):
    env = dict(os.environ)
    env["LANG"] = env["LC_ALL"] = "C.UTF-8"  # cygwin系bashのファイル名をUTF-8にする
    env.update(extra or {})
    return env


def to_bash(path):
    """bash に渡す形のパス（cygwin系なら /c/... 形式）"""
    if CYGPATH:
        r = subprocess.run([CYGPATH, "-u", path], capture_output=True, env=benv())
        if r.returncode == 0:
            return r.stdout.decode("utf-8", "replace").strip()
    return path.replace("\\", "/") if IS_WIN else path


def fwd(p):
    return p.replace("\\", "/")


def git_show(name):
    r = subprocess.run(
        ["git", "-C", REPO, "show", f"{ORIG_REF}:web-security-checklist/scripts/{name}"],
        capture_output=True,
    )
    if r.returncode != 0:
        msg = f"git show {ORIG_REF}:{name} が失敗: {r.stderr.decode('utf-8', 'replace')[:200]}"
        if REQUIRE_ORIG:
            raise AssertionError(msg)
        raise unittest.SkipTest(msg)
    return r.stdout


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def _rb(p):
    with open(p, "rb") as f:
        return f.read()


def norm(b):
    return b.decode("utf-8", "replace").replace("\r\n", "\n")


# ---------------------------------------------------------------- detect_stack
class DetectBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wsc-detect-")
        cls.fx = os.path.join(cls.tmp, "fx")
        os.makedirs(cls.fx)
        cls.orig = None
        if BASH:
            try:
                d = os.path.join(cls.tmp, "orig", "scripts")
                write(os.path.join(d, "detect_stack.sh"), git_show("detect_stack.sh"))
                cls.orig = os.path.join(d, "detect_stack.sh")
            except unittest.SkipTest:
                cls.orig = None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def tree(self, name, files):
        d = os.path.join(self.fx, name)
        os.makedirs(d)
        for rel, data in files.items():
            write(os.path.join(d, rel), data)
        return d

    @staticmethod
    def _n(res):
        out = re.sub(r"(?m)^(\S+): .*?/\.\./references/", r"\1: <S>/../references/", norm(res.stdout))
        return out, norm(res.stderr), res.returncode

    def new(self, *args, cwd=None):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "detect_stack.py"), *args],
                           capture_output=True, cwd=cwd)
        return self._n(r)

    def old(self, *args, cwd=None):
        r = subprocess.run([BASH, to_bash(self.orig), *args], capture_output=True, cwd=cwd, env=benv())
        out = self._n(r)
        # P3の階層化で参照先が移った（元のシェルは移動前のパスを出す）
        mv = lambda s: s.replace("references/principles.md", "references/checklists/principles.md").replace(
            "references/database.md", "references/checklists/database/_index.md")
        return tuple(mv(x) if isinstance(x, str) else x for x in out)


# 名前 -> (ファイル, 期待する行の種類, 標準エラーが出るか)
CASES = {
    "node_pkg": ({"package.json": "{}"}, ["nodejs-typescript"], False),
    "node_tsconfig": ({"tsconfig.json": "{}"}, ["nodejs-typescript"], False),
    "py_req": ({"requirements.txt": "flask"}, ["python"], False),
    "py_pyproject": ({"pyproject.toml": "[x]"}, ["python"], False),
    "py_pipfile": ({"Pipfile": "x"}, ["python"], False),
    "java_pom": ({"pom.xml": "<p/>"}, ["java"], False),
    "java_gradle": ({"build.gradle": "x"}, ["java"], False),
    "java_kts": ({"build.gradle.kts": "x"}, ["java"], False),
    "multi": ({"package.json": "{}", "requirements.txt": "x", "pom.xml": "x"},
              ["nodejs-typescript", "python", "java"], False),
    "unknown_empty": ({}, [], True),
    "unknown_readme": ({"README.md": "pg prisma"}, [], True),
    "db_pg": ({"package.json": '{"dependencies":{"pg":"8"}}'}, ["nodejs-typescript", "database"], False),
    "db_mysql2": ({"package.json": '{"mysql2":"1"}'}, ["nodejs-typescript", "database"], False),
    "db_prisma_upper": ({"requirements.txt": "PRISMA\n"}, ["python", "database"], False),
    "db_django": ({"requirements.txt": "Django==5"}, ["python", "database"], False),
    "db_pyproject": ({"pyproject.toml": "sqlalchemy"}, ["python", "database"], False),
    "db_hibernate": ({"pom.xml": "<a>hibernate</a>"}, ["java", "database"], False),
    "db_gradle": ({"build.gradle": "jdbc"}, ["java", "database"], False),
    # P4で旧.shから変えた（P4_CHANGEDは旧シェルとの同値の比較から外す）
    "db_kts": ({"build.gradle.kts": "prisma"}, ["java", "database"], False),
    "db_pipfile": ({"Pipfile": "django"}, ["python", "database"], False),
    "db_substring_pg": ({"package.json": '{"scripts":{"upgrade":"x"}}'}, ["nodejs-typescript"], False),
    "db_substring_others": ({"requirements.txt": "jpackage\ndjangoish\nmypgtool\n"}, ["python"], False),
    "db_pg_promise": ({"package.json": '{"dependencies":{"pg-promise":"11"}}'}, ["nodejs-typescript", "database"], False),
    "db_sqlite3": ({"package.json": '{"dependencies":{"better-sqlite3":"9","sqlite3":"5"}}'},
                   ["nodejs-typescript", "database"], False),
    "db_mongodb": ({"package.json": '{"dependencies":{"mongodb":"6"}}'}, ["nodejs-typescript", "database"], False),
    "db_prisma_scoped": ({"package.json": '{"dependencies":{"@prisma/client":"5"}}'}, ["nodejs-typescript", "database"], False),
    "db_psycopg2": ({"requirements.txt": "psycopg2-binary==2.9\n"}, ["python", "database"], False),
    "db_spring_jpa": ({"pom.xml": "<artifactId>spring-boot-starter-data-jpa</artifactId>"}, ["java", "database"], False),
    "db_only_no_stack": ({"requirements.txt": ""}, ["python"], False),
    "db_binary": ({"requirements.txt": b"\xff\xfe\x00 psycopg \x80"}, ["python", "database"], False),
    "no_db": ({"package.json": '{"name":"x","dependencies":{"express":"4"}}'}, ["nodejs-typescript"], False),
    "dir_named_like_file": ({"package.json/x": "y"}, [], True),  # package.json がディレクトリ
    "space_jp_path": ({"package.json": "{}", "requirements.txt": "x"}, ["nodejs-typescript", "python"], False),
}


P4_CHANGED = {"db_kts", "db_pipfile", "db_substring_pg", "db_substring_others", "db_pg_promise", "db_sqlite3",
              "db_mongodb", "db_prisma_scoped", "db_psycopg2", "db_spring_jpa"}


class TestDetectFixed(DetectBase):
    def test_cases(self):
        for name, (files, kinds, has_err) in CASES.items():
            with self.subTest(name):
                dname = "空白 日本語 " + name if name == "space_jp_path" else name
                d = self.tree(dname, files)
                out, err, rc = self.new(d)
                self.assertEqual(rc, 0)
                self.assertEqual([l.split(":")[0] for l in out.splitlines()], kinds)
                self.assertEqual(bool(err), has_err)
                if has_err:
                    self.assertTrue(err.startswith("unknown_stack: "))

    def test_default_and_empty_arg_use_cwd(self):
        d = self.tree("cwd_case", {"pom.xml": "x"})
        for args in ((), ("",)):
            out, err, rc = self.new(*args, cwd=d)
            self.assertEqual((out.split(":")[0], err, rc), ("java", "", 0))

    def test_missing_target(self):
        out, err, rc = self.new(os.path.join(self.fx, "no_such_dir"))
        self.assertEqual((out, rc), ("", 0))
        self.assertTrue(err.startswith("unknown_stack: "))


class TestDetectEquivalence(DetectBase):
    def test_same_as_original_shell(self):
        if not BASH or not self.orig:
            self.skipTest(SKIP_BASH)
        n = 0
        for name, (files, _k, _e) in CASES.items():
            if name in P4_CHANGED:
                continue
            with self.subTest(name):
                d = self.tree("eq_" + name, files)
                self.assertEqual(self.new(d), self.old(d))
                n += 1
        d = self.tree("eq_cwd", {"package.json": "{}", "pg": ""})
        self.assertEqual(self.new(cwd=d), self.old(cwd=d))
        self.assertEqual(self.new("", cwd=d), self.old("", cwd=d))
        missing = os.path.join(self.fx, "nope")
        self.assertEqual(self.new(missing), self.old(missing))
        print(f"\n[detect_stack equivalence] compared {n + 3} cases", file=sys.stderr)

    def test_sh_wrapper(self):
        if not BASH:
            self.skipTest(SKIP_BASH)
        d = self.tree("wrap", {"package.json": '{"pg":1}'})
        r = subprocess.run([BASH, to_bash(os.path.join(HERE, "detect_stack.sh")), d],
                           capture_output=True, env=benv())
        self.assertEqual(self._n(r), self.new(d))


# ---------------------------------------------------------------- run_sca_scan
STUB_FETCH = r'''import hashlib, sys, os
for s in (sys.stdout, sys.stderr):
    s.reconfigure(encoding="utf-8", newline="\n")
a = sys.argv[1:]
src = a[a.index("--from-text") + 1]
out = a[a.index("--out") + 1]
data = open(src, "rb").read().replace(b"\r\n", b"\n")
rest = [x for i, x in enumerate(a) if x not in ("--from-text", "--out") and (i == 0 or a[i - 1] not in ("--from-text", "--out"))]
print("STUB-FETCH isolated=%d lines=%d sha=%s args=%s" % (sys.flags.isolated, data.count(b"\n"), hashlib.sha1(data).hexdigest()[:10], " ".join(rest)))
try:
    with open(out, "w") as f:
        f.write("{}")
except OSError:
    print("stub: cannot open out")
print("EPSS/KEV: 取得済み（stub）")
sys.exit(int(os.environ.get("STUB_FETCH_RC", "0")))
'''

PY_SHIM = '''#!/bin/bash
args=(); for a in "$@"; do case "$a" in /*) a="$(cygpath -w "$a" 2>/dev/null || echo "$a")";; esac; args+=("$a"); done
exec "%s" "${args[@]}"
'''


REAL_TOOLS = {"npm", "npx", "pip-audit", "mvn", "osv-scanner"}


def filtered_sys_bin(root):
    """元のbash版に渡す /usr/bin と /bin の代わり。REAL_TOOLS を除いた実行ファイルへのsymlinkを置く。
    CIのLinuxには本物の mvn などが /usr/bin にあり、そのままでは偽ツールが無いケースで本物が動くため。
    Windows（Git Bash）では symlink に権限が要り、/usr/bin に該当ツールも無いので、従来どおりの PATH を返す"""
    if IS_WIN:
        return "/usr/bin:/bin"
    d = os.path.join(root, "sysbin")
    if not os.path.isdir(d):
        os.makedirs(d)
        for src in ("/usr/bin", "/bin"):
            if not os.path.isdir(src):
                continue
            for name in os.listdir(src):
                dst = os.path.join(d, name)
                if name in REAL_TOOLS or os.path.lexists(dst):
                    continue
                os.symlink(os.path.join(src, name), dst)
    return d


def make_stub_dir(root, tools):
    """tools の偽実行ファイルを作る。標準出力は固定、終了コードは環境変数 STUB_RC。
    npm の install は標準エラーに7行出し STUB_INSTALL_RC で終了する"""
    d = os.path.join(root, "stubs")
    os.makedirs(d, exist_ok=True)
    for t in tools:
        sh = f'#!/bin/bash\n'
        if t == "npm":
            sh += 'if [ "$1" = install ]; then [ -n "$STUB_LOG" ] && { echo "args=$*"; echo "cwd=$PWD"; } >> "$STUB_LOG"; for i in 1 2 3 4 5 6 7; do echo "npm-install-err-$i" >&2; done; exit ${STUB_INSTALL_RC:-0}; fi\n'
        sh += f'echo "{t}-stub $*"\necho "found CVE-2024-0001 and GHSA-aaaa-bbbb-cccc"\nexit ${{STUB_RC:-0}}\n'
        write(os.path.join(d, t), sh.replace("\r\n", "\n"))
        os.chmod(os.path.join(d, t), 0o755)
        if IS_WIN:
            cmd = "@echo off\r\n"
            if t == "npm":
                cmd += 'if /i "%~1"=="install" goto inst\r\n'
            cmd += f"echo {t}-stub %*\r\necho found CVE-2024-0001 and GHSA-aaaa-bbbb-cccc\r\nexit /b %STUB_RC%\r\n"
            if t == "npm":
                cmd += ":inst\r\nif defined STUB_LOG >>\"%STUB_LOG%\" echo args=%*\r\nif defined STUB_LOG >>\"%STUB_LOG%\" echo cwd=%CD%\r\n" + "".join(f">&2 echo npm-install-err-{i}\r\n" for i in range(1, 8)) + "exit /b %STUB_INSTALL_RC%\r\n"
            write(os.path.join(d, t + ".cmd"), cmd)
    write(os.path.join(d, "python3"), PY_SHIM % to_bash(sys.executable))
    os.chmod(os.path.join(d, "python3"), 0o755)
    return d


SCA_CASES = [
    # 名前, ファイル(対象内), 偽ツール, 環境変数, 補足
    ("no_tool_node", {"package.json": "{}"}, [], {}, {}),
    ("no_tool_nothing", {}, [], {}, {}),
    ("no_tool_all_stacks", {"package.json": "{}", "requirements.txt": "x", "pom.xml": "x"}, [], {}, {}),
    ("npm_lock_ok", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {}),
    ("npm_shrinkwrap_ok", {"package.json": "{}", "npm-shrinkwrap.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {}),
    ("npm_audit_fails", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "1"}, {}),
    ("npm_nolock_ok_npmrc", {"package.json": "{}", ".npmrc": "x=1"}, ["npm"], {"STUB_RC": "0", "STUB_INSTALL_RC": "0"}, {}),
    ("npm_nolock_audit_fails", {"package.json": "{}"}, ["npm"], {"STUB_RC": "2", "STUB_INSTALL_RC": "0"}, {}),
    ("npm_nolock_install_fails", {"package.json": "{}"}, ["npm"], {"STUB_RC": "0", "STUB_INSTALL_RC": "1"}, {}),
    ("pip_ok", {"requirements.txt": "x"}, ["pip-audit"], {"STUB_RC": "0"}, {}),
    ("pip_fails", {"pyproject.toml": "x"}, ["pip-audit"], {"STUB_RC": "1"}, {}),
    ("pip_missing", {"requirements.txt": "x"}, [], {}, {}),
    ("mvn_ok", {"pom.xml": "x"}, ["mvn"], {"STUB_RC": "0"}, {}),
    ("mvn_fails_kts", {"build.gradle.kts": "x"}, ["mvn"], {"STUB_RC": "1"}, {}),
    ("osv_only", {}, ["osv-scanner"], {"STUB_RC": "0"}, {}),
    ("osv_fails", {"README": "x"}, ["osv-scanner"], {"STUB_RC": "1"}, {}),
    ("all_tools", {"package.json": "{}", "package-lock.json": "{}", "requirements.txt": "x", "pom.xml": "x"},
     ["npm", "pip-audit", "mvn", "osv-scanner"], {"STUB_RC": "0"}, {}),
    ("epss_off", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0", "SCA_EPSS_KEV": "0"}, {}),
    ("epss_off_no_tool", {"package.json": "{}"}, [], {"SCA_EPSS_KEV": "0"}, {}),
    ("epss_empty_var", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0", "SCA_EPSS_KEV": ""}, {}),
    ("fetch_fails", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0", "STUB_FETCH_RC": "3"}, {}),
    ("out_default", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {"no_out": True}),
    ("out_relative", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {"rel_out": "sub/res.json"}),
    ("out_inside_target", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {"out_in_target": True}),
    ("target_spaces_jp", {"package.json": "{}", "package-lock.json": "{}"}, ["npm", "pip-audit"], {"STUB_RC": "0"},
     {"dirname": "空白 と 日本語 ディレクトリ"}),
    ("target_spaces_jp_nolock", {"package.json": "{}"}, ["npm"], {"STUB_RC": "1", "STUB_INSTALL_RC": "0"},
     {"dirname": "日本語 dir"}),
    ("target_injection", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"},
     {"dirname": "a;touch PWNED_SEMI;b $(touch PWNED_SUB) `touch PWNED_BT` && touch PWNED_AND", "inject": True}),
    ("target_injection_nolock", {"package.json": "{}"}, ["npm"], {"STUB_RC": "0", "STUB_INSTALL_RC": "0"},
     {"dirname": "x$(touch PWNED_SUB2);touch PWNED_SEMI2", "inject": True}),
    ("target_missing", None, [], {}, {}),
    ("target_dash_relative", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"},
     {"dirname": "-x", "rel_target": True}),
    ("out_trailing_slash", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"}, {"out_trailing": True}),
    ("out_trailing_slash_in_target", {"package.json": "{}", "package-lock.json": "{}"}, ["npm"], {"STUB_RC": "0"},
     {"out_trailing": True, "out_in_target": True}),
    ("target_default_cwd", {"pom.xml": "x"}, ["mvn"], {"STUB_RC": "0"}, {"use_cwd": True}),
]


class TestSca(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wsc-sca-")
        cls.newdir = os.path.join(cls.tmp, "new")
        os.makedirs(cls.newdir)
        shutil.copy(os.path.join(HERE, "run_sca_scan.py"), os.path.join(cls.newdir, "run_sca_scan.py"))
        write(os.path.join(cls.newdir, "fetch_epss_kev.py"), STUB_FETCH)
        cls.orig = None
        if BASH:
            try:
                od = os.path.join(cls.tmp, "orig")
                write(os.path.join(od, "run_sca_scan.sh"), git_show("run_sca_scan.sh"))
                write(os.path.join(od, "fetch_epss_kev.py"), STUB_FETCH)
                cls.orig = os.path.join(od, "run_sca_scan.sh")
            except unittest.SkipTest:
                cls.orig = None

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_case(self, which, idx, case):
        """which: 'new' | 'old'。ケースごと・実装ごとに別の作業領域を作り、正規化した結果を返す"""
        name, files, tools, envv, opt = case
        TestSca.seq = getattr(TestSca, "seq", 0) + 1
        base = os.path.join(self.tmp, f"{which}{idx}_{TestSca.seq}")
        callcwd = os.path.join(base, "callcwd")
        outdir = os.path.join(base, "outdir")
        os.makedirs(callcwd)
        os.makedirs(outdir)
        target = os.path.join(callcwd, opt.get("dirname", "target"))
        if files is not None:
            os.makedirs(target)
            for rel, data in files.items():
                write(os.path.join(target, rel), data)
        stubs = make_stub_dir(base, tools)
        env_extra = dict(envv)
        out_json = os.path.join(outdir, "res.json")
        if opt.get("rel_out"):
            env_extra["SCA_EPSS_KEV_OUT"] = opt["rel_out"]
            os.makedirs(os.path.join(callcwd, "sub"))
        elif opt.get("out_trailing"):
            od = os.path.join(target, "o") if opt.get("out_in_target") else outdir
            os.makedirs(od, exist_ok=True)
            env_extra["SCA_EPSS_KEV_OUT"] = (od if which == "new" else to_bash(od)) + "/"
        elif opt.get("out_in_target"):
            env_extra["SCA_EPSS_KEV_OUT"] = os.path.join(target, "res.json") if which == "new" else to_bash(os.path.join(target, "res.json"))
        elif not opt.get("no_out"):
            env_extra["SCA_EPSS_KEV_OUT"] = out_json if which == "new" else to_bash(out_json)
        arg = [] if opt.get("use_cwd") else [opt["dirname"] if opt.get("rel_target") else target]
        cwd = target if opt.get("use_cwd") else callcwd
        if which == "new":
            env = dict(os.environ)
            env["PATH"] = stubs
            env.update(env_extra)
            cmd = [sys.executable, os.path.join(self.newdir, "run_sca_scan.py"), *arg]
        else:
            env = benv(env_extra)
            env["PATH"] = to_bash(stubs) + ":" + filtered_sys_bin(self.tmp)
            cmd = [BASH, to_bash(self.orig), *arg]
        # 偽のツールが無い環境で本物が呼ばれていないことの保証: PATH は偽ツール置き場のみ
        # （bashは REAL_TOOLS を除いた /usr/bin と /bin を追加）
        r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, timeout=120)
        if opt.get("inject"):
            for root in (callcwd, target, base):
                for f in os.listdir(root) if os.path.isdir(root) else []:
                    self.assertFalse(f.startswith("PWNED"), f"{name}: 対象パスの一部がコマンドとして実行された: {f}")
        reps = []
        for label, p in (("<TARGET>", target), ("<OUTDIR>", outdir), ("<OUT>", out_json), ("<CWD>", callcwd), ("<BASE>", base)):
            reps += [(to_bash(p) if BASH else p, label), (p, label), (fwd(p), label)]
        reps.sort(key=lambda x: -len(x[0]))

        def n(b):
            t = norm(b)
            for a, lab in reps:
                t = t.replace(a, lab)
            t = re.sub(r"\S*sca-epss-kev\.[A-Za-z0-9_]+\S*", "<WORK>", t)
            # bash自身の診断（`script: line N: cd: ...`）は移植版には無い。メッセージ本体は比べる
            t = re.sub(r"(?m)^\S*run_sca_scan\.sh: line \d+: cd: .*\n", "", t)
            t = re.sub(r"(?m)^cd: usage: .*\n", "", t)
            return t.replace("\\", "/")

        return n(r.stdout), n(r.stderr), r.returncode

    def test_new_basic(self):
        """bash が無くても検査できる、移植版単体の確認"""
        for idx, case in enumerate(SCA_CASES):
            if case[0] in ("no_tool_node", "target_missing", "epss_off", "target_injection", "all_tools"):
                with self.subTest(case[0]):
                    out, err, rc = self.run_case("new", idx, case)
                    if case[0] == "target_missing":
                        self.assertEqual(rc, 1)
                        self.assertIn("対象ディレクトリに移動できません", err)
                    elif case[0] == "no_tool_node":
                        self.assertEqual(rc, 1)
                        self.assertIn("== npm audit ==\nnpm が見つかりません", out)
                        self.assertIn("EPSS/KEV: 未取得（理由: SCA未実施）", out)
                    elif case[0] == "epss_off":
                        self.assertEqual(rc, 0)
                        self.assertTrue(out.endswith("== EPSS/KEV ==\nEPSS/KEV: 未取得（理由: SCA_EPSS_KEV=0 で省略）\n"))
                    elif case[0] == "all_tools":
                        self.assertEqual(rc, 0)
                        self.assertIn("STUB-FETCH isolated=1", out)
                        self.assertIn("JSON: <OUT>（報告書と同じ保存先へ複製する）", out)

    def test_equivalence_with_original_shell(self):
        if not BASH or not self.orig:
            self.skipTest(SKIP_BASH)
        n = 0
        diffs = []
        known = []
        for idx, case in enumerate(SCA_CASES):
            with self.subTest(case[0]):
                a = self.run_case("new", idx, case)
                b = self.run_case("old", idx, case)
                if a != b and self.is_known_orig_bug(a, b, self.orig):
                    known.append(case[0])
                    continue
                if a != b:
                    diffs.append(case[0])
                self.assertEqual(a, b)
                n += 1
        print(f"\n[run_sca_scan equivalence] compared {n} cases (stdout, stderr, exit code); differing: {diffs or 'none'}"
              f"; known bugs of the original: {known or 'none'}", file=sys.stderr)

    @staticmethod
    def is_known_orig_bug(new, old, orig_path):
        """元のbash版の既存の不具合で、移植版が正しく動いている差分か。
        macOS の bash 3.2 は、元のbash版の `$epss_json（` `$epss_skip）` のような「変数の直後に全角文字」を
        変数名の一部と読み、unbound variable で止まることがある。CIの macOS で149行目・155行目で確認し、
        どのケースで起きるかは実行ごとに変わる（条件は未特定）。次をすべて満たすときだけ、この不具合とみなす:
        元のソースのその行に `$<変数名>` の直後が非ASCII文字の箇所がある、元のbash版の標準エラーはその1行だけで
        終了コード1、元のbash版の標準出力は移植版の標準出力の先頭と一致し、差は残りの1行だけ。
        止まった後の部分（移植版の標準エラーと終了コード）は比べられないが、Linux と Windows では同じケースを
        完全一致で比べている"""
        if sys.platform != "darwin":
            return False
        (nout, _nerr, _nrc), (oout, oerr, orc) = new, old
        m = re.fullmatch(r"[^\n]*: line (\d+): ([A-Za-z_][A-Za-z0-9_]*)\S*: unbound variable\n?", oerr)
        if not m or orc != 1:
            return False
        with open(orig_path, encoding="utf-8") as f:
            lines = f.read().split("\n")
        lineno, var = int(m.group(1)), m.group(2)
        if not (1 <= lineno <= len(lines)) or not re.search(r"\$" + var + r"[^\x00-\x7f]", lines[lineno - 1]):
            return False
        rest = nout[len(oout):]
        return nout.startswith(oout) and rest.count("\n") == 1 and rest.endswith("\n")

    def test_sh_wrapper(self):
        if not BASH:
            self.skipTest(SKIP_BASH)
        base = os.path.join(self.tmp, "wrap")
        target = os.path.join(base, "t")
        write(os.path.join(target, "pom.xml"), "x")
        env = benv({"SCA_EPSS_KEV": "0"})
        env["PATH"] = to_bash(make_stub_dir(base, ["mvn"])) + ":/usr/bin:/bin"
        env["STUB_RC"] = "0"
        r = subprocess.run([BASH, to_bash(os.path.join(HERE, "run_sca_scan.sh")), target],
                           capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mvn-stub -q org.owasp:dependency-check-maven:check", norm(r.stdout))
        self.assertIn("SCA_EPSS_KEV=0 で省略", norm(r.stdout))


class TestScaHardening(unittest.TestCase):
    """移植版だけの検査: 作業ディレクトリ経由の実行の防止、旗の脱落・一時領域の消し忘れ・改行の変異の検出"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wsc-hard-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.script = os.path.join(self.tmp, "s", "run_sca_scan.py")
        os.makedirs(os.path.dirname(self.script))
        shutil.copy(os.path.join(HERE, "run_sca_scan.py"), self.script)
        write(os.path.join(os.path.dirname(self.script), "fetch_epss_kev.py"), STUB_FETCH)

    def run_new(self, target, path, env_extra=None, cwd=None):
        env = dict(os.environ)
        env.pop("NoDefaultCurrentDirectoryInExePath", None)
        env["PATH"] = path
        env["SCA_EPSS_KEV_OUT"] = os.path.join(self.tmp, "res.json")
        env.update(env_extra or {})
        return subprocess.run([sys.executable, self.script, target], cwd=cwd or self.tmp, env=env,
                              capture_output=True, timeout=120)

    def plant(self, target):
        """対象に置く罠。実行されると PLANTED_RAN ができる"""
        marker = os.path.join(target, "PLANTED_RAN")
        for t in ("npm", "pip-audit", "mvn", "osv-scanner"):
            write(os.path.join(target, t + ".CMD"), f'@echo off\r\necho x> "{marker}"\r\n')
        return marker

    @unittest.skipUnless(IS_WIN, "Windows の作業ディレクトリ検索の検査")
    def test_planted_cmd_in_target_not_run(self):
        target = os.path.join(self.tmp, "t")
        write(os.path.join(target, "requirements.txt"), "x")
        write(os.path.join(target, "package.json"), "{}")
        write(os.path.join(target, "package-lock.json"), "{}")
        marker = self.plant(target)
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        for label, path in (("PATH無関係", empty), ("PATHに.", empty + os.pathsep + "." + os.pathsep),
                            ("PATHに空項目", os.pathsep + empty + os.pathsep + os.pathsep),
                            ("PATHに対象自身", empty + os.pathsep + target)):
            with self.subTest(label):
                for cwd in (target, None):
                    r = self.run_new(target, path, cwd=cwd)
                    self.assertFalse(os.path.exists(marker), "対象の中の .CMD が実行された")
                    out = norm(r.stdout)
                    self.assertIn("pip-audit が見つかりません", out)
                    self.assertIn("npm が見つかりません", out)
                    self.assertEqual(r.returncode, 1)

    @unittest.skipUnless(IS_WIN, "Windows の作業ディレクトリ検索の検査")
    def test_dot_in_path_still_finds_real_stub_not_planted(self):
        target = os.path.join(self.tmp, "t2")
        write(os.path.join(target, "requirements.txt"), "x")
        marker = self.plant(target)
        stubs = make_stub_dir(self.tmp, ["pip-audit"])
        r = self.run_new(target, ".;" + stubs, {"STUB_RC": "0", "SCA_EPSS_KEV": "0"}, cwd=target)
        self.assertFalse(os.path.exists(marker))
        self.assertIn("pip-audit-stub", norm(r.stdout))
        self.assertEqual(r.returncode, 0)

    def test_tool_resolution_unit(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rsm", self.script)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        target = os.path.join(self.tmp, "t3")
        stubs = make_stub_dir(target, ["npm"])  # 対象の中の PATH 項目は無視される
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = os.pathsep.join([stubs, "", ".", "rel"])
        try:
            self.assertIsNone(m._resolve_tools(target)["npm"])
            other = m._resolve_tools(os.path.join(self.tmp, "other"))["npm"]
            self.assertTrue(other and os.path.isabs(other))
        finally:
            os.environ["PATH"] = old

    def test_target_value_never_in_tool_args(self):
        """ツールに渡す引数は固定の語だけ（cmd.exe 経由の .cmd に対象由来の値を渡さない）"""
        target = os.path.join(self.tmp, "a&b %PATH% ^x;y")
        write(os.path.join(target, "package.json"), "{}")
        stubs = make_stub_dir(self.tmp, ["npm"])
        log = os.path.join(self.tmp, "log.txt")
        r = self.run_new(target, stubs, {"STUB_RC": "0", "STUB_INSTALL_RC": "0", "STUB_LOG": log, "SCA_EPSS_KEV": "0"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("npm-stub audit --audit-level=high\n", norm(r.stdout))
        self.assertNotIn("a&b", norm(r.stdout))
        args_line = [l for l in norm(_rb(log)).splitlines() if l.startswith("args=")][0]
        self.assertEqual(args_line, "args=install --package-lock-only --ignore-scripts --no-audit --no-fund")

    def test_npm_install_flags_and_tmp_cleanup(self):
        target = os.path.join(self.tmp, "t4")
        write(os.path.join(target, "package.json"), "{}")
        stubs = make_stub_dir(self.tmp, ["npm"])
        log = os.path.join(self.tmp, "log.txt")
        r = self.run_new(target, stubs, {"STUB_RC": "0", "STUB_INSTALL_RC": "0", "STUB_LOG": log, "SCA_EPSS_KEV": "0"})
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = norm(_rb(log)).splitlines()
        args = [l for l in lines if l.startswith("args=")][0]
        for flag in ("install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"):
            self.assertIn(flag, args)
        sca_tmp = [l for l in lines if l.startswith("cwd=")][0][4:]
        self.assertNotEqual(os.path.normcase(os.path.realpath(sca_tmp)), os.path.normcase(os.path.realpath(target)))
        self.assertFalse(os.path.exists(sca_tmp), "一時ディレクトリが残っている")
        self.assertEqual(sorted(os.listdir(target)), ["package.json"])  # 対象は変更されない

    def test_no_crlf_in_own_output(self):
        """newline="\n" の脱落の検出: 自分の出力を改行コード変換なしのバイト列で見る。ツールの出力は含めない"""
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        target = os.path.join(self.tmp, "t5")
        write(os.path.join(target, "package.json"), "{}")
        r = self.run_new(target, empty)
        self.assertIn(b"== EPSS/KEV ==\n", r.stdout)
        self.assertNotIn(b"\r", r.stdout)
        self.assertNotIn(b"\r", r.stderr)
        r = self.run_new(os.path.join(self.tmp, "nope"), empty)
        self.assertNotIn(b"\r", r.stderr)
        self.assertTrue(r.stderr.endswith(b"\n"))
        d = subprocess.run([sys.executable, os.path.join(HERE, "detect_stack.py"), target], capture_output=True)
        self.assertTrue(d.stdout)
        self.assertNotIn(b"\r", d.stdout)

    def test_cp_failure_reported(self):
        if IS_WIN:
            self.skipTest("読めないファイルの作り方がOSで異なる")
        target = os.path.join(self.tmp, "t6")
        write(os.path.join(target, "package.json"), "{}")
        os.chmod(os.path.join(target, "package.json"), 0)
        if os.access(os.path.join(target, "package.json"), os.R_OK):
            self.skipTest("root では読めてしまう")
        stubs = make_stub_dir(self.tmp, ["npm"])
        r = self.run_new(target, stubs, {"STUB_RC": "0", "STUB_INSTALL_RC": "0", "SCA_EPSS_KEV": "0"})
        self.assertIn(b"cp: cannot copy 'package.json'", r.stderr)


if __name__ == "__main__":
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    unittest.main(verbosity=1)
