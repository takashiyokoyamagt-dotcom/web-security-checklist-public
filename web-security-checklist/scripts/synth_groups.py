#!/usr/bin/env python3
"""5c補足3（finding-arbiter.md）の機械的な部分: SYNTHへ渡す群の選別と入力パケット、群diffの当て直し。

Usage:
  python3 synth_groups.py prepare --work WORK --target TARGET --mask-file FILE [--force]
  python3 synth_groups.py finish  --work WORK --target TARGET --wid WORK_ID [--out DIR]
  python3 synth_groups.py apply   --work WORK --target TARGET [--force]
  python3 synth_groups.py --self-test

prepare: `members.json`・`findings-log.jsonl`・`out/red-NN.jsonl`・`out/blue-NN.jsonl`から、
- 単独項目（構成IDが1件）で、確定diffが対象に当たり、どの欄にも「要検討」が無く、当てた後のJS・JSONが壊れない
  （`node --check`。nodeとgitがあるとき）ものは、SYNTHに渡さない。
  diffの各hunkを対象の同じ内容の行に当て（文脈行が省かれたdiffも、変更前の行の並びが一致すれば当たる。
  複数あれば見出しの行番号に近い方）、`a/`・`b/`接頭辞付きの厳密なdiffを作り直して
  `synth/auto/<work_id>/group.diff`に保存し、SYNTHの戻り値と同じキーの行を`synth-auto.jsonl`に書く。
- それ以外（群、要検討、diffが無い・当たらない単独項目）は`synth-in/<work_id>.json`（SYNTHの入力パケット。
  `members`・`base`〔代表の構成ID〕・`tree`・`pre_applied`・`finish`〔SYNTHが実行するコマンド〕・`return`〔SYNTHが
  戻り値を書くパス〕・`items`）を書く。秘密値は`<マスク>`にする
  （`make_packets.py`と同じ。BLUEの`fix_suggestion_check.diff`が確定diffと同じなら省略の印）。
  群ごとにSYNTHの作業ツリー`synth-work/<work_id>/`（対象の複製を基準コミットしたgitリポジトリ）を作り、
  代表の確定diffが当たれば未コミットで当てておく（`pre_applied`＝代表の構成ID。当たらなければnull）。
finish: SYNTHが作業ツリーを編集した後に実行する。基準コミットとの差分を`a/`・`b/`接頭辞付きの`group.diff`
  （既定は`synth/<work_id>/`）に書き、
  対象の新しい複製で`git apply --check`・適用・`node --check`・JSONの読込を確かめる。変更が無い・失敗なら rc1。
最後に、自動で作った件数とSYNTHに渡す群の一覧（変更するファイル）を表示する。
apply: 全項目の`group.diff`（`synth/`以下の`<work_id>/group.diff`。SYNTHもこの形で保存する）を、対象の新しい複製
（`.git`・`node_modules`を除く）ごとに`git apply --check`して適用し、変更したJavaScriptを`node --check`、
JSONを読み込みで確かめる。SYNTHが要検討としてdiffを作らなかった群は、`group.diff`の代わりに理由（「要検討」を含む）を
`no-diff.txt`に置けば欠けにしない（NODIFF）。SYNTH・SCA-SYNTHの戻り値（JSON1行。UTF-8）は`group.diff`と同じ
ディレクトリの`return.json`から読み（JSON・`work_id`・キーを検査。欠け・不正はRETURN_NG）、`synth-auto.jsonl`の行と
合わせて`members.json`の順に`synth-out.jsonl`へ書く（手で連結しない）。戻り値の`fix_suggestion`が`@group.diff`なら、
同じディレクトリの`group.diff`の内容（prepareの`--mask-file`と対象の設定ファイルの秘密値は`<マスク>`。戻り値に
`fix_note`があればその文をdiffの前に置き、`fix_note`のキーは除く）で埋める（SYNTHがdiffを書き写さなくてよい）。
作業ツリーの代表diffは、末尾に改行が無いファイルにも改行の無いまま当てる（単独項目の自動化の条件は変えない）。
結果を`synth-apply/apply-log.txt`に書き、欠け・失敗があれば rc1。
判断を含まない。既存の出力があれば`--force`が無い限り rc2。Stdlib only, Python 3.9+（applyはgitを使う）.
"""
import argparse
import difflib
import glob
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_5c_components as c5c  # noqa: E402
import make_packets as mp  # noqa: E402

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
REVIEW = "要検討"
NODIFF = "no-diff.txt"  # SYNTHが要検討としてdiffを作らなかった群の理由（group.diffの代わりに置く）
RETURN = "return.json"  # SYNTH・SCA-SYNTHの戻り値のJSON1行（UTF-8。group.diffと同じディレクトリ）。applyがsynth-out.jsonlに連結
FILL = "@group.diff"  # 戻り値の fix_suggestion をこの値にすると、applyが group.diff の内容（マスク済み）で埋める
PREP = "_prepare.json"  # prepareの設定（マスク用ファイルのパス）。synth/auto/ に置く
_COMMON_K = ("fix_suggestion", "intent", "design_refs", "behavior_change", "compat_class", "design_conflict",
             "alternatives", "unmerged_notes", "open_points")
SYNTH_RET_K = ("work_id", "members", "fold_log") + _COMMON_K + ("applied_files", "checks")  # agent-roles.md SYNTH
SCA_RET_K = ("work_id", "category", "file_line", "severity_prov", "summary", "vulnerable_code", "root_cause",
             "failure_scenario") + _COMMON_K + ("reach", "pkg_table", "checks")  # 同 SCA-SYNTH
AUTO_NOTE ="単独項目。BLUEの確定diffを対象に当て、厳密なdiffに作り直した（synth_groups.py。SYNTHには渡していない）"
SKIP_DIRS = {".git", "node_modules"}


def rmtree(p):
    """読み取り専用のファイル（Windowsのgitのオブジェクト等）も消す"""
    def onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if os.path.lexists(p):
        if os.path.isdir(p) and not os.path.islink(p):
            if sys.version_info >= (3, 12):
                shutil.rmtree(p, onexc=onexc)
            else:
                shutil.rmtree(p, onerror=onexc)
        else:
            os.remove(p)


class NoApply(Exception):
    pass


def parse_diff(text):
    """[(old_path|None, new_path|None, [(old_start, [hunk lines])])]。ファイル見出しの無いdiffは空"""
    files, cur, hunk = [], None, None
    lines = c5c.strip_fence(text.replace("\r\n", "\n"))
    while lines and not lines[-1].strip():
        lines.pop()  # 末尾の空行は空の文脈行と区別できないので捨てる
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            old, new = ln[4:].strip(), lines[i + 1][4:].strip()
            cur = [None if old == "/dev/null" else c5c.clean_path(old),
                   None if new == "/dev/null" else c5c.clean_path(new), []]
            files.append(cur)
            hunk = None
            i += 2
            continue
        m = HUNK.match(ln)
        if m and cur is not None:
            hunk = (int(m.group(1)), [])
            cur[2].append(hunk)
        elif hunk is not None and (ln[:1] in (" ", "+", "-") or ln == ""):
            hunk[1].append(ln if ln else " ")
        elif hunk is not None and ln.startswith("\\"):
            pass
        elif ln.startswith(("diff --git", "index ", "new file mode", "deleted file mode", "similarity", "rename ")):
            hunk = None
        else:
            hunk = None
        i += 1
    return files


def apply_hunks(cur, hunks, path):
    """行のリスト（改行なし）にhunkを順に当てる。当たらなければ NoApply"""
    out, pos, offset = list(cur), 0, 0
    for start, body in hunks:
        old = [l[1:] for l in body if l[:1] in (" ", "-")]
        new = [l[1:] for l in body if l[:1] in (" ", "+")]
        want = max(start - 1 + offset, 0)
        if not old:
            at = min(want, len(out)) if start else 0
        else:
            hits = [i for i in range(pos, len(out) - len(old) + 1) if out[i:i + len(old)] == old]
            if not hits:
                hits = [i for i in range(pos, len(out) - len(old) + 1)
                        if [s.rstrip() for s in out[i:i + len(old)]] == [s.rstrip() for s in old]]
            if not hits:
                raise NoApply("%s: hunk @@ -%d に一致する行が無い" % (path, start))
            at = min(hits, key=lambda i: (abs(i - want), i))
        out[at:at + len(old)] = new
        pos = at + len(new)
        offset += len(new) - len(old)
    return out


def read_text(target, rel):
    """(行のリスト〔改行なし〕, 末尾に改行が無いか)"""
    root = os.path.realpath(target)
    p = os.path.realpath(os.path.join(root, rel))
    if os.path.commonpath([root, p]) != root:
        raise NoApply("%s: 対象の外" % rel)
    with open(p, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    if text.startswith("﻿"):
        raise NoApply("%s: BOM付き" % rel)
    if "\r\n" in text:
        raise NoApply("%s: CRLF" % rel)
    noeol = bool(text) and not text.endswith("\n")  # 末尾の改行の有無は変えずに保つ
    return (text + "\n" if noeol else text).split("\n")[:-1] if text else [], noeol


def with_eol(lines, noeol):
    """行に改行を付ける。noeolなら最後の行だけ付けない"""
    out = [s + "\n" for s in lines]
    if noeol and out:
        out[-1] = out[-1][:-1]
    return out


def strict_diff(target, diff):
    """(厳密なdiff, 変更したファイル)。当たらなければ NoApply"""
    files = parse_diff(diff)
    if not files or not any(h for _, _, h in files):
        raise NoApply("diffが無い")
    chunks, touched = [], []
    for old, new, hunks in files:
        if new is None or (old is not None and old != new):
            raise NoApply("削除・改名のdiff")
        if old is None:
            if os.path.exists(os.path.join(target, new)):
                raise NoApply("%s: 新規作成のdiffだが既に有る" % new)
            a = []
        else:
            a, noeol = read_text(target, old)
            if noeol:  # 単独項目でも自動にせずSYNTHへ回す（従来どおり。作業ツリーには改行の無いまま当てる）
                raise NoApply("%s: 末尾に改行が無い" % old)
        b = apply_hunks(a, hunks, new)
        if a == b:
            continue
        al, bl = [s + "\n" for s in a], [s + "\n" for s in b]
        body = list(difflib.unified_diff(al, bl, "/dev/null" if old is None else "a/" + new, "b/" + new, n=3))
        head = "diff --git a/%s b/%s\n" % (new, new) + ("new file mode 100644\n" if old is None else "")
        chunks.append(head + "".join(body))
        touched.append(new)
    if not chunks:
        raise NoApply("変更が無い")
    return "".join(chunks), touched


def load_inputs(work):
    members = json.load(open(os.path.join(work, "members.json"), encoding="utf-8"))
    log = {r["tmp_id"]: r for r in mp.load_jsonl(os.path.join(work, "findings-log.jsonl"))}
    red, blue = mp.load_outputs(work)
    return members, log, red, blue


def item_of(t, log, red, blue):
    r, b, g = red.get(t, {}), blue.get(t, {}), log[t]
    it = {"tmp_id": t, "file_line": b.get("corrected_file_line") or r.get("file_line") or g.get("file_line"),
          "category": r.get("category", g.get("category")), "severity_prov": r.get("severity", g.get("severity")),
          "summary": r.get("summary", g.get("summary")), "root_cause": r.get("root_cause"),
          "failure_scenario": r.get("failure_scenario"), "verdict": g.get("verdict"), "fix_final": g.get("diff"),
          "fix_source": g.get("diff_source")}
    for k in mp.DESIGN_K:
        it[k] = b.get(k, r.get(k))
    it["blue"] = {k: b.get(k) for k in ("verdict", "evidence", "vulnerable_code_check", "fix_suggestion_check",
                                        "needs_repro")}
    it["blue"]["fix_suggestion_check"] = mp.drop_same_diff(it["blue"]["fix_suggestion_check"], it["fix_final"])
    return it


def syntax_ng(target, diff):
    """自動で作るdiffを対象の複製に当て、JS・JSONが壊れれば理由（SYNTHへ回す）。node・gitが無ければ確かめない"""
    node = shutil.which("node")
    if not node or not shutil.which("git"):
        return None
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "g.diff")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(diff)
        status, note, bad = check_one(target, p, os.path.join(td, "t"), node)
    return None if status == "APPLIED" and not bad else "構文NG（%s）" % note


def prepare(work, target, mask_file, force=False):
    outs = [os.path.join(work, p) for p in ("synth-auto.jsonl", "synth-in", os.path.join("synth", "auto"),
                                            "synth-work")]
    if not force and any(os.path.exists(p) for p in outs):
        print("NG: 出力が既に有る（--forceで上書き）: " + ", ".join(p for p in outs if os.path.exists(p)))
        return 2
    members, log, red, blue = load_inputs(work)
    mask = mp.Masker(target, mask_file)
    for p in outs[1:]:
        rmtree(p)
    os.makedirs(outs[1], exist_ok=True)
    auto, packets, why, tree_fail = [], [], {}, 0
    for wid, ids in members.items():
        items = [item_of(t, log, red, blue) for t in ids]
        reason = None
        if len(ids) > 1:
            reason = "群"
        elif REVIEW in json.dumps(items, ensure_ascii=False):
            reason = "要検討"
        else:
            try:
                diff, touched = strict_diff(target, items[0]["fix_final"] or "")
            except NoApply as e:
                reason = "当たらない（%s）" % e
            except (OSError, UnicodeDecodeError) as e:
                reason = "当たらない（%s）" % type(e).__name__
            else:
                reason = syntax_ng(target, diff)
        if reason is None:
            d = os.path.join(outs[2], wid)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "group.diff"), "w", encoding="utf-8", newline="\n") as f:
                f.write(diff)
            it = items[0]
            row = {"work_id": wid, "members": ids, "fix_suggestion": diff, "fold_log": AUTO_NOTE}
            row.update({k: it.get(k) for k in mp.DESIGN_K})
            row.update({"unmerged_notes": [], "open_points": [], "applied_files": touched,
                        "checks": "厳密なdiffを生成（適用の確認は synth_groups.py apply）"})
            auto.append(mask(row))
            continue
        why[wid] = reason
        base = mp.representative(list(ids), {t: {"verdict": log[t]["verdict"],
                                                 "severity": red.get(t, {}).get("severity", log[t].get("severity"))}
                                             for t in ids})
        tree = os.path.join(outs[3], wid)
        try:
            pre = make_tree(target, tree, next(it["fix_final"] for it in items if it["tmp_id"] == base))
        except OSError as e:  # gitが無い等
            print("NG: %s の作業ツリーを作れない: %s" % (wid, e))
            rmtree(tree)
            tree_fail += 1
            pre = False
        fwd = lambda x: os.path.abspath(x).replace(os.sep, "/")
        fin = "python3 %s finish --work %s --target %s --wid %s" % (fwd(__file__), fwd(work), fwd(target), wid)
        pk = mask({"work_id": wid, "members": ids, "base": base, "tree": fwd(tree),
                   "pre_applied": base if pre else None, "finish": fin,
                   "return": fwd(os.path.join(work, "synth", wid, RETURN)), "items": items})
        with open(os.path.join(outs[1], wid + ".json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(pk, f, ensure_ascii=False, indent=1)
        fs = sorted({p for it in items for _, p, _ in parse_diff(it["fix_final"] or "") if p})
        packets.append((wid, len(ids), reason, ",".join(fs)))
    with open(outs[0], "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in auto))
    os.makedirs(outs[2], exist_ok=True)
    with open(os.path.join(outs[2], PREP), "w", encoding="utf-8", newline="\n") as f:  # applyが埋めるdiffのマスク用
        json.dump({"mask_file": os.path.abspath(mask_file)}, f, ensure_ascii=False)
    kinds = {}
    for _, _, r, _ in packets:
        k = r.split("（")[0]
        kinds[k] = kinds.get(k, 0) + 1
    print("prepare: %d item(s): auto %d (synth/auto/, synth-auto.jsonl) / SYNTH %d (synth-in/: %s)"
          % (len(members), len(auto), len(packets), ", ".join("%s %d" % kv for kv in kinds.items()) or "-"))
    for wid, n, r, fs in packets:
        print("SYNTH\t%s\t%d\t%s\t%s" % (wid, n, r, fs))
    return 1 if tree_fail else 0


def copy_target(target, dst):
    def ignore(d, names):
        return [n for n in names if n in SKIP_DIRS] if os.path.realpath(d) == os.path.realpath(target) else []
    shutil.copytree(target, dst, ignore=ignore)


def check_one(target, diff, dst, node):
    """対象の新しい複製dstにdiffを`git apply --check`してから当て、変更したJS・JSONを確かめる。
    (状態 APPLIED|CHECK_FAIL, 注記, 問題の数)"""
    copy_target(target, dst)
    diff = os.path.abspath(diff)
    git = ["git", "-c", "core.autocrlf=false", "apply"]
    r = subprocess.run(git + ["--check", diff], cwd=dst, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode == 0:
        r = subprocess.run(git + [diff], cwd=dst, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        return "CHECK_FAIL", (r.stderr.strip().splitlines() or ["?"])[0], 1
    notes, bad = [], 0
    with open(diff, encoding="utf-8") as f:
        touched = sorted({p for _, p, _ in parse_diff(f.read()) if p})
    for p in touched:
        fp = os.path.join(dst, p)
        if p.endswith((".js", ".mjs", ".cjs")):
            if not node:
                notes.append(p + ":node無し")
                continue
            c = subprocess.run([node, "--check", fp], capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            notes.append(p + (":ok" if c.returncode == 0 else ":NG"))
            bad += c.returncode != 0
        elif p.endswith(".json"):
            try:
                with open(fp, encoding="utf-8") as f:
                    json.load(f)
                notes.append(p + ":json ok")
            except (OSError, ValueError):
                notes.append(p + ":json NG")
                bad += 1
    return "APPLIED", " ".join(notes), bad


GIT_ID = ["-c", "user.name=synth", "-c", "user.email=synth@localhost", "-c", "commit.gpgsign=false",
          "-c", "core.autocrlf=false"]


def git(tree, *args):
    return subprocess.run(["git"] + GIT_ID + list(args), cwd=tree, capture_output=True)


def make_tree(target, tree, base_diff):
    """SYNTHの作業ツリー: 対象の複製を基準コミットし、代表の確定diffが当たれば未コミットで当てておく。
    当てたら True"""
    copy_target(target, tree)
    for a in (("init", "-q"), ("add", "-A"), ("commit", "-q", "--allow-empty", "-m", "base")):
        r = git(tree, *a)
        if r.returncode:
            raise OSError("git %s: %s" % (a[0], r.stderr.decode("utf-8", "replace").strip()))
    try:
        files = parse_diff(base_diff or "")
        if not files:
            return False
        new_text, noeol = {}, {}
        for old, new, hunks in files:
            if new is None or (old is not None and old != new):
                return False
            if old is None and os.path.exists(os.path.join(tree, new)):
                return False
            if new not in new_text:
                new_text[new], noeol[new] = ([], False) if old is None else read_text(tree, old)
            new_text[new] = apply_hunks(new_text[new], hunks, new)
    except (NoApply, OSError, UnicodeDecodeError):
        return False
    for rel, lines in new_text.items():
        p = os.path.join(tree, rel)
        os.makedirs(os.path.dirname(p) or tree, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("".join(with_eol(lines, noeol[rel])))
    return True


def finish(work, target, wid, out_dir):
    """作業ツリーの変更を厳密な`group.diff`にして out_dir に書き、対象の新しい複製で確かめる"""
    tree = os.path.join(work, "synth-work", wid)
    if not os.path.isdir(os.path.join(tree, ".git")):
        print("NG: 作業ツリーが無い（prepareで作る）: " + tree)
        return 2
    git(tree, "add", "-A")
    r = git(tree, "diff", "--cached", "--no-color", "--no-ext-diff", "--no-renames", "--src-prefix=a/",
            "--dst-prefix=b/", "HEAD")
    if r.returncode or not r.stdout.strip():
        print("NG: %s 変更が無い（diffを作らない要検討なら、理由を %s に書く）" % (wid, NODIFF))
        return 1
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "group.diff")
    with open(path, "wb") as f:  # gitの出力のまま（CRLFのファイルの行末も保つ）
        f.write(r.stdout)
    with tempfile.TemporaryDirectory() as td:
        status, note, bad = check_one(target, path, os.path.join(td, "t"), shutil.which("node"))
    print("finish: %s %s %s -> %s" % (wid, status, note, path))
    return 1 if bad else 0


def read_return(wid, paths):
    """SYNTH・SCA-SYNTHが書いた`return.json`（戻り値のJSON1行。UTF-8）を読み、(行, 問題)を返す"""
    if len(paths) != 1:
        return None, ("%s が無い" % RETURN) if not paths else ("%s が複数: %s" % (RETURN, ", ".join(paths)))
    try:
        with open(paths[0], "rb") as f:
            obj = json.loads(f.read().decode("utf-8-sig"))
    except UnicodeDecodeError:
        return None, "%s がUTF-8でない（Writeで書き直す）" % RETURN
    except ValueError as e:
        return None, "%s がJSONでない（%s）" % (RETURN, e)
    if not isinstance(obj, dict) or obj.get("work_id") != wid:
        return None, "%s がJSONオブジェクトでない、またはwork_idが%sでない" % (RETURN, wid)
    miss = [k for k in (SCA_RET_K if "pkg_table" in obj else SYNTH_RET_K) if k not in obj]
    return obj, ("%s のキーが無い: %s" % (RETURN, ",".join(miss))) if miss else None


def fill_diff(work, target, row, paths, masker):
    """戻り値の`fix_suggestion`が`@group.diff`なら、group.diffの内容（秘密値は<マスク>。`fix_note`があれば前に置く）
    で置き換える。(行, 問題)"""
    if len(paths) != 1:
        return None, "fix_suggestion が %s だが group.diff が無い、または複数" % FILL
    if not masker:
        try:
            with open(os.path.join(work, "synth", "auto", PREP), encoding="utf-8") as f:
                masker.append(mp.Masker(target, json.load(f)["mask_file"]))
        except (OSError, ValueError, KeyError) as e:
            return None, "fix_suggestion を埋めるマスクの設定が読めない（prepareの %s）: %s" % (PREP, e)
    with open(paths[0], encoding="utf-8", newline="") as f:
        diff = f.read()
    row = dict(row)
    note = str(row.pop("fix_note", "") or "").rstrip("\n")
    row["fix_suggestion"] = masker[0]((note + "\n" if note else "") + diff)
    return row, None


def apply(work, target, force=False):
    out = os.path.join(work, "synth-apply")
    if os.path.exists(out):
        if not force:
            print("NG: 出力が既に有る（--forceで上書き）: " + out)
            return 2
        rmtree(out)
    os.makedirs(out)
    members = json.load(open(os.path.join(work, "members.json"), encoding="utf-8"))
    found, nodiff, rets = {}, {}, {}
    for name, d in (("group.diff", found), (NODIFF, nodiff), (RETURN, rets)):
        for p in glob.glob(os.path.join(work, "synth", "**", name), recursive=True):
            d.setdefault(os.path.basename(os.path.dirname(p)), []).append(p)
    ap = os.path.join(work, "synth-auto.jsonl")
    autos = {r.get("work_id"): r for r in (mp.load_jsonl(ap) if os.path.isfile(ap) else [])}
    node = shutil.which("node")
    log, bad, rows, masker = [], 0, [], []
    for wid in members:
        row, why = autos.get(wid), None
        if row is None:
            row, why = read_return(wid, rets.get(wid, []))
            if not why and row.get("fix_suggestion") == FILL:
                row, why = fill_diff(work, target, row, found.get(wid, []), masker)
        if why:
            log.append("%s\tRETURN_NG\t%s" % (wid, why))
            bad += 1
        else:
            rows.append(row)
    with open(os.path.join(work, "synth-out.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    for wid in members:
        ps = found.get(wid, [])
        nd = nodiff.get(wid, [])
        if not ps and len(nd) == 1:
            with open(nd[0], encoding="utf-8") as f:
                why = " ".join(f.read().split())
            if REVIEW in why:  # SYNTHが要検討としてdiffを作らなかった群。欠けではない
                log.append("%s\tNODIFF\t%s" % (wid, why[:120]))
                continue
        if len(ps) != 1 or nd:
            if nd and ps:
                why = "group.diff と %s が両方ある" % NODIFF
            elif nd:
                why = "%s に「%s」が無い、または複数" % (NODIFF, REVIEW)
            else:
                why = "group.diff が無い" if not ps else "group.diff が複数: " + ", ".join(ps)
            log.append("%s\tMISSING\t%s" % (wid, why))
            bad += 1
            continue
        status, note, b = check_one(target, ps[0], os.path.join(out, wid), node)
        log.append("%s\t%s\t%s" % (wid, status, note))
        bad += b
    with open(os.path.join(out, "apply-log.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(log) + "\n")
    ok = sum("\tAPPLIED\t" in l and ":NG" not in l and "json NG" not in l for l in log)
    nds = sum("\tNODIFF\t" in l for l in log)
    print("apply: %d of %d group(s) applied and checked; %s without diff %d; problems %d (synth-apply/apply-log.txt);"
          " %d return(s) -> synth-out.jsonl" % (ok, len(members), REVIEW, nds, bad, len(rows)))
    for l in log:
        if "\tNODIFF\t" in l:
            print("INFO\t" + l)
        elif "\tAPPLIED\t" not in l or ":NG" in l or "json NG" in l:
            print("NG\t" + l)
    return 1 if bad else 0


def self_test():
    with tempfile.TemporaryDirectory() as d:
        tgt, work = os.path.join(d, "app"), os.path.join(d, "work")
        os.makedirs(os.path.join(tgt, "routes"))
        os.makedirs(os.path.join(tgt, ".git"))
        os.makedirs(os.path.join(work, "out"))
        src = "".join("l%d\n" % i for i in range(1, 31))
        with open(os.path.join(tgt, "routes", "a.js"), "w", encoding="utf-8", newline="\n") as f:
            f.write(src.replace("l1\n", "const secret = 'Sup3rS3cretValue';\n", 1))
        mf = os.path.join(d, "mask.txt")
        with open(mf, "w", encoding="utf-8") as f:
            f.write("Sup3rS3cretValue\n")
        # 末尾の文脈行が無いdiff（gitは当てない）。見出しの行番号もずれている
        loose = "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -9,3 +9,4 @@\n l10\n-l11\n+L11\n+L11b\n"
        far = "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -20,2 +20,2 @@\n-nothing\n+x\n"
        rows = [("R0101", loose, "CONFIRMED"), ("R0102", "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -20,1 +20,1 @@\n-l20\n+L20\n", "CONFIRMED"),
                ("R0103", "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -21,1 +21,1 @@\n-l21\n+L21\n", "PLAUSIBLE"),
                ("R0104", far, "CONFIRMED"), ("R0105", loose.replace("L11b", "要検討の暫定"), "CONFIRMED"),
                ("R0106", "--- /dev/null\n+++ b/.gitignore\n@@ -0,0 +1,1 @@\n+node_modules/\n", "CONFIRMED"),
                ("R0107", "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -25,1 +25,1 @@\n-l25\n+function x( {\n", "CONFIRMED")]
        with open(os.path.join(work, "findings-log.jsonl"), "w", encoding="utf-8") as f:
            for t, dfx, v in rows:
                f.write(json.dumps({"tmp_id": t, "file_line": "routes/a.js:1", "severity": "High", "summary": "s",
                                    "verdict": v, "diff": dfx, "diff_source": "blue"}, ensure_ascii=False) + "\n")
        with open(os.path.join(work, "out", "red-01.jsonl"), "w", encoding="utf-8") as f:
            for t, _, _ in rows:
                f.write(json.dumps({"id": "R01-" + t[-2:], "file_line": "routes/a.js:1", "category": "x CWE-1",
                                    "severity": "High", "summary": "s Sup3rS3cretValue", "root_cause": "r",
                                    "failure_scenario": "f", "intent": "i"}, ensure_ascii=False) + "\n")
        with open(os.path.join(work, "out", "blue-01.jsonl"), "w", encoding="utf-8") as f:
            for t, _, v in rows:
                f.write(json.dumps({"n": "R01-" + t[-2:], "verdict": v, "evidence": "e"}, ensure_ascii=False) + "\n")
        mem = {"F1": ["R0102", "R0103"], "F2": ["R0101"], "F3": ["R0104"], "F4": ["R0105"], "F5": ["R0106"],
               "F6": ["R0107"]}
        chk = bool(shutil.which("node") and shutil.which("git"))  # F6は構文の壊れたdiff（確かめられればSYNTHへ）
        with open(os.path.join(work, "members.json"), "w", encoding="utf-8") as f:
            json.dump(mem, f)
        buf = io.StringIO()
        old, sys.stdout = sys.stdout, buf
        try:
            rc = prepare(work, tgt, mf)
            rc2 = prepare(work, tgt, mf)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert rc == 0 and rc2 == 2, out
        assert ("auto 2" if chk else "auto 3") in out and ("SYNTH 4" if chk else "SYNTH 3") in out, out
        assert "群 1" in out and "要検討 1" in out and (not chk or "構文NG 1" in out), out
        g = open(os.path.join(work, "synth", "auto", "F2", "group.diff"), encoding="utf-8").read()
        assert g.startswith("diff --git a/routes/a.js b/routes/a.js\n--- a/routes/a.js\n+++ b/routes/a.js\n@@ -8,7 +8,8 @@"), g
        assert "+L11b\n l12\n" in g, g
        assert os.path.exists(os.path.join(work, "synth", "auto", "F5", "group.diff"))
        autos = mp.load_jsonl(os.path.join(work, "synth-auto.jsonl"))
        assert [r["work_id"] for r in autos] == ["F2", "F5"] + ([] if chk else ["F6"]) and autos[0]["intent"] == "i", autos
        assert set(autos[0]) == set(SYNTH_RET_K), set(autos[0]) ^ set(SYNTH_RET_K)  # SYNTHの戻り値と同じキー
        pk = json.load(open(os.path.join(work, "synth-in", "F1.json"), encoding="utf-8"))
        assert pk["base"] == "R0102" and len(pk["items"]) == 2, pk
        assert "Sup3rS3cretValue" not in json.dumps(pk, ensure_ascii=False) and "<マスク>" in json.dumps(pk, ensure_ascii=False)
        assert sorted(os.listdir(os.path.join(work, "synth-in"))) == ["F1.json", "F3.json", "F4.json"] + (["F6.json"] if chk else [])
        assert pk["tree"].endswith("/synth-work/F1") and pk["finish"].endswith(" --wid F1"), pk
        assert pk["return"].endswith("/synth/F1/return.json"), pk
        if shutil.which("git"):
            # 作業ツリー: 基準コミット済み。代表（R0102）のdiffが未コミットで当ててある。当たらない群はnull
            t1 = os.path.join(work, "synth-work", "F1")
            assert pk["pre_applied"] == "R0102" and os.path.isdir(os.path.join(t1, ".git")), pk
            a1 = os.path.join(t1, "routes", "a.js")
            assert "L20\n" in open(a1, encoding="utf-8").read()
            pk3 = json.load(open(os.path.join(work, "synth-in", "F3.json"), encoding="utf-8"))
            assert pk3["pre_applied"] is None, pk3
            # finish: SYNTHが残りのメンバー（R0103）を足した後、厳密なdiffを書いて確かめる
            with open(a1, encoding="utf-8") as f:
                s1 = f.read().replace("l21\n", "L21\n")
            with open(a1, "w", encoding="utf-8", newline="\n") as f:
                f.write(s1)
            fo = os.path.join(d, "fin", "F1")
            sys.stdout = io.StringIO()
            try:
                rc_f = finish(work, tgt, "F1", fo)
                rc_n = finish(work, tgt, "F3", os.path.join(d, "fin", "F3"))
                rc_m = finish(work, tgt, "F9", os.path.join(d, "fin", "F9"))
                out = sys.stdout.getvalue()
            finally:
                sys.stdout = old
            gd = open(os.path.join(fo, "group.diff"), encoding="utf-8").read()
            assert rc_f == 0 and "finish: F1 APPLIED routes/a.js:" in out, out
            assert gd.startswith("diff --git a/routes/a.js b/routes/a.js") and "+L20\n" in gd and "+L21\n" in gd, gd
            assert rc_n == 1 and "F3 変更が無い" in out and rc_m == 2, out
            assert not os.path.exists(os.path.join(d, "fin", "F3")), "変更が無ければ書かない"
            # --force: gitの読み取り専用のオブジェクトがあっても作り直せる
            sys.stdout = io.StringIO()
            try:
                rc_r = prepare(work, tgt, mf, force=True)
                out = sys.stdout.getvalue()
            finally:
                sys.stdout = old
            assert rc_r == 0 and "WARN" not in out and "L21\n" not in open(a1, encoding="utf-8").read(), out
            # SYNTHの戻り値の代わりに、F1・F3・F4の group.diff を置く（F4は壊れたdiff）
            for wid, dfx in (("F1", "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -19,3 +19,3 @@\n l19\n-l20\n+L20\n l21\n"),
                             ("F3", None), ("F4", "--- a/routes/a.js\n+++ b/routes/a.js\n@@ -1,1 +1,1 @@\n-nope\n+x\n")):
                p = os.path.join(work, "synth", "K1", wid)
                os.makedirs(p)
                if dfx:
                    with open(os.path.join(p, "group.diff"), "w", encoding="utf-8", newline="\n") as f:
                        f.write(dfx)
            if chk:  # SYNTHが直したF6
                p = os.path.join(work, "synth", "K1", "F6")
                os.makedirs(p)
                with open(os.path.join(p, "group.diff"), "w", encoding="utf-8", newline="\n") as f:
                    f.write("--- a/routes/a.js\n+++ b/routes/a.js\n@@ -24,3 +24,3 @@\n l24\n-l25\n+L25\n l26\n")

            def ret(wid, enc="utf-8", **kw):  # SYNTHの戻り値（return.json）
                row = {k: [] for k in SYNTH_RET_K}
                row.update(work_id=wid, fold_log="取り込み 説明")
                row.update(kw)
                with open(os.path.join(work, "synth", "K1", wid, RETURN), "wb") as f:
                    f.write(json.dumps(row, ensure_ascii=False).encode(enc))

            ret("F1")
            ret("F3", enc="cp932")  # Windowsの標準出力経由で書かれた形
            ret("F4", work_id="F9")
            if chk:
                ret("F6")
            buf = io.StringIO()
            sys.stdout = buf
            try:
                rc = apply(work, tgt)
            finally:
                sys.stdout = old
            out = buf.getvalue()
            lg = open(os.path.join(work, "synth-apply", "apply-log.txt"), encoding="utf-8").read()
            assert rc == 1, out
            assert "F1\tAPPLIED" in lg and "F2\tAPPLIED" in lg and "F5\tAPPLIED" in lg, lg
            assert "F3\tMISSING" in lg and "F4\tCHECK_FAIL" in lg, lg
            assert not os.path.exists(os.path.join(work, "synth-apply", "F2", ".git"))
            assert "L11b" in open(os.path.join(work, "synth-apply", "F2", "routes", "a.js"), encoding="utf-8").read()
            # return.json: UTF-8でない・work_idが違うものはRETURN_NG。正しいものと自動の行をmembersの順に連結
            assert "F3\tRETURN_NG\treturn.json がUTF-8でない" in lg and "F4\tRETURN_NG\t" in lg, lg
            so = os.path.join(work, "synth-out.jsonl")
            assert [r["work_id"] for r in mp.load_jsonl(so)] == ["F1", "F2", "F5", "F6"], open(so, encoding="utf-8").read()
            ret("F3")
            os.remove(os.path.join(work, "synth", "K1", "F4", RETURN))
            os.makedirs(os.path.join(work, "synth", "K2", "F4"))
            with open(os.path.join(work, "synth", "K2", "F4", RETURN), "w", encoding="utf-8") as f:
                f.write('{"work_id": "F4"}\n')
            # no-diff.txt: 要検討の理由があれば欠けではない。理由に要検討が無い、group.diffと両方、は欠け
            ndp = os.path.join(work, "synth", "K1", "F3", NODIFF)
            f4 = os.path.join(work, "synth", "K1", "F4", "group.diff")
            os.remove(f4)

            def run_apply():
                sys.stdout = io.StringIO()
                try:
                    r = apply(work, tgt, force=True)
                    o = sys.stdout.getvalue()
                finally:
                    sys.stdout = old
                return r, o, open(os.path.join(work, "synth-apply", "apply-log.txt"), encoding="utf-8").read()

            with open(ndp, "w", encoding="utf-8") as f:
                f.write("方式の判断が要る\n")
            with open(os.path.join(work, "synth", "K1", "F4", NODIFF), "w", encoding="utf-8") as f:
                f.write("要検討（運用判断）\n")
            rc, out, lg = run_apply()
            assert rc == 1 and "F3\tMISSING" in lg and "F4\tNODIFF\t要検討（運用判断）" in lg, (out, lg)
            assert "F4\tRETURN_NG\treturn.json のキーが無い: members,fold_log" in lg, lg  # 要検討の群も戻り値は要る
            ret("F4")
            os.remove(os.path.join(work, "synth", "K2", "F4", RETURN))
            with open(ndp, "w", encoding="utf-8") as f:
                f.write("要検討（理由: 方式の判断が要る）\n")
            rc, out, lg = run_apply()
            assert rc == 0 and "F3\tNODIFF" in lg and "without diff 2; problems 0" in out, (out, lg)
            assert "6 return(s) -> synth-out.jsonl" in out and len(mp.load_jsonl(so)) == 6, out
            with open(os.path.join(os.path.dirname(ndp), "group.diff"), "w", encoding="utf-8", newline="\n") as f:
                f.write("--- a/routes/a.js\n+++ b/routes/a.js\n@@ -19,3 +19,3 @@\n l19\n-l20\n+L20\n l21\n")
            rc, out, lg = run_apply()
            assert rc == 1 and "F3\tMISSING\tgroup.diff と no-diff.txt が両方ある" in lg, (out, lg)
            # fix_suggestion が @group.diff: applyが group.diff の内容（マスク済み。fix_noteを前に）で埋める
            os.remove(os.path.join(os.path.dirname(ndp), "group.diff"))
            with open(os.path.join(work, "synth", "K1", "F1", "group.diff"), "a", encoding="utf-8", newline="\n") as f:
                f.write("+// Sup3rS3cretValue\n")
            ret("F1", fix_suggestion=FILL, fix_note="要検討（暫定のdiff）。")
            rc, out, lg = run_apply()
            r1 = [r for r in mp.load_jsonl(so) if r["work_id"] == "F1"][0]
            assert r1["fix_suggestion"].startswith("要検討（暫定のdiff）。\n--- a/routes/a.js\n") and "fix_note" not in r1, r1
            assert "<マスク>" in r1["fix_suggestion"] and "Sup3rS3cretValue" not in r1["fix_suggestion"], r1
            ret("F1", fix_suggestion=FILL)
            os.rename(os.path.join(work, "synth", "K1", "F1", "group.diff"), os.path.join(d, "g1.diff"))
            rc, out, lg = run_apply()
            assert rc == 1 and "F1\tRETURN_NG\tfix_suggestion が @group.diff だが group.diff が無い" in lg, lg
    with tempfile.TemporaryDirectory() as d:  # 末尾に改行が無いファイル
        tgt = os.path.join(d, "app")
        os.makedirs(tgt)
        with open(os.path.join(tgt, "b.js"), "w", encoding="utf-8", newline="\n") as f:
            f.write("b1\nb2\nb3")
        dfx = "--- a/b.js\n+++ b/b.js\n@@ -2,2 +2,2 @@\n b2\n-b3\n+B3\n"
        try:
            strict_diff(tgt, dfx)
            raise AssertionError("単独項目の自動化の条件は従来どおり（末尾に改行が無いファイルはSYNTHへ）")
        except NoApply as e:
            assert str(e) == "b.js: 末尾に改行が無い", e
        if shutil.which("git"):
            tree = os.path.join(d, "tree")
            assert make_tree(tgt, tree, dfx + "@@ -1,1 +1,2 @@\n b1\n+b1x\n") is False  # 当たらない順のhunk
            rmtree(tree)
            assert make_tree(tgt, tree, dfx) is True
            assert open(os.path.join(tree, "b.js"), encoding="utf-8", newline="").read() == "b1\nb2\nB3"
            r = git(tree, "diff", "--no-color")
            assert r.stdout.decode().count("\\ No newline at end of file") == 2, r.stdout
    print("self-test OK")
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["--self-test"]:
        return self_test()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=("prepare", "finish", "apply"))
    ap.add_argument("--work", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mask-file")
    ap.add_argument("--wid", help="finish: 群のwork_id")
    ap.add_argument("--out", help="finish: group.diffの出力先（既定: WORK/synth/<work_id>）")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    if a.step == "prepare":
        if not a.mask_file:
            ap.error("prepare requires --mask-file")
        return prepare(a.work, a.target, a.mask_file, a.force)
    if a.step == "finish":
        if not a.wid:
            ap.error("finish requires --wid")
        return finish(a.work, a.target, a.wid, a.out or os.path.join(a.work, "synth", a.wid))
    return apply(a.work, a.target, a.force)


if __name__ == "__main__":
    sys.exit(main())
