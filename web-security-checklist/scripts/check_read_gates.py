#!/usr/bin/env python3
"""読了ゲートの遵守を、実行後の記録（transcript）と成果物から機械的に点検する（読み取り専用・LLM不使用）。

使い方:
  python3 check_read_gates.py --manifest web-security-checklist/manifest.json --mode {2,3} \
      --transcript session.jsonl [--agents-dir tasks/] [--report path.md] [--evidence-dir outputs/] [--json] [--verbose]

判定: PASS / NG / UNDETERMINED（決められないときは決して PASS にしない）。
終了コード: 0=すべてPASS, 1=NGあり, 3=NGなしでUNDETERMINEDあり。
記録の形式は Claude Code の JSONL（type=assistant の message.content に text / tool_use）。
読めない行・未知の行は数えて飛ばす（致命にしない）。

読了の数え方（保守的）:
- 数えるのはオーケストレータ本人のReadのみ（サブエージェントの読了は数えない）。
- Readのtool_use_idに対応するtool_result（user行）が無い（打切り等）→UNDETERMINED。エラー・拒否のReadは読了に数えない。
- offset/limit付きは部分読み。総行数（--skill-root または manifest 所在のファイルの行数。manifestに行数は無い）を
  複数のReadの範囲の和が覆うときだけ読了。総行数が不明なら UNDETERMINED。
- パスはスキル根（--skill-root、無ければ記録のSKILL.mdのRead、無ければmanifestの場所）直下に解決されるものだけ有効。
  別ディレクトリの同名ファイル・末尾一致・部分一致は無効。/ と バックスラッシュは同一視、大文字小文字を無視するのはドライブ文字のみ。
- --transcript は複数回指定でき、渡した順に1本の継続として扱う（再開）。圧縮マーカー（summary / compact_boundary）より前の
  Readはstale扱いで UNDETERMINED（圧縮後に読み直せば有効）。
"""
import argparse, fnmatch, glob, json, os, posixpath, re, sys

PASS, NG, UND = "PASS", "NG", "UNDETERMINED"
AGENT_TOOLS = ("Agent", "Task")
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

# ---- 成果物の検査表: 各行に出典の文書を付ける。出典に無い要件は載せない ----------------------
# 章は assets/templates/report_template.md の見出し番号。R=必須 C=条件付き（無ければ condition unknown） O=省略可
CHAPTERS = [  # (番号, 見出し語, mode2, mode3, 出典)
    (1, "エグゼクティブサマリー", "R", "R", "assets/templates/report_template.md 見出し1。モード2は mode2-audit-review.md が同じ見出し語・構成を要求し、省略を許すのは9のみ"),
    (2, "実施メタデータ", "R", "R", "mode2-audit-review.md「2. 実施メタデータは省略せず記入する」"),
    (3, "カテゴリ別実施状況", "R", "R", "mode2-audit-review.md（簡略化して記載）／report_template.md"),
    (4, "指摘サマリー", "R", "R", "assets/templates/report_template.md 見出し4"),
    (5, "指摘詳細", "R", "R", "assets/templates/report_template.md 見出し5"),
    (6, "リスク分析", "R", "R", "mode2-audit-review.md「メトリクス別の判定根拠はリスク分析章を参照」／report_template.md"),
    (7, "要確認事項", "C", "C", "report_template.md 見出し7（Plausible判定がある場合）"),
    (8, "SCA", "C", "C", "mode2-audit-review.md「SCAを実行した場合のみ、8節」／report_template.md"),
    (9, "自己レビュー", "O", "R", "mode2-audit-review.md「モード2では節自体を省略してよい」／mode3-report.md"),
    (10, "次のアクション", "R", "R", "assets/templates/report_template.md 見出し10"),
    (11, "出典別レポート", "C", "C", "report_template.md 見出し11（出典別ファイル保存時。mode3-by-source.md）"),
    (12, "留意事項", "R", "R", "assets/templates/report_template.md 見出し12"),
]
FINDING_CHECKS = [  # (キー, 説明, 正規表現, 出典)
    ("cvss31", "CVSS v3.1 のスコア（数値。「未算出（理由）」は注記扱い）", r"^[ \t]*(?:\|[ \t]*CVSS v3\.1[ \t]*\|[ \t]*|[-*][ \t]*CVSS:[ \t]*v3\.1[ \t]+)(\d{1,2}\.\d|未算出)",
     "report_template.md 5節表「CVSS v3.1」／mode2-audit-review.md「CVSS: v3.1 …」"),
    ("cvss40", "CVSS v4.0 のスコア（同上）", r"^[ \t]*(?:\|[ \t]*CVSS v4\.0[ \t]*\|[ \t]*|[-*][ \t]*CVSS:[^\n]*?/[ \t]*v4\.0[ \t]+)(\d{1,2}\.\d|未算出)",
     "report_template.md 5節表「CVSS v4.0」／mode2-audit-review.md"),
    ("sources", "根拠（sourcesタグ由来の行）", r"根拠", "report_template.md 5節表「根拠」／mode2-audit-review.md「根拠: <sources…>」"),
    ("5d-plain", "5d: わかりやすい解説", r"わかりやすい解説", "mode2-audit-review.md 5d／report_template.md"),
    ("5d-tech", "5d: 技術的詳細解説", r"技術的詳細解説", "mode2-audit-review.md 5d／report_template.md"),
    ("5d-annot", "5d: 該当コードの問題点", r"該当コードの問題点", "mode2-audit-review.md 5d／report_template.md"),
    ("5d-fix", "5d: 修正内容の解説", r"修正内容の解説", "mode2-audit-review.md 5d／report_template.md"),
    ("5e", "5e: 修正案の監査レビュー", r"修正案の監査レビュー", "mode2-audit-review.md 5e／report_template.md"),
]
EVIDENCE = [  # (ファイル, mode2での不在の扱い, mode3での不在の扱い, 出典)
    ("cvss-raw-output.jsonl", UND, NG, "mode3-report.md（前提: CVSS生JSON Linesが手元にあること）"),
    ("cvss-decisions.jsonl", UND, NG, "mode3-report.md（check_cvss_decisions.py --decisions／保存先へ複製）"),
]


DOC_DIRS = ("references/core", "references/modes", "references/pipeline", "references/cvss", "references/design",
            "references/checklists", "references/sources", "references", "assets/templates", "assets")  # P3の階層

def lp(p):
    """Windows long-path (over 260 chars) support: add the extended-length prefix."""
    if os.name == "nt" and p and not p.startswith(chr(92)*2):
        return chr(92)*2 + "?" + chr(92) + os.path.abspath(p)
    return p


def norm_path(p):
    """/ と \\ を揃え、.. を解決する。大文字小文字を無視するのはドライブ文字だけ。"""
    p = (p or "").replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", p):
        p = p[0].lower() + p[1:]
    return posixpath.normpath(p) if p else p


def norm(p):
    return (p or "").replace("\\", "/")


def path_matches(path, rel, root):
    """pathがスキル根(root)直下のrelに解決される場合だけTrue（末尾一致・部分一致は不可）。"""
    if not root:
        return False
    full = norm_path(root) + "/" + norm(rel)
    p = norm_path(path)
    return fnmatch.fnmatchcase(p, full) if "*" in rel else p == full


class Transcript:
    DENIED = re.compile(r"^\s*(<tool_use_error>|The user doesn't want|Permission to use|Permission denied|File does not exist|Error:)")

    def __init__(self, skill_name="web-security-checklist"):
        self.seq = 0
        self.reads = []       # dict(idx, path, id, offset, limit)
        self.results = {}     # tool_use_id -> is_error
        self.compactions = []  # 圧縮マーカーの位置
        self.agents = []     # (idx, text)
        self.writes = []     # (idx, path, tool)
        self.texts = []      # (idx, text)
        self.skipped = 0
        self.lines = 0
        self.skill_name = skill_name
        self.root = None
        self.disk_root = None
        self._lc = {}

    def lines_of(self, rel):
        """ファイルの総行数（ディスク上のスキル根から数える。無ければNone）。"""
        if rel in self._lc:
            return self._lc[rel]
        n = None
        if self.disk_root and "*" not in rel:
            fp = lp(os.path.join(self.disk_root, *rel.split("/")))
            try:
                with open(fp, "rb") as f:
                    data = f.read()
                n = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
            except OSError:
                n = None
        self._lc[rel] = n
        return n

    def detect_root(self, explicit, manifest_path):
        if explicit:
            self.root = norm_path(explicit)
            self.disk_root = explicit if os.path.isdir(lp(explicit)) else None
        else:
            for r in self.reads:
                p = norm_path(r["path"])
                if posixpath.basename(p) == "SKILL.md" and posixpath.basename(posixpath.dirname(p)) == self.skill_name:
                    self.root = posixpath.dirname(p)
                    break
        mdir = os.path.dirname(os.path.abspath(manifest_path))
        if self.root is None:
            self.root = norm_path(mdir)
        if self.disk_root is None and os.path.isdir(lp(mdir)):
            self.disk_root = mdir

    def read_state(self, rel):
        """(状態, 完了位置, 理由)。状態: OK / UND / NONE。エラー・拒否のReadは数えない。"""
        cands = [r for r in self.reads if path_matches(r["path"], rel, self.root)]
        if not cands:
            return "NONE", None, ""
        n = self.lines_of(rel)
        spans, why, done, partial = [], None, None, False
        for r in sorted(cands, key=lambda x: x["idx"]):
            if r["id"] is None or r["id"] not in self.results:
                why = why or "Readのtool_resultが記録に無い（打切りの可能性）"
                continue
            if self.results[r["id"]]:
                continue  # エラー・拒否は読了に数えない
            o, l = r["offset"], r["limit"]
            if o is None and l is None and (n is None or n <= 2000):
                done = r["idx"]
                break
            s0 = o if o else 1
            spans.append((s0, s0 + (l if l else 2000) - 1))
            partial = True
            if n is None:
                why = why or "offset/limit付きの部分読みで総行数が不明"
                continue
            cur = 1
            for a, b in sorted(spans):
                if a <= cur:
                    cur = max(cur, b + 1)
            if cur > n:
                done = r["idx"]
                break
        if done is not None:
            if any(c > done for c in self.compactions):
                return "UND", done, "コンテキスト圧縮前のRead（stale）"
            return "OK", done, ""
        if why:
            return "UND", None, why
        if partial:
            return "UND", None, "部分読み(offset/limit)で全体を覆わない"
        return "NONE", None, ""

    def feed(self, line):
        self.lines += 1
        try:
            d = json.loads(line)
        except ValueError:
            self.skipped += 1
            return
        if not isinstance(d, dict):
            self.skipped += 1
            return
        if d.get("type") == "summary" or d.get("subtype") == "compact_boundary" or d.get("isCompactSummary"):
            self.compactions.append(self.seq)
            return
        m = d.get("message")
        if d.get("type") == "user" and isinstance(m, dict) and isinstance(m.get("content"), list):
            found = False
            for b in m["content"]:
                if isinstance(b, dict) and b.get("type") == "tool_result" and isinstance(b.get("tool_use_id"), str):
                    found = True
                    c = b.get("content")
                    if isinstance(c, str):
                        txt = c
                    elif isinstance(c, list):
                        txt = " ".join(x.get("text", "") for x in c if isinstance(x, dict) and isinstance(x.get("text"), str))
                    else:
                        txt = ""
                    self.results[b["tool_use_id"]] = bool(b.get("is_error")) or bool(self.DENIED.match(txt))
            if not found:
                self.skipped += 1
            return
        if d.get("type") != "assistant" or not isinstance(m, dict):
            self.skipped += 1
            return
        c = m.get("content")
        if isinstance(c, str):
            c = [{"type": "text", "text": c}]
        if not isinstance(c, list):
            self.skipped += 1
            return
        for b in c:
            if not isinstance(b, dict):
                continue
            self.seq += 1
            t = b.get("type")
            if t == "text" and isinstance(b.get("text"), str):
                self.texts.append((self.seq, b["text"]))
            elif t == "tool_use":
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                name = b.get("name")
                if name == "Read":
                    fp = inp.get("file_path") or inp.get("path")
                    if isinstance(fp, str):
                        o, l = inp.get("offset"), inp.get("limit")
                        self.reads.append({"idx": self.seq, "path": fp,
                                           "id": b.get("id") if isinstance(b.get("id"), str) else None,
                                           "offset": o if isinstance(o, int) else None,
                                           "limit": l if isinstance(l, int) else None})
                elif name in AGENT_TOOLS:
                    self.agents.append((self.seq, " ".join(str(inp.get(k, "")) for k in ("description", "prompt", "subagent_type"))))
                elif name in WRITE_TOOLS or name == "Artifact":
                    fp = inp.get("file_path") or inp.get("path") or ""
                    self.writes.append((self.seq, str(fp), name))


def load_transcripts(paths, skill_name="web-security-checklist"):
    """複数の記録を渡された順に1本の流れとして読む（再開・継続。圧縮マーカーだけを境界とみなす）。"""
    t = Transcript(skill_name)
    for path in paths:
        with open(lp(path), encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    t.feed(line)
    return t


def first_agent(t, rx=None):
    for i, txt in t.agents:
        if rx is None or re.search(rx, txt):
            return i
    return None


def first_write(t, rx):
    for i, p, name in t.writes:
        if re.search(rx, norm(p)) or (name == "Artifact" and "ARTIFACT" in rx):
            return i
    return None


def step_marker(gate, t):
    """ゲートの『手順の開始』を示す記録上の位置。決められなければ (None, 説明)。"""
    if gate in ("G0", "R1", "G1", "G2"):
        return first_agent(t), "最初のAgent起動（Red/Blue/設計書抽出のいずれも起動前に通過が必要）"
    if gate == "G3":
        a = first_agent(t, r"5[def]|監査レビュー|CVSS|cvss")
        w = first_write(t, r"(cvss-(raw-output|decisions)|5[def][^/]*)\.jsonl?$")
        c = [x for x in (a, w) if x]
        return (min(c) if c else None), "5d/5e/5f委任のAgent起動、またはCVSS/5d-5f永続化ファイルの最初の書込み"
    if gate == "G5":
        return first_write(t, r"security-audit-report\.md$|(^|/)report[^/]*\.md$"), "統合レポート(.md)の最初のWrite/Edit"
    if gate == "G6":
        return first_write(t, r"\.html?$|ARTIFACT"), "HTMLまたはArtifactの最初のWrite/公開"
    if gate == "G7":
        return first_write(t, r"by-source|security-audit-report-[a-z0-9-]+\.md$"), "出典別レポートの最初のWrite"
    return None, "未定義"


class Result:
    def __init__(self):
        self.items = []  # (status, area, message)

    def add(self, status, area, msg):
        self.items.append((status, area, msg))

    def counts(self):
        return {s: sum(1 for x in self.items if x[0] == s) for s in (PASS, NG, UND)}

    def code(self):
        c = self.counts()
        return 1 if c[NG] else (3 if c[UND] else 0)


def _need(t, f, marker, bad, und, after_label="手順開始後に読了"):
    s, i, w = t.read_state(f)
    if s == "NONE":
        bad.append("未読: " + f)
    elif s == "UND":
        und.append("%s: %s" % (f, w))
    elif marker is not None and i > marker:
        bad.append("%s: %s" % (after_label, f))
    return s, i


def check_gates_mode3(man, t, res):
    for st in man["modes"]["3"]["steps"]:
        g = st.get("gate")
        if not g:
            continue
        req = st.get("required", [])
        cond = [c["file"] for c in st.get("conditional", [])]
        toks = st.get("gate_token") or []
        if not req and not cond and not toks:
            res.add(PASS, g, "対象ファイル・トークンなし（読了要件なし）")
            continue
        marker, mdesc = step_marker(g, t)
        bad, und = [], []
        for f in req:
            _need(t, f, marker, bad, und)
        cond_state = {}
        for f in cond:
            s, i, w = t.read_state(f)
            cond_state[f] = s
            if s == "UND":
                und.append("%s: %s" % (f, w))
            elif s == "OK" and marker is not None and i > marker:
                bad.append("手順開始後に読了(条件付き): " + f)
        if cond and not req and all(v == "NONE" for v in cond_state.values()):
            if any("設計書なし" in x and g in x for _, x in t.texts):
                res.add(PASS, g, "条件付き・設計書なしの記載あり（トークン不要）")
            else:
                res.add(UND, g, "条件付きファイル未読で、条件（候補の有無）を記録から決められない: " + ", ".join(cond))
            continue
        for tk in toks:
            s, r, w = t.read_state(tk["file"])
            if s == "NONE":
                bad.append("トークン対象ファイル未読: " + tk["file"])
                continue
            if s == "UND":
                m = "%s: %s" % (tk["file"], w)
                if m not in und:
                    und.append(m)
                continue
            hit = [i for i, x in t.texts if tk["value"] in x]
            if not hit:
                bad.append("トークン未引用: " + tk["id"])
            elif max(hit) < r:
                bad.append("トークンがRead前にしか引用されていない: " + tk["id"])
        if bad:
            res.add(NG, g, "; ".join(bad))
        elif und:
            res.add(UND, g, "読了を確定できない: " + "; ".join(und))
        elif marker is None:
            res.add(UND, g, "読了・トークンは良いが手順開始位置を決められない（%sが記録に無い）" % mdesc)
        else:
            res.add(PASS, g, "読了と引用は手順開始前（基準: %s）" % mdesc)


def check_mode2_gate(st, t, res):
    """モード2のゲート（M4: 手順4の前）。対象ファイルの読了とGATE-TOKENの引用が、5d/5e/5fの委任・CVSSの永続化の
    最初の位置（無ければ最終応答）より前にあるか。Agent起動が無ければ手順4に進んだかを決められない（PASSにしない）。"""
    g, req, toks = st["gate"], st.get("required", []), st.get("gate_token") or []
    if first_agent(t) is None:
        res.add(UND, g, "Agent起動が記録に無く、手順4に進んだか（ゲート%sの要否）を決められない" % g)
        return
    marker, mdesc = step_marker("G3", t)
    if marker is None and t.texts:
        marker, mdesc = t.texts[-1][0], "最終応答（5d/5e/5fの委任・CVSSの永続化が記録に無い）"
    bad, und = [], []
    for f in req:
        _need(t, f, marker, bad, und, "手順4以降に読了")
    for tk in toks:
        s, r, w = t.read_state(tk["file"])
        if s != "OK":
            continue  # 未読・未確定は上で計上済み
        hit = [i for i, x in t.texts if tk["value"] in x]
        if not hit:
            bad.append("トークン未引用: " + tk["id"])
        elif max(hit) < r:
            bad.append("トークンがRead前にしか引用されていない: " + tk["id"])
    if bad:
        res.add(NG, g, "; ".join(bad))
    elif und:
        res.add(UND, g, "読了を確定できない: " + "; ".join(und))
    elif marker is None:
        res.add(UND, g, "読了・トークンは良いが手順4の開始位置を決められない")
    else:
        res.add(PASS, g, "読了と引用は手順4の前（基準: %s）" % mdesc)


def check_gates_mode2(man, t, res, report_given, evidence_dir):
    marker = first_agent(t)
    allsteps = man["modes"]["2"]["steps"]
    steps = [s for s in allsteps if not s.get("gate")]
    decided = {}
    if report_given:
        decided["M2-B"] = "--report 指定（レポート保存あり）"
    if evidence_dir and glob.glob(os.path.join(evidence_dir, "security-audit-report-*.md")):
        decided["M2-C"] = "出典別レポートの成果物あり"
    bad, und = [], []
    late = "最初のAgent起動後に読了"
    for s in steps:
        for f in s.get("required", []):
            _need(t, f, marker, bad, und, late)
    for s in steps:
        for c in s.get("conditional", []):
            f, cid = c["file"], c["condition_id"]
            if cid in decided:
                st, _i = _need(t, f, marker, bad, und, late)
                if st == "NONE":
                    bad[-1] = "未読(条件成立: %s): %s" % (decided[cid], f)
                continue
            st, i, w = t.read_state(f)
            if st == "OK" and marker is not None and i > marker:
                bad.append("%s(条件付き): %s" % (late, f))
            elif st == "UND":
                und.append("%s: %s" % (f, w))
            elif st == "NONE":
                res.add(UND, "M2:" + cid, "condition unknown: %s は未読。条件の成否を記録から決められない" % f)
    if bad:
        res.add(NG, "mode2-reads", "; ".join(bad))
    elif und:
        res.add(UND, "mode2-reads", "読了を確定できない: " + "; ".join(und))
    elif marker is None:
        res.add(UND, "mode2-reads", "必須ファイルは読了済みだが、Agent起動が記録に無く順序を決められない")
    else:
        res.add(PASS, "mode2-reads", "必須ファイルはすべて最初のAgent起動前に読了")
    for s in allsteps:
        if s.get("gate"):
            check_mode2_gate(s, t, res)


def final_answer_text(t):
    return t.texts[-1][1] if t.texts else None


def check_final_mode2(man, t, res):
    ft = final_answer_text(t)
    if ft is None:
        res.add(UND, "final-answer", "assistantのテキストが無い")
        return
    m = re.search(r"読了[:：]([^\n]*)", ft)
    if not m:
        res.add(NG, "final-answer", "最終応答に「読了:」行が無い（SKILL.md 最終応答の規則）")
        return
    names = {n.strip().replace(".md", "") for n in re.split(r"[,、，]", m.group(1)) if n.strip()}
    launched = first_agent(t) is not None  # ゲート（M4）の対象は、手順3に進んだ（Agentを起動した）ときだけ必須
    req = [f for s in man["modes"]["2"]["steps"] if launched or not s.get("gate") for f in s.get("required", [])]
    stems = [os.path.basename(f).replace(".md", "") for f in req if f != "SKILL.md"]
    missing = [s for s in stems if s not in names]
    phantom = [n for n in sorted(names)
               if all(t.read_state("%s/%s.md" % (d, n))[0] == "NONE" for d in DOC_DIRS)]
    if missing or phantom:
        res.add(NG, "final-answer", "「読了:」に不足: %s／未読なのに記載: %s" % (missing or "なし", phantom or "なし"))
    else:
        res.add(PASS, "final-answer", "「読了:」行が必須ファイルを網羅し、Readの記録と一致")


def check_final_mode3(man, t, res):
    ft = final_answer_text(t)
    if ft is None:
        res.add(UND, "final-answer", "assistantのテキストが無い")
        return
    gates = [s["gate"] for s in man["modes"]["3"]["steps"] if s.get("gate") and s["gate"] != "R1"]
    if "ゲート" not in ft and "gate" not in ft.lower():
        res.add(NG, "final-answer", "最終応答にゲート読了の報告が見当たらない")
        return
    need = [g for g in gates if g not in ft and step_marker(g, t)[0] is not None]
    if need:
        res.add(NG, "final-answer", "ゲート読了の報告に不足: " + ", ".join(need))
    else:
        res.add(PASS, "final-answer", "ゲート読了の報告あり（実施したゲートに言及。内容の真偽はRead記録で点検済み）")


FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})[^\n]*\n.*?(?:^[ \t]*\1[ \t]*$|\Z)", re.S | re.M)


def strip_fences(text):
    """コードフェンス内（例示・引用）は章・指摘の判定から除く。"""
    return FENCE.sub("", text)


def split_findings(text):
    m5 = re.search(r"^##\s*5\.[^\n]*\n", text, re.M)
    if m5:
        rest = text[m5.end():]
        end = re.search(r"^##\s*6\.", rest, re.M)
        body = rest[:end.start()] if end else rest
        parts = [p for p in re.split(r"^(?=###\s*5\.\d+)", body, flags=re.M) if re.match(r"###\s*5\.\d+", p)]
        if parts:
            return [(re.match(r"###\s*(5\.\d+)", p).group(1), p) for p in parts]
    head = r"\s*[-*]?\s*\[(?:Critical|High|Medium|Low|Info\w*)\]"
    parts = [p for p in re.split(r"^(?=%s)" % head, text, flags=re.M) if re.match(head, p)]
    out = []
    for n, p in enumerate(parts, 1):
        p = re.split(r"^### 出典別まとめ|^\*\*CVSS整合性確認", p, flags=re.M)[0]
        out.append(("F%d" % n, p))
    return out


def check_report(mode, path, res):
    try:
        with open(lp(path), encoding="utf-8") as fh:
            text = strip_fences(fh.read())
    except OSError as e:
        res.add(NG, "report", "レポートを開けない: %s" % e)
        return
    idx = 2 if mode == 2 else 3
    ch_ng = []
    for ch in CHAPTERS:
        num, name, kind = ch[0], ch[1], ch[idx]
        if re.search(r"^##\s*%d\.\s*\S" % num, text, re.M):
            continue
        if kind == "R":
            ch_ng.append("%d. %s" % (num, name))
        elif kind == "C":
            res.add(UND, "report", "condition unknown: %d. %s は無い（条件付きの章。出典: %s）" % (num, name, ch[4]))
    if ch_ng:
        res.add(NG, "report", "必須の章が無い: " + ", ".join(ch_ng))
    else:
        res.add(PASS, "report", "必須の章はすべて存在")
    fs = split_findings(text)
    if not fs:
        res.add(NG, "report-findings", "指摘（5.N節 または [重大度] 行）が1件も見つからない")
        return
    bad, notes = [], 0
    for fid, body in fs:
        miss = []
        for key, _desc, rx, _src in FINDING_CHECKS:
            m = re.search(rx, body, re.M)
            if not m:
                miss.append(key)
            elif m.lastindex and m.group(1) == "未算出":
                notes += 1
        if miss:
            bad.append("%s: %s" % (fid, ",".join(miss)))
    if bad:
        res.add(NG, "report-findings", "指摘のフィールド欠落 %d/%d件 (%s)" % (len(bad), len(fs), "; ".join(bad[:20])))
    else:
        res.add(PASS, "report-findings", "指摘%d件すべてにCVSS(v3.1/v4.0)・根拠・5d・5eの項目あり%s"
                % (len(fs), "（未算出の注記 %d）" % notes if notes else ""))


def check_evidence(mode, d, res):
    for fn, st2, st3, src in EVIDENCE:
        p = os.path.join(d, fn)
        if os.path.isfile(lp(p)) and os.path.getsize(lp(p)) > 0:
            res.add(PASS, "evidence", fn + " あり（存在のみ。内容の整合は check_cvss_decisions.py の担当）")
        else:
            res.add(st2 if mode == 2 else st3, "evidence", "%s が無いか空（出典: %s）" % (fn, src))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--mode", required=True, type=int, choices=(2, 3))
    ap.add_argument("--transcript", action="append", help="複数回指定可（渡した順に1本の流れとして扱う）")
    ap.add_argument("--skill-root", help="スキルの根（記録上のパス）。省略時は記録のSKILL.mdのReadから、無ければmanifestの場所から決める")
    ap.add_argument("--agents-dir")
    ap.add_argument("--report")
    ap.add_argument("--evidence-dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--brief", action="store_true", help="既定。問題と件数のみ表示")
    ap.add_argument("--verbose", action="store_true", help="PASSも表示")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    with open(lp(a.manifest), encoding="utf-8") as f:
        man = json.load(f)
    res = Result()
    t = None
    if a.transcript:
        t = load_transcripts(a.transcript, man.get("skill", {}).get("name", "web-security-checklist"))
        t.detect_root(a.skill_root, a.manifest)
        if a.mode == 3:
            check_gates_mode3(man, t, res)
            check_final_mode3(man, t, res)
        else:
            check_gates_mode2(man, t, res, bool(a.report), a.evidence_dir)
            check_final_mode2(man, t, res)
    else:
        res.add(UND, "transcript", "--transcript が無いため読了順序と最終応答を点検していない")
    if a.agents_dir:
        n = len(glob.glob(os.path.join(a.agents_dir, "**", "*.jsonl"), recursive=True))
        res.add(PASS if n else UND, "agents-dir", "サブエージェント記録 %d本（件数のみ。役割別の読了順は点検しない）" % n)
    if a.report:
        check_report(a.mode, a.report, res)
    if a.evidence_dir:
        check_evidence(a.mode, a.evidence_dir, res)
    c = res.counts()
    if a.json:
        print(json.dumps({"mode": a.mode, "counts": c, "exit": res.code(),
                          "skipped_lines": t.skipped if t else None,
                          "items": [{"status": s, "area": ar, "message": m} for s, ar, m in res.items]},
                         ensure_ascii=False, indent=2))
    else:
        for s, ar, m in res.items:
            if s != PASS or a.verbose:
                print("%s [%s] %s" % (s, ar, m))
        if t:
            print("transcript: %d行 (読めない・対象外 %d行), Read %d回, Agent起動 %d回" % (t.lines, t.skipped, len(t.reads), len(t.agents)))
        print("RESULT: PASS=%d NG=%d UNDETERMINED=%d exit=%d" % (c[PASS], c[NG], c[UND], res.code()))
    return res.code()


if __name__ == "__main__":
    sys.exit(main())
