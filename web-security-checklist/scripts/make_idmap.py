#!/usr/bin/env python3
"""一時ID対応表（TSV）と --fill-ids 用JSONを、5cの合成結果から機械生成する（標準ライブラリのみ）。
手で振った最終番号のずれで、Writerの入力の連鎖切断の相手が誤った事例（docs/HISTORY.md 43節）の再発防止。
単独項目（群に入らない指摘）も、1件だけの members として入力に含める。

入力:
  --members members.json  {"<作業用ID>": ["<5bの一時ID>", ...]}  最終項目ごとの構成一時ID（5cの合成結果）。
                          値が {"members": [...], ...} の辞書でもよい（合成の中間ファイルをそのまま渡せる）
  --final   final.json    {"<作業用ID>": "5.N"}                  最終番号
出力:
  --out-tsv  idmap.tsv    temp_id<TAB>final_number<TAB>work_id（ヘッダ付き。
                          最終番号の数値順→一時ID順）。check_5b_clique.py（第2引数）と
                          check_cvss_decisions.py --mapping が読む
  --out-json idmap.json   {"<構成一時IDを昇順に+で連結>": "5.N"}。
                          check_cvss_decisions.py --fill-ids --idmap が読む。
                          cvss-decisions.jsonl の tmp も同じ連結形（昇順）で書くこと
  --strip-hyphen          一時IDからハイフン類を除いて出力する（check_5b_clique.py はハイフン入りIDを扱えない。
                          例: R01-01 → R0101。members 側の元の綴りは変えない）
検査（NGなら何も書かず終了コード1）:
  一時IDの重複（同じ項目内・別項目にまたがる。ハイフン除去後の衝突を含む） / members と final の作業用IDの不一致 /
  同じ最終番号が複数の作業用IDに付く / 最終番号の形式（5.N、Nは1から欠番なしの連番） /
  IDの文字種（英数字と . のみ。ハイフンは --strip-hyphen で除去するか、IDを直す） / 空の項目 / 作業用IDの空白・タブ。
  空入力（最終項目が0件） / JSONの同じキーの重複（--members・--final とも）。
  大文字小文字だけが違う一時ID（a1 と A1）はWARN（NGにしない。ID表記の揺れの疑い）。
出力先: 既存のファイルは上書きする。出力先ディレクトリが無い・書けないときはNG（何も残さない）。
  TSVとJSONは、両方を一時ファイル（<出力先>.tmp）に書いてから置き換える。
終了コード 0=OK 1=NG（入力不正を含む）。--self-test で自己検査。Python 3.9以上で動く。"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
import tempfile

ID_RE = re.compile(r"[A-Za-z0-9.]+")
FINAL_RE = re.compile(r"5\.([1-9][0-9]*)")
HYPHENS = "-‐‑–—－ー―"
HEADER = "temp_id\tfinal_number\twork_id"


def _members_of(work, v, errs):
    if isinstance(v, dict) and "members" in v:
        v = v["members"]
    if not isinstance(v, list) or not v:
        errs.append(f"{work}: membersが空、または一時IDの配列でない")
        return None
    if not all(isinstance(x, str) and x.strip() for x in v):
        errs.append(f"{work}: membersに文字列でない・空の一時IDがある")
        return None
    return list(v)


def build(members, final, strip_hyphen=False, warns=None):
    """戻り値 (errs, tsv_text, json_dict)。errs が空でなければ後ろ2つは None。
    warns にリストを渡すと、NGにしない注意（大文字小文字だけが違うID）を追記する"""
    errs: list[str] = []
    if not isinstance(members, dict) or not isinstance(final, dict):
        return ["members・finalはJSONオブジェクト"], None, None
    if not members and not final:
        return ["入力が空（最終項目が0件）。members・finalに項目が要る"], None, None
    mem: dict[str, list[str]] = {}
    for w, v in members.items():
        if not isinstance(w, str) or not w.strip() or re.search(r"\s", w):
            errs.append(f"作業用ID {w!r}: 空・空白・タブ・改行を含む")
            continue
        m = _members_of(w, v, errs)
        if m is not None:
            mem[w] = m
    for k in sorted(set(members) - set(final), key=str):
        errs.append(f"{k}: membersにあるがfinalに無い（最終番号が無い）")
    for k in sorted(set(final) - set(members), key=str):
        errs.append(f"{k}: finalにあるがmembersに無い（構成一時IDが無い）")
    nums: dict[str, str] = {}
    for w, n in final.items():
        if not isinstance(n, str) or not FINAL_RE.fullmatch(n):
            errs.append(f"{w}: 最終番号 {n!r} が 5.N の形でない（Nは1以上の整数）")
            continue
        nums[w] = n
    byn: dict[str, list[str]] = {}
    for w, n in nums.items():
        byn.setdefault(n, []).append(w)
    for n, ws in sorted(byn.items(), key=lambda x: int(x[0][2:])):
        if len(ws) > 1:
            errs.append(f"最終番号 {n} が複数の作業用IDに付いている: {sorted(ws)}")
    if byn:
        got = sorted(int(n[2:]) for n in byn)
        miss = sorted(set(range(1, max(got) + 1)) - set(got))
        if miss:
            errs.append(
                "最終番号が1からの連番でない（欠番: "
                + ", ".join(f"5.{x}" for x in miss)
                + "）"
            )
    seen: dict[str, str] = {}  # 出力する一時ID → 作業用ID
    out: dict[str, list[str]] = {}
    hyph: list[str] = []
    for w, ids in mem.items():
        outs = []
        for t in ids:
            o = t
            if strip_hyphen:
                o = "".join(c for c in t if c not in HYPHENS)
            if not ID_RE.fullmatch(o):
                if any(c in HYPHENS for c in o):
                    hyph.append(t)
                else:
                    errs.append(f"{w}: 一時ID {t!r} が英数字と . のみでない")
                continue
            if o in seen:
                where = "同じ項目内" if seen[o] == w else f"{seen[o]}と重複"
                note = f"（元の綴り {t!r}）" if o != t else ""
                errs.append(f"一時ID {o}{note} が重複: {w}（{where}）")
                continue
            seen[o] = w
            outs.append(o)
        out[w] = outs
    if hyph:
        errs.append(
            f"ハイフンのある一時IDが{len(hyph)}件（例: {', '.join(hyph[:3])}）。"
            "ヒント: check_5b_clique.py はハイフン入りの一時IDを扱えない。"
            "--strip-hyphen で除去する（5bのペア表・群表も除去後のIDで書く）か、IDを英数字に直す"
        )
    if errs:
        return errs, None, None
    if warns is not None:
        low: dict[str, list[str]] = {}
        for t in seen:
            low.setdefault(t.lower(), []).append(t)
        for k, v in sorted(low.items()):
            if len(v) > 1:
                warns.append(
                    f"大文字小文字だけが違う一時ID {sorted(v)}（表記の揺れでないか確認）"
                )
    rows = []
    jdict = {}
    for w, ids in out.items():
        n = nums[w]
        for t in ids:
            rows.append((int(n[2:]), t, n, w))
        jdict["+".join(sorted(ids))] = n
    rows.sort()
    tsv = HEADER + "\n" + "".join(f"{t}\t{n}\t{w}\n" for _, t, n, w in rows)
    jd = dict(sorted(jdict.items(), key=lambda kv: (int(kv[1][2:]), kv[0])))
    return [], tsv, jd


def _pairs(pairs):
    keys = [k for k, _ in pairs]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise ValueError(f"JSONに同じキーが重複している: {dup}")
    return dict(pairs)


def _load(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_pairs)


def run(members_p, final_p, tsv_p, json_p, strip_hyphen=False):
    try:
        members, final = _load(members_p), _load(final_p)
    except (OSError, ValueError) as e:
        print("NG: 入力を読めない:", e)
        return 1
    warns: list[str] = []
    errs, tsv, jd = build(members, final, strip_hyphen, warns)
    for w in warns:
        print("WARN:", w)
    if errs:
        for e in errs:
            print("NG:", e)
        print(f"RESULT: NG ({len(errs)}件。出力ファイルは書いていない)")
        return 1
    outs = [
        (p, text)
        for p, text in (
            (tsv_p, tsv),
            (json_p, json.dumps(jd, ensure_ascii=False, indent=1) + "\n"),
        )
        if p
    ]
    made: list[str] = []
    try:
        for (
            p,
            text,
        ) in outs:  # 先に全部を一時ファイルへ書く（途中で失敗しても出力先は変わらない）
            made.append(p + ".tmp")
            with open(made[-1], "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
        for (p, _), tmp in zip(outs, made):
            os.replace(tmp, p)
    except OSError as e:
        for tmp in made:
            with contextlib.suppress(OSError):
                os.remove(tmp)
        print("NG: 出力を書けない:", e)
        print("RESULT: NG (出力先を確かめる。一時ファイルは消した)")
        return 1
    n_t = len(tsv.splitlines()) - 1
    print(f"RESULT: OK (最終項目{len(jd)}件、一時ID{n_t}件)")
    return 0


def selftest():
    def good():
        return (
            {"F1": ["I3", "U1"], "F2": ["U3"], "S1": ["R10"]},
            {"F1": "5.2", "F2": "5.1", "S1": "5.3"},
        )

    errs, tsv, jd = build(*good())
    assert not errs, errs
    assert tsv == (
        "temp_id\tfinal_number\twork_id\n"
        "U3\t5.1\tF2\nI3\t5.2\tF1\nU1\t5.2\tF1\nR10\t5.3\tS1\n"
    ), repr(tsv)
    assert list(jd.items()) == [("U3", "5.1"), ("I3+U1", "5.2"), ("R10", "5.3")], jd
    # 5.10 は 5.9 の後（数値順）、連結キーは文字列の昇順
    m = {f"W{i}": [f"X{i:02d}"] for i in range(1, 11)}
    m["W3"] = ["B2", "A9", "A10"]
    f = {f"W{i}": f"5.{i}" for i in range(1, 11)}
    errs, tsv, jd = build(m, f)
    assert not errs and [r.split("\t")[1] for r in tsv.splitlines()[1:]][-1] == "5.10"
    assert jd["A10+A9+B2"] == "5.3", jd
    # members の値が辞書（合成の中間ファイル）でもよい
    errs, _, jd = build({"F1": {"members": ["A1", "B1"], "x": 1}}, {"F1": "5.1"})
    assert not errs and jd == {"A1+B1": "5.1"}
    # ハイフン除去
    errs, tsv, jd = build({"F1": ["R01-01", "SCA-01"]}, {"F1": "5.1"}, True)
    assert not errs and jd == {"R0101+SCA01": "5.1"}, (errs, jd)

    def ng(name, m, f, want, strip=False):
        errs, tsv, jd = build(m, f, strip)
        assert errs and tsv is None and jd is None, f"[未検出!] {name}"
        assert any(want in e for e in errs), f"[メッセージ不一致] {name}: {errs}"
        print(f"[NG検出] {name}")

    m, f = good()
    ng("一時IDが別項目で重複", {**m, "F2": ["U3", "I3"]}, f, "重複")
    ng("一時IDが同じ項目内で重複", {**m, "F2": ["U3", "U3"]}, f, "同じ項目内")
    ng("ハイフン除去後の衝突", {"F1": ["R01-01", "R0101"]}, {"F1": "5.1"}, "重複", True)
    ng("finalに無い作業用ID", {**m, "F9": ["Z1"]}, f, "finalに無い")
    ng("membersに無い作業用ID", m, {**f, "F9": "5.4"}, "membersに無い")
    ng("最終番号の重複", m, {**f, "S1": "5.1"}, "複数の作業用ID")
    ng("最終番号の欠番", m, {**f, "S1": "5.5"}, "連番でない")
    ng("5.1から始まらない", {"F1": ["A1"]}, {"F1": "5.2"}, "欠番: 5.1")
    ng("最終番号の形式（5.0）", m, {**f, "S1": "5.0"}, "5.N の形でない")
    ng("最終番号の形式（数値）", m, {**f, "S1": 3}, "5.N の形でない")
    ng("最終番号の形式（前置の空白）", m, {**f, "S1": " 5.3"}, "5.N の形でない")
    ng("ハイフン入りID（除去なし）", {"F1": ["R01-01"]}, {"F1": "5.1"}, "ハイフン")
    ng("ハイフンのヒント", {"F1": ["R01-01"]}, {"F1": "5.1"}, "--strip-hyphen")
    ng("文字種（空白）", {"F1": ["A B"]}, {"F1": "5.1"}, "英数字と . のみでない")
    ng("文字種（_）", {"F1": ["A_B"]}, {"F1": "5.1"}, "英数字と . のみでない")
    ng("空のmembers", {"F1": []}, {"F1": "5.1"}, "空")
    ng("空の一時ID", {"F1": ["A1", " "]}, {"F1": "5.1"}, "空の一時ID")
    ng("作業用IDにタブ", {"F\t1": ["A1"]}, {"F\t1": "5.1"}, "空白・タブ")
    ng("JSONオブジェクトでない", [], {}, "JSONオブジェクト")
    ng("空入力", {}, {}, "入力が空")
    w: list[str] = []
    errs, _, _ = build(
        {"F1": ["a1"], "F2": ["A1"]}, {"F1": "5.1", "F2": "5.2"}, False, w
    )
    assert not errs and w and "大文字小文字" in w[0], (errs, w)
    w = []
    build({"F1": ["a1"], "F2": ["B1"]}, {"F1": "5.1", "F2": "5.2"}, False, w)
    assert not w, w
    print("[WARN検出] 大文字小文字だけが違うID(NGにしない)")
    # ファイル入出力（ファイルが書かれる／NGなら書かれない）
    with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        p = lambda n: os.path.join(d, n)
        m, f = good()
        json.dump(m, open(p("m.json"), "w"))
        json.dump(f, open(p("f.json"), "w"))
        assert run(p("m.json"), p("f.json"), p("o.tsv"), p("o.json")) == 0
        assert open(p("o.tsv"), encoding="utf-8").read() == tsv_of(m, f)
        assert json.load(open(p("o.json"))) == {
            "U3": "5.1",
            "I3+U1": "5.2",
            "R10": "5.3",
        }
        json.dump({**f, "S1": "5.1"}, open(p("f2.json"), "w"))
        assert run(p("m.json"), p("f2.json"), p("n.tsv"), p("n.json")) == 1
        assert not os.path.exists(p("n.tsv")) and not os.path.exists(p("n.json"))
        open(p("bad.json"), "w").write("{bad")
        assert run(p("bad.json"), p("f.json"), p("x.tsv"), None) == 1
        assert run(p("none.json"), p("f.json"), p("x.tsv"), None) == 1
        # JSONの重複キー（--members・--finalとも）
        open(p("dm.json"), "w").write(
            '{"F1": ["A"], "F1": ["B"], "F2": ["C"], "S1": ["D"]}'
        )
        open(p("df.json"), "w").write('{"F1": "5.1", "F1": "5.2"}')
        for mm, ff in (("dm.json", "f.json"), ("m.json", "df.json")):
            assert run(p(mm), p(ff), p("dup.tsv"), None) == 1
        assert not os.path.exists(p("dup.tsv"))
        # 空入力
        open(p("e.json"), "w").write("{}")
        assert run(p("e.json"), p("e.json"), p("e.tsv"), None) == 1
        assert not os.path.exists(p("e.tsv"))
        # 出力先ディレクトリが無い: トレースバックでなくNG。片方だけ残らない
        nodir = os.path.join(d, "nodir")
        assert (
            run(p("m.json"), p("f.json"), p("ok2.tsv"), os.path.join(nodir, "x.json"))
            == 1
        )
        assert not os.path.exists(p("ok2.tsv")) and not os.path.exists(p("ok2.tsv.tmp"))
        # 既存ファイルの上書き（仕様）
        open(p("o.tsv"), "w").write("old")
        assert run(p("m.json"), p("f.json"), p("o.tsv"), None) == 0
        assert open(p("o.tsv"), encoding="utf-8").read() == tsv_of(m, f)
    print("self-test OK (正常系 + NG全ケース検出)")


def tsv_of(m, f):
    return build(m, f)[1]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--members")
    ap.add_argument("--final")
    ap.add_argument("--out-tsv")
    ap.add_argument("--out-json")
    ap.add_argument("--strip-hyphen", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        selftest()
        sys.exit(0)
    if not (a.members and a.final and (a.out_tsv or a.out_json)):
        ap.error("--members・--final と、--out-tsv か --out-json が必要")
    sys.exit(run(a.members, a.final, a.out_tsv, a.out_json, a.strip_hyphen))
