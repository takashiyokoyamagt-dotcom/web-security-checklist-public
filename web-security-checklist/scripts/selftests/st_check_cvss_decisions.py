"""check_cvss_decisions.py の自己検査（--self-test）の本体。本体から分けた（読込を減らすため。P6）。
単独では実行しない。`python3 scripts/check_cvss_decisions.py --self-test` が呼ぶ。
本体のモジュールの名前（関数・定数）をこのモジュールの名前空間に写してから、元のコードをそのまま実行する。"""
from __future__ import annotations

import argparse
import contextlib
import copy
import datetime
import difflib
import io
import itertools
import json
import os
import re
import sys
import tempfile
import unicodedata

_MAIN_FILE = None  # 本体のファイルのパス（_st_entry が入れる）
_MAIN_GLOBALS = None  # 本体の globals()。本体の定数を一時的に変える検査はここを書き換える


def selftest(verbose=False):
    import random
    import subprocess

    V = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

    def alt_vec(m, x):
        return "/".join(
            ["CVSS:3.1"] + [f"{k}:{x if k == m else v}" for k, v in vec(V).items()]
        )

    def mk(tmp, borderline=False):
        m = {k: [v, "a.js:1", "事実", "default"] for k, v in vec(V).items()}
        r = {
            "tmp": tmp,
            "id": "5." + tmp[1:],
            "cat": "x",
            "cwe": ["CWE-89"],
            "type": "SQLi",
            "grp": "g",
            "v3": V,
            "v4": V4,
            "band": "High",
            "m3": m,
            "v4map": "std",
            "dev": [],
            "borderline": [],
            "sbs": False,
            "attn": "none",
            "calc": "std",
            "raw": int(tmp[1:]),
            "by": "arbiter",
            "rev": 1,
            "st": "final",
        }
        if borderline:  # Iを迷い、別案I:H(9.1/Critical)を算出済み
            m["I"][3] = "迷:複文可否が未確認"
            m["I"].append({"alt": "H", "score": "7.5/High", "why": "複文可なら"})
            r["borderline"] = ["I"]
            r["attn"] = "low"
            r["attn_why"] = "複文可否"
        return r

    def rw(t, r):
        return {
            "id": t,
            "raw": {
                "v3": {"vector": r["v3"], "base_score": 7.5, "base_severity": "High"},
                "v4": {"vector": r["v4"], "score": 8.7, "severity": "High"},
            },
        }

    ERR = {
        "vector": V4.replace("/SA:N", ""),
        "error": '無効なCVSS v4.0ベクターです: Missing mandatory metrics "SA"',
    }  # 実calculate_cvss.pyの算出エラー出力の形（vectorとerror）

    def envify(d, r):  # 環境メトリクス反映（CR:H）: 主・別案とも環境スコア付き
        for x in d:
            x[1]["v3"] += "/CR:H"
            x[1]["band"] = "Critical"
        for x in r:
            v = x[1]["raw"]["v3"]
            v["vector"] += "/CR:H"
            v["environmental_score"] = 9.3
            v["environmental_severity"] = "Critical"

    def altraw(t, m="I", vv=None, sc_=(7.5, "High")):
        return {
            "id": t,
            "kind": "alt",
            "of": m,
            "raw": {
                "v3": {
                    "vector": vv or alt_vec(m, "H"),
                    "base_score": sc_[0],
                    "base_severity": sc_[1],
                },
                "v4": {},
            },
        }

    a, b, c = mk("F1"), mk("F2"), mk("F3", True)
    D = [(1, a), (2, b), (3, c)]
    R = [(1, rw("F1", a)), (2, rw("F2", b)), (3, rw("F3", c)), (4, altraw("F3"))]

    def go(d, r, **k):
        if not k.pop(
            "nomemo", False
        ):  # 判定直後の作業メモ行（最終行より後ろに置き、同revでも有効行は最終行）
            d = d + [
                (100 + i, {**x, "st": "memo"})
                for i, (_, x) in enumerate(d)
                if x.get("st") == "final"
            ]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = check(d, r, final=True, adopted=k.pop("adopted", 3), **k)
        return ok, buf.getvalue()

    ok, out = go(D, R)
    assert ok, out

    def okcase(name, f, **k):  # 正常系の亜種: OKでなければ失敗
        d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
        f(d2, r2)
        ok, out = go(d2, r2, **k)
        assert ok, f"{name}: {out}"
        print(f"[OK確認] {name}")

    okcase(
        "v4算出エラー(実出力の形)+v4=未算出",
        lambda d, r: (
            r[0][1]["raw"].update(v4=copy.deepcopy(ERR)),
            d[0][1].update(v4=UNCALC),
        ),
    )

    def _env_ok(d, r):
        envify(d, r)
        d[2][1]["m3"]["I"][4]["score"] = "9.3/Critical"

    okcase("環境メトリクス+正しいalt", _env_ok)
    okcase(
        "証拠 a.js:9,10 とWindowsパス",
        lambda d, r: (
            d[0][1]["m3"]["C"].__setitem__(1, "a.js:9,10"),
            d[0][1]["m3"]["AV"].__setitem__(1, "C:\\src\\a.js:9"),
        ),
    )
    okcase(
        "attn_whyのF5ロードバランサは一時IDでない",
        lambda d, r: d[2][1].update(attn_why="F5ロードバランサ配下か未確認"),
    )

    def _zero(d, r):  # v3.1=0.0（C/I/A全てN）: rawの区分はNone、bandはLow（規則）
        Z = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        d[1][1]["v3"] = Z
        d[1][1]["m3"]["C"][0] = "N"
        d[1][1]["band"] = "Low"
        r[1][1]["raw"]["v3"] = {"vector": Z, "base_score": 0.0, "base_severity": "None"}
        r[1][1]["raw"]["v4"].update(score=0.0, severity="None")

    okcase("v3.1=0.0（raw区分None）はband=Low", _zero)

    def _vd(
        cause, attn="none", v4sev="Medium", **kw
    ):  # F1: v3.1=High / v4.0=v4sev の食い違い
        def f(d, r):
            r[0][1]["raw"]["v4"]["severity"] = v4sev
            if cause:
                d[0][1]["v4diff"] = {"cause": cause, "why": "ATの扱い"}
            if attn != "none":
                d[0][1].update(attn=attn, attn_why="要吟味")
            d[0][1].update(kw)

        return f

    okcase("帯が食い違いv4diff=spec(v4map=std)", _vd("spec"))
    okcase("帯が食い違いv4diff=judgment+attn=high", _vd("judgment", "high"))
    okcase(
        "環境メトリクスで帯が変わってもv4diffは基準値同士の比較(基準値が一致すれば不要)",
        lambda d, r: (envify(d, r), d[2][1]["m3"]["I"][4].update(score="9.3/Critical")),
    )
    okcase(
        "v4のNone(0.0)はLow扱いで一致(v4diff不要)",
        lambda d, r: (_zero(d, r), r[1][1]["raw"]["v4"].update(severity="None")),
    )

    def _reraw(
        d, r
    ):  # F1の主行をraw末尾に再追記（上書き後の再実行）。確定行のrawは最後の行
        r.append((5, copy.deepcopy(r[0][1])))
        d[0][1]["raw"] = 5

    okcase("raw主行の再追記（最後の行が有効）", _reraw)
    case_reraw = (
        "raw主行の再追記なのに確定行のrawが古い行",
        lambda d, r: r.append((5, copy.deepcopy(r[0][1]))),
    )
    UW = "grep:SECRET→定義1件・参照0件"
    okcase(
        "未使用の指摘が同じ帯の末尾",
        lambda d, r: d[2][1].update(unused=True, unused_why=UW),
    )

    def _chg(d, r):  # Arbiterが前revのベクターを上書き（rev0=サブ、確定行=Arbiter）
        prev = {**d[0][1], "st": "memo", "rev": 0, "by": "sub", "v3": V + "/CR:H"}
        d.append((0, prev))

    okcase("上書きでrechk無し（旧形式の再検査はWARNのみ）", _chg)
    okcase(
        "上書きでrechkが全項目",
        lambda d, r: (_chg(d, r), d[0][1].update(rechk=list(RECHK))),
    )
    print("[OK系]")
    print(out.rstrip())
    cases = []

    def case(name, f, **k):
        cases.append((name, f, k))

    def _env_bad(d, r):
        envify(d, r)
        r[3][1]["raw"]["v3"]["vector"] = alt_vec("AV", "L") + "/CR:H"

    case("環境メトリクス+無関係alt", _env_bad)
    case("帯が食い違うのにv4diff無し", _vd(None))
    case(
        "v4diffのcauseが不正",
        lambda d, r: (_vd("spec")(d, r), d[0][1]["v4diff"].update(cause="other")),
    )
    case(
        "v4diffのwhyが空",
        lambda d, r: (_vd("spec")(d, r), d[0][1]["v4diff"].update(why=" ")),
    )
    case(
        "v4diffのwhyにv4メトリクス名が無い",
        lambda d, r: (_vd("spec")(d, r), d[0][1]["v4diff"].update(why="版の違い")),
    )
    case(
        "v4diffのwhyが文字列でない",
        lambda d, r: (_vd("spec")(d, r), d[0][1]["v4diff"].update(why=5)),
    )
    case(
        "v4diffのcauseが大文字/空白付き",
        lambda d, r: (_vd("spec")(d, r), d[0][1]["v4diff"].update(cause="Spec")),
    )
    case(
        "v4diffがリスト",
        lambda d, r: (_vd("spec")(d, r), d[0][1].update(v4diff=["spec"])),
    )
    case("v3.1=High/v4.0=None(Low扱い)でv4diff無し", _vd(None, v4sev="None"))
    case(
        "v4未算出の行にv4diffが残る",
        lambda d, r: (
            r[0][1]["raw"].update(v4=copy.deepcopy(ERR)),
            d[0][1].update(v4=UNCALC, v4diff={"cause": "spec", "why": "AT"}),
        ),
    )
    case(
        "v4diffがdictでない",
        lambda d, r: (_vd("spec")(d, r), d[0][1].update(v4diff="spec")),
    )
    case("judgmentでattn=high以外", _vd("judgment", "low"))
    case("specでv4map非std", _vd("spec", v4map="AT:Pに変更"))
    case(
        "帯が一致するのにv4diffがある",
        lambda d, r: d[1][1].update(v4diff={"cause": "spec", "why": "x"}),
    )
    case(
        "0.0でband=None（規則はLow）",
        lambda d, r: (_zero(d, r), d[1][1].update(band="None")),
    )
    case("0.0でband=Medium", lambda d, r: (_zero(d, r), d[1][1].update(band="Medium")))
    case(
        "Lowのrawなのにband=Medium",
        lambda d, r: (
            r[1][1]["raw"]["v3"].update(base_severity="Low"),
            d[1][1].update(band="Medium"),
        ),
    )
    case(
        "v4エラー(実出力の形)でv4が未算出でない",
        lambda d, r: r[0][1]["raw"].update(v4=copy.deepcopy(ERR)),
    )
    case(
        "v3エラー(実出力の形)でv3が未算出でない",
        lambda d, r: r[0][1]["raw"].update(v3={"vector": V, "error": "x"}),
    )
    case("raw行番号が不一致", lambda d, r: d[0][1].update(raw=999))
    case("行数不足", lambda d, r: d.pop())
    case("必須キー欠落", lambda d, r: d[0][1].pop("attn"))
    case("未確定(band=null)", lambda d, r: d[0][1].update(band=None))
    case("有効行がmemo", lambda d, r: d[0][1].update(st="memo"))
    case(
        "raw不一致(v3)",
        lambda d, r: r[0][1]["raw"]["v3"].update(vector=alt_vec("AV", "L")),
    )
    case("m3とv3の不一致", lambda d, r: d[0][1]["m3"]["C"].__setitem__(0, "L"))
    case("証拠形式不正", lambda d, r: d[0][1]["m3"]["C"].__setitem__(1, "だいたい"))
    case("規則タグ不正", lambda d, r: d[0][1]["m3"]["C"].__setitem__(3, "なんとなく"))
    case(
        "borderlineが配列の配列",
        lambda d, r: d[2][1].update(borderline=[["I", d[2][1]["m3"]["I"][4]]]),
    )
    case("devが配列の配列", lambda d, r: d[2][1].update(dev=[["I"]]))
    case(
        "borderlineに未知のメトリクス名",
        lambda d, r: d[2][1].update(borderline=["I", "ZZ"]),
    )
    case("id重複", lambda d, r: d[1][1].update(id="5.1"))
    case("同tmp同rev重複", lambda d, r: d.append((9, copy.deepcopy(d[0][1]))))
    case("revが文字列", lambda d, r: d[0][1].update(rev="2"))
    case("rawにrawキー無し", lambda d, r: r[0][1].pop("raw"))
    case(
        "v4算出エラー行でv4が未算出でない",
        lambda d, r: r[0][1]["raw"].update(v4={"error": "x"}),
    )
    case("borderlineでaltが無い", lambda d, r: d[2][1]["m3"]["I"].pop())
    case("borderlineに載せず迷タグ", lambda d, r: d[2][1].update(borderline=[]))
    case(
        "sbs=trueだがalt無し/帯不変",
        lambda d, r: d[1][1].update(sbs=True, attn="high", attn_why="x"),
    )
    case(
        "sbs=falseだが別案で帯が変わる",
        lambda d, r: (
            r[3][1]["raw"]["v3"].update(base_severity="Critical")
            or d[2][1]["m3"]["I"][4].update(score="7.5/Critical")
        ),
    )
    case(
        "altが無関係ベクター",
        lambda d, r: r[3][1]["raw"]["v3"].update(vector=alt_vec("AV", "L")),
    )
    case(
        "altのscore数値誤り",
        lambda d, r: d[2][1]["m3"]["I"][4].update(score="9.9/High"),
    )
    case("altのraw行が無い", lambda d, r: r.pop())
    case("自由文に一時ID", lambda d, r: d[2][1].update(attn_why="F1と同じ"))
    case("memo rev>1でrev_why無し", lambda d, r: d[0][1].update(st="memo", rev=2))
    case("作業メモ行が無い", lambda d, r: None, nomemo=True)
    case("tmpの形式が不正", lambda d, r: d[0][1].update(tmp="F 1"))
    case(
        "tmpが対応表の一時IDと不一致",
        lambda d, r: None,
        mapping={"5.1": {"F1", "F9"}, "5.2": {"F2"}, "5.3": {"F3"}},
    )
    case(
        "未使用の指摘より後ろに使用中の指摘（同じ帯）",
        lambda d, r: d[0][1].update(unused=True, unused_why=UW),
    )
    case("unused=trueでunused_why無し", lambda d, r: d[2][1].update(unused=True))
    case(
        "unused_whyに0件が無い",
        lambda d, r: d[2][1].update(unused=True, unused_why="grep:SECRET→定義のみ"),
    )
    case(
        "unusedが真偽値でない", lambda d, r: d[2][1].update(unused="yes", unused_why=UW)
    )
    case("unused_whyだけある", lambda d, r: d[2][1].update(unused_why=UW))
    case(
        "上書きでrechkが一部の項目だけ",
        lambda d, r: (_chg(d, r), d[0][1].update(rechk=["reason", "body"])),
    )
    case(
        "上書きでrechkが配列でない",
        lambda d, r: (_chg(d, r), d[0][1].update(rechk="reason")),
    )
    case("旧形式の記録を--strictで検査", lambda d, r: None, strict=True)
    PN = {k: ["no", "a.js:1", ""] for k in PREM}  # 前提条件の確認: 全て「無」

    # 指摘iのpremを、全て「無」から kv（項目→[値,根拠,説明]）だけ変える
    def _prem(i=0, **kv):
        def f(d, r):
            d[i][1]["prem"] = {**copy.deepcopy(PN), **kv}

        return f

    case("premが辞書でない", lambda d, r: d[0][1].update(prem="no"))
    case(
        "premの項目fが欠落",
        lambda d, r: d[0][1].update(prem={k: v for k, v in PN.items() if k != "f"}),
    )
    case("premに不明な項目g", _prem(g=["no", "a.js:1", ""]))
    case("premの値がyes|no|unk|naでない", _prem(a=["maybe", "a.js:1", "x"]))
    case("premのyesの根拠がfile:lineでない", _prem(a=["yes", "なし", "x"]))
    case("premのunkの説明が空", _prem(b=["unk", "-", " "]))
    case("premの項目が配列でない", _prem(c="no"))
    case("premの(e)をnaにした（全ての指摘に当てはまる）", _prem(e=["na", "-", ""]))
    case("--require-premでpremが無い", lambda d, r: None, require_prem=True)
    case(
        "--require-premで一部の指摘だけprem",
        lambda d, r: (_prem(0)(d, r), _prem(1)(d, r)),
        require_prem=True,
    )
    case(*case_reraw)
    fails = 0
    for name, f, k in cases:
        d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
        f(d2, r2)
        ok, out = go(d2, r2, **k)
        nglines = [l for l in out.splitlines() if l.startswith("NG:")]
        if ok:
            fails += 1
            print(f"[未検出!] {name}")
        else:
            print(
                f"[NG検出] {name} -> {nglines[0][4:].strip() if nglines else out.strip()}"
            )

    # 前提条件の確認（prem）: 形式が正しければOKのまま、矛盾するメトリクスの選択をWARN
    def prem_warn(name, f, want, **k):
        nonlocal fails
        d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
        f(d2, r2)
        ok, out = go(d2, r2, **k)
        ws = [x for x in out.splitlines() if x.startswith("WARN:") and "前提" in x]
        got = all(any(w in x for x in ws) for w in want) and (want or not ws)
        if not ok or not got:
            fails += 1
            got_ = [x for x in out.splitlines() if x.startswith(("NG", "WARN"))]
            print(f"[未検出!] prem {name}: {got_}")
        else:
            print(f"[OK確認] prem {name}")

    def allp(**kv):  # 3指摘ともpremを付ける
        return lambda d, r: [_prem(i, **kv)(d, r) for i in range(3)]

    prem_warn("全て無ならWARNなし", allp(), [])
    prem_warn("全て無で--require-prem", allp(), [], require_prem=True)
    prem_warn("(e)ホスト侵入でAV:N", allp(e=["yes", "a.js:2", "要侵入"]), ["前提(e)"])
    prem_warn("(c)公開済みでC:H", allp(c=["yes", "a.js:3", "直書き"]), ["前提(c)"])
    prem_warn("(d)引き起こせない条件でAC:L", allp(d=["unk", "-", "障害時"]), [])
    prem_warn("(d)yesでAT:N", allp(d=["yes", "a.js:4", "障害時のみ"]), ["前提(d)"])

    def _d_vec(ac):  # v4.0をAT:Pにし、v3.1のACを ac にする（rawと別案も合わせる）
        def f(d, r):
            allp(d=["yes", "a.js:4", "障害時のみ"])(d, r)
            for _, x in d:
                x["v4"] = x["v4"].replace("/AT:N/", "/AT:P/")
                x["v3"] = x["v3"].replace("/AC:L/", f"/AC:{ac}/")
                x["m3"]["AC"][0] = ac
            for _, x in r:
                v = x["raw"]
                if isinstance(v.get("v4"), dict) and "vector" in v["v4"]:
                    v["v4"]["vector"] = v["v4"]["vector"].replace("/AT:N/", "/AT:P/")
                v["v3"]["vector"] = v["v3"]["vector"].replace("/AC:L/", f"/AC:{ac}/")

        return f

    # v3.1とv4.0の双方を見る: v4.0だけAT:Pにしても、v3.1のAC:Lに理由が無ければWARN
    prem_warn("(d)yesでv4.0だけAT:P", _d_vec("L"), ["前提(d)", "v3.1 AC:L"])
    prem_warn("(d)yesでAC:HかつAT:PならWARNなし", _d_vec("H"), [])
    prem_warn("(a)開発依存でAV/AC既定", allp(a=["yes", "a.js:5", "dev"]), ["前提(a)"])
    d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
    _d_vec("L")(d2, r2)
    if "v4.0 AT" in go(d2, r2)[1]:
        fails += 1
        print("[未検出!] prem (d) AT:Pなのにv4.0を挙げた")
    prem_warn("premが一部の指摘にだけある", _prem(0), [])
    d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
    _prem(0)(d2, r2)
    if "premが一部の指摘にだけある" not in go(d2, r2)[1]:
        fails += 1
        print("[未検出!] prem 一部の指摘にだけある")
    # 6節の「前提(x)」の記載（--report時）
    pr = {"prem": {**copy.deepcopy(PN), "b": ["yes", "a.js:1", "lockfile"]}}
    pr["prem"]["f"] = ["unk", "-", "将来"]
    p6 = (("前提(b): lockfileあり。前提（f）: 不明", 0), ("前提(b)のみ", 1))
    for body, want in p6:
        w6: list[str] = []
        prem_report({"F1": (1, {**pr, "id": "5.1"})}, {"1": ("### 6.1", body)}, w6)
        if len(w6) != want or (want and "(f)" not in w6[0]):
            fails += 1
            print(f"[未検出!] prem 6節の記載 {body}: {w6}")
    # 6節の該当行に「前提(x)」があれば反映済み（版ごと。片方だけならもう片方をWARN）
    H6 = "| メトリクス | 値 | 判定根拠 |\n| --- | --- | --- |\n"

    def body6(v3rows, v4rows):
        return "**CVSS v3.1**\n\n" + H6 + v3rows + "\n\n**CVSS v4.0**\n\n" + H6 + v4rows

    ac = "| AC（攻撃条件の複雑さ） | L | {} |\n"
    at = "| AT（攻撃条件） | N | {} |\n"
    av = "| AV（攻撃元区分） | N | {} |\n"
    cc, vc = "| C（機密性） | H | {} |\n", "| VC（機密性） | H | {} |\n"
    for name, x, body, want, nothave in (
        (
            "dの片方",
            "d",
            body6(ac.format("前提(d): 障害時のみ"), at.format("x")),
            1,
            "v3.1 AC",
        ),
        (
            "dの双方",
            "d",
            body6(ac.format("前提(d): x"), at.format("前提（d）: x")),
            0,
            "",
        ),
        (
            "aの反映",
            "a",
            body6(av.format("前提(a): x"), at.format("前提(a): x")),
            0,
            "",
        ),
        ("cの片方", "c", body6(cc.format("前提(c): x"), vc.format("x")), 1, "v3.1 C:H"),
        ("eの記載なし", "e", body6(av.format("x"), av.format("x")), 1, "-"),
    ):
        row = {**copy.deepcopy(D[0][1]), "id": "5.1"}
        row["prem"] = {**copy.deepcopy(PN), x: ["yes", "a.js:1", "前提"]}
        w6 = []
        prem_report({"F1": (1, row)}, {"1": ("### 6.1", body)}, w6)
        if len(w6) != want or (
            want and (f"前提({x})" not in w6[0] or nothave in w6[0])
        ):
            fails += 1
            print(f"[未検出!] prem 6節の該当行 {name}: {w6}")
    print("[OK確認] prem 6節の該当行の「前提(x)」（版ごと）")
    if not row_problems({**D[0][1], "prem": {"a": "x"}}):
        fails += 1
        print("[未検出!] prem --appendの形式検査")
    print("[OK確認] prem 6節の記載・--appendの形式検査")

    # NGメッセージのヒント（手順書に書いていない運用上の落とし穴。HISTORY 43節・44節）
    def hint(name, f, want, **k):
        nonlocal fails
        d2, r2 = copy.deepcopy(D), copy.deepcopy(R)
        f(d2, r2)
        ok, out = go(d2, r2, **k)
        nglines = [l for l in out.splitlines() if l.startswith("NG:")]
        if ok or "内部エラー" in out or not any(want in l for l in nglines):
            fails += 1
            print(f"[ヒント未出力!] {name}: {out.strip()[:300]}")
        else:
            print(f"[ヒント出力] {name}")

    def _wk(d, r):  # 作業用ID（F12等）をtmpに書いた
        d[0][1].update(tmp="F12")
        r[0][1].update(id="F12")

    hint(
        "tmp不一致のヒント（作業用IDではない）",
        lambda d, r: None,
        "群の作業用ID（F12等）ではない",
        mapping={"5.1": {"F1", "F9"}, "5.2": {"F2"}, "5.3": {"F3"}},
    )
    hint(
        "tmp形式不正のヒント",
        lambda d, r: d[0][1].update(tmp="F 1"),
        "作業用ID（F12等）ではない",
    )
    hint(
        "tmp形式不正にハイフン除去のヒント",
        lambda d, r: d[0][1].update(tmp="R01-01+R05-02"),
        "ハイフンを除いた形",
    )
    hint(
        "規則タグ不正に許される接頭辞の一覧",
        lambda d, r: d[0][1]["m3"]["C"].__setitem__(3, "例:なんとなく"),
        "許される接頭辞: default / 表:<行名> / 原則:<名> / 迷: / 例外: / 逸脱:",
    )
    hint(
        "規則タグ不正に「例:」は不可と明記",
        lambda d, r: d[0][1]["m3"]["C"].__setitem__(3, "例:なんとなく"),
        "「例:」は不可",
    )

    # [["I",{alt…}]]（配列の配列）。正しい形は ["I"] ＋ m3.I の5番目の辞書
    def _bl_pairs(d, r):
        d[2][1]["borderline"] = [["I", d[2][1]["m3"]["I"][4]]]

    hint(
        "borderlineが配列の配列（クラッシュせず原因を示す）",
        _bl_pairs,
        "borderlineはメトリクス名の文字列の配列",
    )
    hint(
        "borderlineに辞書の要素",
        lambda d, r: d[2][1].update(borderline=[{"I": 1}]),
        "要素が文字列（メトリクス名）でない",
    )
    hint(
        "devが配列の配列",
        lambda d, r: d[2][1].update(dev=[["I"]]),
        "dev",
    )
    hint(
        "borderlineに未知のメトリクス名",
        lambda d, r: d[2][1].update(borderline=["I", "ZZ"]),
        "未知のメトリクス名",
    )
    hint(
        "borderlineの5要素目が無いときもヒント",
        lambda d, r: d[2][1]["m3"]["I"].pop(),
        "別案は m3.<メトリクス> の5番目の要素に辞書",
    )
    hint(
        "idmapの連結順違いのヒント",
        lambda d, r: (
            d[0][1].update(tmp="F1+A1"),
            r[0][1].update(id="F1+A1"),
            d[0][1].update(),
        ),
        "昇順に連結",
        idmap={"A1+F1": "5.1", "F2": "5.2", "F3": "5.3"},
    )
    hint(
        "idmapにtmpが無いときのヒント（作業用ID）",
        _wk,
        "群の作業用ID（F12等）ではない",
        idmap={"F1": "5.1"},
    )
    assert idmap_hint("F1", {"F1": "5.1"}) == ""
    assert "昇順" in idmap_hint("B1+A1", {"A1+B1": "5.1"})
    # --append のrow_problems: borderlineが配列の配列の行は追記前に拒否される
    assert any(
        "borderline" in x
        for x in row_problems({"st": "memo", "borderline": [["I", {}]]})
    ), "row_problemsがborderlineの配列の配列を見逃した"
    assert not [
        x
        for x in row_problems({"st": "memo", "borderline": ["I"], "dev": []})
        if "要素" in x
    ]
    # --idmap は { で始まればJSON文字列、でなければファイルパス（File name too long の回避）
    with tempfile.TemporaryDirectory() as td_:
        pp = lambda n, t_: (
            open(os.path.join(td_, n), "w", encoding="utf-8").write(t_),
            os.path.join(td_, n),
        )[1]
        dpp = pp(
            "d.jsonl", "".join(json.dumps(x[1], ensure_ascii=False) + "\n" for x in D)
        )
        rpp = pp(
            "r.jsonl", "".join(json.dumps(x[1], ensure_ascii=False) + "\n" for x in R)
        )
        ipp = pp("i.json", '{"F1":"5.1"}')
        me = os.path.abspath(_MAIN_FILE)
        for nm, arg in (
            ("JSON文字列", '{"F1":"5.1","F2":"5.2","F3":"5.3"}'),
            ("ファイル", ipp),
        ):
            pr = subprocess.run(
                [
                    sys.executable,
                    me,
                    "--fill-ids",
                    "--decisions",
                    dpp,
                    "--raw",
                    rpp,
                    "--idmap",
                    arg,
                ],
                capture_output=True,
                text=True,
            )
            fine = (
                pr.returncode == 0 and "File name too long" not in pr.stdout + pr.stderr
            )
            if not fine:
                fails += 1
            print(
                ("[OK] " if fine else "[失敗!] ") + f"--idmapに{nm}: rc={pr.returncode}"
            )
        pr = subprocess.run(
            [
                sys.executable,
                me,
                "--fill-ids",
                "--decisions",
                dpp,
                "--raw",
                rpp,
                "--idmap",
                "{bad",
            ],
            capture_output=True,
            text=True,
        )
        if pr.returncode == 0 or "RESULT: NG" not in pr.stdout:
            fails += 1
            print("[失敗!] --idmapの不正なJSON文字列がNGにならない")
    # seq/ts・時刻順・集中・rechk（--strict）の検査。memo(rev1)→raw→確定行(rev2)の順に時刻を付ける
    T0 = datetime.datetime(2026, 10, 8, 10, 0, tzinfo=datetime.timezone.utc)
    iso = lambda sec: (T0 + datetime.timedelta(seconds=sec)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    def fixture(nf):
        xs = [mk(f"F{i}") for i in range(1, nf + 1)]
        return [(i, x) for i, x in enumerate(xs, 1)], [
            (i, rw(x["tmp"], x)) for i, x in enumerate(xs, 1)
        ]

    def stampedgo(nf=3, step=60, rawat=None, mut=None, **k):
        d, r = fixture(nf)
        memo = [(100 + i, {**x, "st": "memo", "rev": 1}) for i, (_, x) in enumerate(d)]
        fin = [(n, {**x, "rev": 2}) for n, x in d]
        dd, rr = memo + fin, r
        at = step * nf if rawat is None else rawat
        for i, (_, x) in enumerate(dd):
            x.update(seq=i + 1, ts=iso(step * i + (step * nf if i >= nf else 0)))
        for i, (_, x) in enumerate(rr):
            x.update(seq=i + 1, ts=iso(at + step * i))
        if mut:
            mut(dd, rr)
        return go(dd, rr, nomemo=True, adopted=nf, **k)

    ok, out = stampedgo(strict=True)
    assert ok and "seq/ts" not in out and "集中" not in out, f"時刻付き: {out}"
    ok, out = stampedgo(nf=12, step=0, rawat=0)
    assert ok and "集中" in out and "同時刻" in out, f"集中はWARNのみ: {out}"
    chg = lambda d, r: d[0][1].update(by="sub", v3=V + "/CR:H")
    ok, out = stampedgo(mut=chg)
    assert ok and "rechk" in out, f"rechk無しはWARNのみ: {out}"
    full = lambda d, r: (chg(d, r), d[3][1].update(rechk=list(RECHK)))
    ok, out = stampedgo(mut=full, strict=True)
    assert ok, f"rechk全項目: {out}"
    assert "履歴行" not in stampedgo(strict=True)[1], "メモrev1→確定rev2は正常"
    def rsn(d, r):  # JUDGEの出力をそのまま--appendした記録（memo→reasons）
        d.insert(1, (150, {"tmp": d[0][1]["tmp"], "r3": {}, "r4": {}, "ts": d[0][1]["ts"]}))
        for i, (_, x) in enumerate(d, 1):
            x["seq"] = i

    ok, out = stampedgo(mut=rsn, strict=True)
    assert ok and "rechk" not in out, f"メモ行の後のreasons行（rev無し）は上書きでない: {out}"

    def hist(d, r):  # 先頭の確定行をメモ行と同じrev1で先に追記した履歴が残る
        d.insert(3, (99, {**d[3][1], "rev": 1}))
        for i, (_, x) in enumerate(d, 1):
            x["seq"] = i

    ok, out = stampedgo(mut=hist, strict=True)
    assert ok and "履歴行あり（1行: L99）" in out, f"履歴行はWARNのみ: {out}"

    def memo_after(d, r):  # 確定行rev2の後に同じrev2のメモ行が残る（無視された行）
        d.append((98, {**d[3][1], "st": "memo", "rev_why": "x", "seq": 7}))
        d[-1][1]["ts"] = iso(900)

    ok, out = stampedgo(mut=memo_after, strict=True)
    assert ok and "先行行以下の履歴行あり（1行: L98）" in out, f"WARNのみ: {out}"

    def whys(*ws, vc="H"):  # F1・F2の帯を食い違わせv4diff.whyを書く。F2のv4はVC:vc
        def f(d, r):
            for i, w in enumerate(ws):
                r[i][1]["raw"]["v4"]["severity"] = "Medium"
                d[3 + i][1]["v4diff"] = {"cause": "spec", "why": w}
            v4 = V4.replace("VC:H", f"VC:{vc}")
            for x in (d[1][1], d[4][1], r[1][1]["raw"]["v4"]):
                x.update({"v4" if "tmp" in x else "vector": v4})

        return f

    W1 = "ATの扱い"
    ok, out = stampedgo(mut=whys(W1, W1), strict=True)
    assert ok and "v4diff.why" not in out, f"同じベクターの同文はWARNなし: {out}"
    ok, out = stampedgo(mut=whys(W1, W1, vc="L"), strict=True)
    assert ok and "v4diff.whyの流用（ベクター" in out, f"WARNのみ: {out}"
    ok, out = stampedgo(mut=whys(W1, "ATとVCの扱い", vc="L"), strict=True)
    assert ok and "v4diff.why" not in out, f"別の文ならWARNなし: {out}"

    def wr(*rows):  # why_reuse単体: (id, v3, st)の行。whyは全て同じ
        w = []
        e = {
            f"F{i}": (i, {"id": x, "v3": v3, "v4": V4, "st": st, "v4diff": {"why": W1}})
            for i, (x, v3, st) in enumerate(rows)
        }
        why_reuse(e, w)
        return w

    V2 = V.replace("C:H", "C:L")
    assert wr(("5.1", V, "final"), ("5.2", V2, "final")), "ベクター違いの同文"
    assert not wr(("5.1", V, "final"), ("5.2", V + "/CR:H", "final")), "環境のみ"
    assert not wr(("5.1", V, "final"), ("5.2", V2, "memo")), "確定行以外は対象外"
    print("[OK確認] 時刻付き・集中はWARNのみ・rechk・rev順の履歴行・v4diff.whyの流用")

    def late(d, r):  # 先頭のメモ行を最後に（時刻も最後に）追記し直す
        d.append(d.pop(0))
        d[-1][1].update(seq=7, ts=iso(900))

    stamp_cases = [
        ("seqが増加しない", dict(mut=lambda d, r: d[3][1].update(seq=1))),
        ("tsが戻る", dict(mut=lambda d, r: d[4][1].update(ts=iso(1)))),
        ("tsが解釈できない", dict(mut=lambda d, r: d[0][1].update(ts="昨日"))),
        ("一部の行だけseq無し", dict(mut=lambda d, r: d[2][1].pop("seq"))),
        ("seqに欠番", dict(mut=lambda d, r: d[5][1].update(seq=9))),
        ("tsが日付のみ", dict(mut=lambda d, r: d[0][1].update(ts="2026-10-08"))),
        ("raw出力がメモ行より前", dict(rawat=-1000)),
        ("確定行がraw出力より前", dict(rawat=5000)),
        ("メモ行が確定行より後に追記", dict(mut=late)),
        ("確定行のrevがメモ行と同じ", dict(mut=lambda d, r: d[3][1].update(rev=1))),
        ("--strictで上書きにrechk無し", dict(mut=chg, strict=True)),
        (
            "--strictで上書きのrechkが一部",
            dict(
                mut=lambda d, r: (chg(d, r), d[3][1].update(rechk=["body"])),
                strict=True,
            ),
        ),
    ]
    for name, kw in stamp_cases:
        ok, out = stampedgo(**kw)
        nglines = [x for x in out.splitlines() if x.startswith("NG:")]
        if ok:
            fails += 1
            print(f"[未検出!] {name}")
        else:
            print(f"[NG検出] {name} -> {nglines[0][4:].strip()}")

    def report_cases(td, p, dp, rp, bd):
        """5〜6節のスコア・値、未使用の表示、判定根拠の重複、--appendの検査"""
        rng = random.Random(7)
        rtxt = lambda: "".join(
            rng.choice("あいうえおかきくけこさしすせそたちつてと") for _ in range(50)
        )
        fixed = {(v_, m): rtxt() for v_ in "34" for m in {**vec(V), **vec(V4)}}
        head = ["| メトリクス | 値 | 判定根拠 |", "| --- | --- | --- |"]

        def mkrep(n=3, why=None, unused=(), mut=None):
            why = why or (lambda i, ver, m: rtxt())

            def rows(i, ver, vc):
                return [
                    f"| {m}（x） | {v} | {why(i, ver, m)} |" for m, v in vec(vc).items()
                ]

            out = ["## 4. 指摘サマリー", ""]
            for i in range(1, n + 1):
                u = "（未使用・実質問題なし）" if i in unused else ""
                out.append(f"| [5.{i}](#x) | High | 7.5 | 8.7 | a.js | CONFIRMED{u} |")
            out += ["", "## 5. 指摘詳細", ""]
            for i in range(1, n + 1):
                out += [
                    f"### 5.{i} [High] x",
                    "",
                    f"| CVSS v3.1 | 7.5（High）。ベクター文字列: `{V}` |",
                    f"| CVSS v4.0 | 8.7（High）。ベクター文字列: `{V4}` |",
                    "",
                ]
                if i in unused:
                    out += ["**実害の有無（未使用の欠陥）**", "", UNUSED_MSG + "。", ""]
            out += ["## 6. リスク分析", ""]
            for i in range(1, n + 1):
                out += [f"### 6.{i} [High] x", "", "**CVSS v3.1**", ""] + head
                out += rows(i, "3", V)
                out += [
                    "",
                    f"- ベクター文字列: `{V}`",
                    "- ベーススコア: 7.5（High）",
                    "",
                ]
                out += ["**CVSS v4.0**", ""] + head
                out += rows(i, "4", V4)
                out += ["", f"- ベクター文字列: `{V4}`", "- スコア: 8.7（High）", ""]
            t = "\n".join(out + ["## 7. 後続", ""])
            return mut(t) if mut else t

        def verdict(text, d=dp, r=rp, n=3, strict=False):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok = run(d, r, p("rep3.md", text), n, None, True, None, strict)
            return ok, buf.getvalue()

        dump = lambda xs: "".join(json.dumps(x, ensure_ascii=False) + "\n" for x in xs)
        memo = lambda ds: [{**x, "st": "memo"} for _, x in ds]
        d12, r12 = fixture(12)
        dp12 = p("d12.jsonl", dump([x for _, x in d12] + memo(d12)))
        rp12 = p("r12.jsonl", dump([x for _, x in r12]))
        du = copy.deepcopy(D)
        du[2][1].update(unused=True, unused_why=UW)
        dpu = p("du.jsonl", dump([x for _, x in du] + memo(du)))
        reuse = lambda i, ver, m: fixed[ver, m] if m == "AV" and i < 6 else rtxt()

        def tagged(i, ver, m):
            if i == 1 and m == "AC":
                return "基準からの逸脱: " + fixed["3", "AV"]
            return (
                fixed["3", "AV"] + "（根拠: a.js:1）"
                if i == 1 and m == "PR"
                else rtxt()
            )

        def same(i, ver, m):
            return fixed["3", "AV"] if i == 1 and m in ("AC", "PR") else rtxt()

        const = lambda i, ver, m: fixed[ver, m]
        sw = lambda a_, b_: lambda t: t.replace(a_, b_, 1)
        ok, o = verdict(mkrep())
        assert ok, f"5〜6節が記録と一致する正常系: {o}"
        ok, o = verdict(mkrep(unused=(3,)), dpu)
        assert ok, f"未使用の記述が揃った正常系: {o}"
        ok, o = verdict(mkrep(12, reuse), dp12, rp12, 12)
        assert ok and "4指摘以上" in o, f"5指摘の流用はWARNのみ: {o}"
        ok, o = verdict(mkrep(unused=(3,)))
        assert ok and "未使用と述べる" in o, f"unused無しはWARNのみ: {o}"
        ok, o = verdict(mkrep(unused=(3,)), strict=True)
        assert not ok and "NG: F3: 5.3は未使用と述べる" in o, f"--strictではNG: {o}"
        mention = "### 5.2 [High] x\n\n5.3の指摘は" + UNUSED_MSG + "だが\n"
        other = sw("### 5.2 [High] x\n", mention)
        ok, o = verdict(mkrep(unused=(3,), mut=other), dpu)
        assert ok and "未使用と述べる" not in o, f"他指摘への言及は対象外: {o}"

        def twin(i, ver, m):
            return fixed[ver, "C"] if m in ("C", "I", "VC", "VI") else rtxt()

        ok, o = verdict(mkrep(why=twin))
        assert ok and "似た判定根拠" in o, f"C/Iの対の重複はWARNのみ: {o}"
        boldbody = sw(UNUSED_MSG + "。", "**" + UNUSED_MSG + "。**")
        ok, o = verdict(mkrep(unused=(3,), mut=boldbody), dpu)
        assert ok, f"本文全体が太字でも本文として読む: {o}"
        lack = sw("### 5.3 [High] x", "### 5.3 [High] 認証機構の欠如")
        ok, o = verdict(mkrep(unused=(3,), mut=lack), dpu)
        assert ok and "判定質問③" in o, f"未使用で見出しが欠如を述べるのはWARNのみ: {o}"
        S = "v4.0のACは防御機構の回避難度だけを表す。"  # 正規化後22字
        HIT, NO = "判定根拠の文単位の流用（同じ文が3指摘以上", "文単位の流用"

        def sdup(cells, strict=False, head=None, n=3):  # セルの末尾（headは先頭）に文
            def why(i, ver, m):
                h = (head or {}).get((i, ver, m), "")
                return h + rtxt() + "。" + cells.get((i, ver, m), "")

            t = mkrep(n, why)
            if strict:  # seq/ts付きの記録で--strict
                return stampedgo(strict=True, report=p("sd.md", t))
            return verdict(t) if n == 3 else verdict(t, dp12, rp12, 12)

        three = {(i, "4", "AC"): S for i in (1, 2, 3)}
        for strict in (False, True):
            ok, o = sdup(three, strict)
            assert ok and HIT in o and "6.1(v4.0 AC)" in o, o
        ok, o = sdup({(i, "4", "AC"): S for i in (1, 2)})
        assert ok and NO not in o, f"2指摘ならWARNなし: {o}"
        s19, s20 = (
            "このACは防御機構の回避難度だけを表す。",
            "そこでACは防御機構の回避難度だけを表す。",
        )
        assert (len(sent_key(s19)), len(sent_key(s20))) == (19, 20)
        ok, o = sdup({(i, "4", "AC"): s19 for i in (1, 2, 3)})
        assert ok and NO not in o, f"20字未満は数えない: {o}"
        ok, o = sdup({(i, "4", "AC"): s20 for i in (1, 2, 3)})
        assert ok and HIT in o, f"20字は数える: {o}"
        paren = "回避すべき機構（CSRF。署名）が無いためL。"  # 括弧内の「。」で切ると20字未満
        ok, o = sdup({(i, "4", "AC"): paren for i in (1, 2, 3)})
        assert ok and HIT in o, f"括弧内の「。」で切らない: {o}"
        tagged3 = {(2, "4", "AC"): S[:-1] + "（根拠: a.js:1）。", (3, "4", "AC"): S}
        ok, o = sdup(tagged3, head={(1, "4", "AC"): "迷: " + S})
        assert ok and HIT in o, f"規則タグ・（根拠: …）を除いて比べる: {o}"
        kana = {
            (1, "4", "AC"): S[:-1] + "．そのためL。",
            (2, "4", "AC"): S[:-1] + "．だからL。",
        }
        ok, o = sdup({**kana, (3, "4", "AC"): S})
        assert ok and HIT in o, f"「．」の後がかなでも切る: {o}"
        own = {(1, "3", "AC"): S, (1, "4", "AC"): S, (2, "4", "AC"): S}
        ok, o = sdup(own)
        assert ok and NO not in o, f"同じ指摘の別版は1指摘: {o}"
        wide = {
            (1, "4", "AC"): "ｖ４．０のＡＣは防御機構の回避難度だけを表す．",
            (2, "4", "AC"): "v4.0の AC は防御機構の回避難度だけを表す",
            (3, "3", "AC"): S,
        }
        ok, o = sdup(wide)
        assert ok and HIT in o, f"全角半角・空白・句点を揃える: {o}"
        ms = list(vec(V)) + list(vec(V4))  # 12指摘の全19欄に5通りの文を流用
        tpl = "番目の定型文としてこの指摘にも同じように書いた。"
        many = {
            (i, v_, m): f"{ms.index(m) % 5}{tpl}"
            for i in range(1, 13)
            for v_ in "34"
            for m in ms
        }
        ok, o = sdup(many, n=12)
        line = next((x for x in o.splitlines() if NO in x), "")
        assert ok and "等)" in line and "ほか2文" in line and len(line) < 500, line
        ok, o = sdup({k: S for k in many}, n=12)  # 1文を12指摘の全19欄に流用
        line = next((x for x in o.splitlines() if NO in x), "")
        assert ok and "ほか8指摘" in line and len(line) < 200, line
        print("[OK確認] 5〜6節の一致・未使用の表示・判定根拠の流用(WARN)・文単位の流用")
        T7 = "## 7. 後続\n"
        NRC = "Arbiterの実機確認（記録#1）で停止しなかった。部分的な影響だけのためN。"

        def nrrep(
            s7, s12, cell=(1, "3", "A"), txt=NRC, far=False, h7="## 7. 要確認事項"
        ):
            def why(i, ver, m):
                far_ = {1: "攻撃は起きなかった。", 2: "成立しなかったためL。"}
                far_[3] = "可用性への影響は観測されていない。"  # 弱い語（A:N）
                if far and (i, ver, m) in (
                    (1, "3", "AV"),
                    (2, "3", "AC"),
                    (3, "3", "A"),
                ):
                    return far_[i] + rtxt()
                return txt if (i, ver, m) == cell and not far else rtxt()

            sec = h7 + "\n\n" + s7 + "\n\n## 12. 留意事項\n\n" + s12 + "\n"
            return verdict(mkrep(why=why, mut=sw(T7, sec)))

        def a5(o):  # A-5のNG/WARN行
            return [x for x in o.splitlines() if x[:3] in ("NG:", "WAR") and "A-5" in x]

        H7 = "**実機で再現できなかった主張**\n\n"
        P7 = (
            H7
            + "- 5.1のdicerによる停止は再現できなかった。陽性対照は取ってある（記録#1）。"
        )
        N7 = (
            H7
            + "- 5.1のdicerによる停止は再現できなかった。陽性対照（停止する版）は無い。"
        )
        U12 = "**未検証の事項**: 実ブラウザでの実行は未検証である。"
        NG12 = "**未検証の事項**: dicerの停止は再現できなかったが、陽性対照は無く、未検証である。"
        ok, o = nrrep(P7, U12)
        assert ok and "A-5）: 1欄 6.1(v3.1 A)" in o and not a5(o), f"A-5の整合: {o}"
        ok, o = nrrep(
            "- 5.1のdicerの停止は再現できなかった。陽性対照は取ってある。", U12
        )
        assert ok and not a5(o), f"見出しが無ければ7節全体で言及を探す: {o}"
        ok, o = nrrep(P7, NG12)
        assert ok and "食い違う（A-5。1組。dicer" in o, f"7節と12節の陽性対照: {o}"
        L12 = "**未検証の事項**: lodashの汚染は、陽性対照は無く、未検証である。"
        ok, o = nrrep(P7, L12)
        assert ok and not a5(o), f"別パッケージは食い違いにしない: {o}"
        ok, o = nrrep(N7, "特記事項なし。")
        assert ok and "12節に「未検証」の記載が無い" in o, f"12節の未検証: {o}"
        GR = "6節で引き下げの根拠に使われている（A-5。人間が確認）: "
        ok, o = nrrep(N7, NG12)
        assert ok and len(a5(o)) == 1 and GR + "6.1(v3.1 A)" in o, f"自己申告: {o}"
        C7 = H7 + "- 5.1のdicerの停止は再現できず、条件2を満たさないため未検証とする。"
        ok, o = nrrep(C7, U12)
        assert ok and GR + "6.1(v3.1 A)" in o, f"条件2の自己申告: {o}"
        ok, o = nrrep(sw("条件2を満たさない", "3条件を満たさない")(C7), U12)
        assert ok and GR in o, f"3条件を満たさない: {o}"
        ok, o = nrrep(
            sw("条件2を満たさないため未検証とする", "条件1〜3をすべて満たしている")(C7),
            U12,
        )
        assert ok and GR not in o, f"条件を満たしている（肯定）は対象外: {o}"
        ok, o = nrrep(N7, NG12, cell=(1, "3", "AV"))
        assert ok and GR not in o, f"引き下げ側でない欄は対象外: {o}"
        ok, o = nrrep(H7 + "- x\n\n**dicer（5.1）**\n\n" + P7[len(H7) :], U12)
        assert ok and not a5(o), f"項の中の太字の小見出しで切らない: {o}"
        D12 = "**未検証の事項**: dicerのビルドは未検証。lodashの汚染は陽性対照は無く、未検証。"
        ok, o = nrrep(P7, D12)
        assert ok and not a5(o), f"12節は段落の先頭文の語を引き継がない: {o}"
        PoC = {
            "1": (
                "",
                "| I（x） | N | 汚染されなかった。 |\n| AV（x） | N | 再現しない。 |",
            )
        }
        PoC["2"] = (
            "",
            "| AC（x） | L | PoCが再現しない。 |\n| A（x） | L | 書き換えなかった。 |",
        )
        got = nonrepro_cells(PoC)
        assert got == [
            ("1", "v3.1 I", True),
            ("2", "v3.1 AC", False),
            ("2", "v3.1 A", True),
        ], got  # 「再現しない」はPoC等の語が無いAVでは数えない
        ok, o = nrrep("なし。", "なし。", far=True)
        assert ok and "A-5" not in o, f"引き下げと無関係の語・弱い語: {o}"
        pol = [
            pc_polarity(x, 4)
            for x in (
                "陽性対照（停止する版）は無い",
                "陽性対照を実行していない",
                "陽性対照を取っていない",
                "陽性対照を取ったが影響はない",
                "陽性対照として",
                "陽性対照の取り方",
                "陽性対照は取っておらず",
                "陽性対照は実行しておらず",
                "陽性対照は取得していない",
                "陽性対照はありません",
                "陽性対照は確認済みではない",
                "陽性対照は取れた",
                "陽性対照を用意した",
                "陽性対照を取った",
            )
        ]
        assert (
            pol == [False, False, False, True, None, None] + [False] * 5 + [True] * 3
        ), pol
        assert topics("[5.20](#520-low-設定apiのbody) `qs`") == {"5.20", "qs"}
        assert refs("5.32はMedium（5.3）。qs 6.5.1、6.2/High") == {"5.32"}
        assert refs("5.16/5.25、スコア5.3、CVSS 6.1、v5.2") == {"5.16", "5.25"}
        # 2乗にならない（閉じない太字行・多数の番号）
        t0 = datetime.datetime.now(datetime.timezone.utc)
        refs("5.1 " * 50000), nr_scope("**" + "再現できなかった" * 30000 + "\n- x")
        assert (
            datetime.datetime.now(datetime.timezone.utc) - t0
        ).total_seconds() < 3, "refs/nr_scopeが遅い"
        drop_pc = sw("陽性対照は取ってある", "")
        nrres = [
            ("6節の非再現の根拠に7節の言及が無い", nrrep(sw("5.1の", "")(P7), U12)[0]),
            (
                "7節の言及が「再現できなかった主張」の項の外だけ",
                nrrep(
                    "**判定に迷い**\n\n- 5.1\n\n" + drop_pc(sw("5.1の", "")(P7)), U12
                )[0],
            ),
            (
                "項の後の既知の見出し（判定に迷い）の下だけに言及",
                nrrep(H7 + "- x\n\n**判定に迷い**\n\n- 5.1", U12)[0],
            ),
            (
                "6節の「再現しない」（PoC）に7節の言及が無い",
                nrrep("なし。", U12, txt="勧告のPoCが再現しないためN。")[0],
            ),
        ]
        ok, o = nrrep(P7, U12, h7="## ７． 要確認事項")
        assert not ok and "7節の見出し（`## 7. `）が見つからない" in o, o
        nrres.append(("7節の見出しの形が違う（## ７．）", ok))
        print(
            "[OK確認] A-5の6・7・12節の整合（言及・陽性対照の食い違い・未検証・自己申告）"
        )
        PL, TD = "わかりやすい解説（専門知識を前提としない説明）", "技術的詳細解説"
        INT, ALT = "元の処理の意図と、修正による挙動の変化", "設計方針に従えない場合の代替案"
        RES = "修正後に残るリスクと別経路"
        DE = "誰でも削除できる。全件を消せる。回数の制限も無い。"
        MS = "誰でも削除できます。全件を消せます。回数の制限もありません。"

        def st(fs):  # {見出し: 本文} の1指摘に対する文体のWARN
            w = []
            body = "".join(f"**{h}**\n\n{x}\n\n" for h, x in fs.items())
            style_check({"1": ("", body)}, w)
            return w

        X = "説明する。\n\n"  # 除外が無ければ、続くです・ます調の文で過半になる
        BUL = "- `12行目`: 認証が無いです\n- `20行目`: 誰でも呼べます"
        for name_, fs, hit in (
            ("である調のみ", {PL: DE}, False),
            ("です・ます調", {PL: MS}, True),
            (
                "混在（2/4文で過半でない）",
                {PL: "削除できます。消せます。制限は無い。復旧できない。"},
                False,
            ),
            (
                "コードブロック",
                {PL: X + "```\n削除しました。\n\n消せます。\n\n止まります。\n```"},
                False,
            ),
            # コードフェンスの開閉（CommonMark）: 中の行で閉じない
            (
                "コードブロック（外側````の中のdiffの文脈行「 ```」）",
                {PL: X + "````diff\n ```\n削除しました。\n\n消せます。\n\n止まります。\n````"},
                False,
            ),
            (
                "コードブロック（~~~の中の```）",
                {PL: X + "~~~\n```\n削除しました。\n\n消せます。\n\n止まります。\n~~~"},
                False,
            ),
            (
                "コードブロック（```の中の~~~）",
                {PL: X + "```\n~~~\n削除しました。\n\n消せます。\n\n止まります。\n```"},
                False,
            ),
            (
                "コードブロック（開きより短い閉じ）",
                {PL: X + "````\n```\n削除しました。\n\n消せます。\n\n止まります。\n````"},
                False,
            ),
            (
                "コードブロック（行頭の空白1つの開き・閉じ）",
                {PL: X + " ```\n削除しました。\n\n消せます。\n\n止まります。\n   ```"},
                False,
            ),
            (  # 外側が```なら「 ```」で閉じる（CommonMark）。後の文は本文
                "コードブロック（外側```は「 ```」で閉じる）",
                {
                    PL: X
                    + "```diff\n-a\n ```\n削除しました。\n\n消せます。\n\n止まります。"
                },
                True,
            ),
            ("引用", {PL: X + "> 削除しました。\n> 消せます。"}, False),
            (
                "表",
                {
                    PL: X
                    + "| a | 削除しました。 |\n| b | 消せます。 |\n| c | 止まります。 |"
                },
                False,
            ),
            ("1文だけ", {PL: "誰でも削除できます。"}, False),
            ("でした", {PL: "説明する。脆弱でした。危険でした。"}, True),
            ("ください・ましょう", {PL: "削除してください。確認しましょう。"}, True),
            ("〜か？", {PL: X + "消せますか？\n\n止まりますか？"}, True),
            ("！", {PL: X + "消せます！\n\n止まります！"}, True),
            (".", {PL: X + "消せます.\n\n止まります."}, True),
            (
                "文末の括弧の補足",
                {PL: "削除できます（認証なし）。消せます（全件（一度に））。"},
                True,
            ),
            ("箇条書き（句点なし）", {"該当コードの問題点": BUL}, True),
            ("長い欄に薄められない", {PL: MS, TD: DE * 4}, True),
            ("攻撃シナリオ", {"攻撃シナリオ": MS}, True),
            ("対象外の見出し", {"概要": MS}, False),
            # S1-3の新ブロックも同じ基準（修正内容の解説の後ろにあっても対象になる）
            ("新ブロック: 元の処理の意図（です・ます調）", {INT: MS}, True),
            ("新ブロック: 元の処理の意図（である調）", {INT: DE}, False),
            ("新ブロック: 代替案（です・ます調）", {ALT: MS}, True),
            (
                "新ブロック: 代替案（表は対象外）",
                {ALT: X + "| 案 | 消せます。 |\n| 1 | 止まります。 |"},
                False,
            ),
            ("新ブロック: 修正内容の解説の後ろ", {"修正内容の解説": DE, INT: MS}, True),
            # 修正内容の解説の直後の新ブロックも同じ基準
            ("新ブロック: 残るリスク（です・ます調）", {RES: MS}, True),
            ("新ブロック: 残るリスク（である調）", {RES: DE}, False),
            ("新ブロック: 残るリスク（箇条書き）", {RES: BUL}, True),
            (
                "新ブロック: 解説の直後の残るリスク",
                {"修正内容の解説": DE, RES: MS, INT: DE},
                True,
            ),
            (
                "新ブロック: 残るリスクで解説が終わる",
                {"修正内容の解説": DE, RES: DE, INT: DE},
                False,
            ),
        ):
            w = st(fs)
            assert bool(w) == hit and (not w or "5.1(" in w[0]), f"文体: {name_}: {w}"
        # fence_step単体: 行の並びと、各行がフェンス行（開き・閉じ）か（1）中身・本文か（0）
        for seq, exp in (
            (["````diff", " ```", "-a", "````"], "1001"),
            (["```diff", " ```", "```"], "111"),
            (["~~~", "```", "~~~"], "101"),
            (["```", "~~~", "```"], "101"),
            (["````", "```", "````"], "101"),
            (["```", "`````", "```"], "111"),
            (["```", "``` x", "```  "], "101"),
            (["```", "    ```", "   ```"], "101"),
            (["    ```", "```"], "01"),
            (["```x`y", "~~~x`y", "~~~"], "011"),
        ):
            fs_, got = None, ""
            for ln in seq:
                isf, fs_ = fence_step(ln, fs_)
                got += "1" if isf else "0"
            assert got == exp, f"fence_step: {seq}: {got}（期待{exp}）"
        for v_ in [
            "なりすます",
            "励ます",
            "冷ます",
            "覚ます",
            "醒ます",
            "済ます",
            "悩ます",
            "澄ます",
            "さます",
            "飲ます",
        ]:
            assert not st({PL: f"{v_}。{v_}。"}), f"文体: 普通体の{v_}"
        w = st({PL: MS, "攻撃シナリオ": MS})
        assert (
            w
            and "（わかりやすい解説1件・攻撃シナリオ1件） 5.1(わかりやすい・攻撃シナリオ)。"
            in w[0]
        ), w
        # 2乗にならない（閉じた括弧が続く長い文）
        t0 = datetime.datetime.now(datetime.timezone.utc)
        st({PL: "()" * 500000})
        assert (
            datetime.datetime.now(datetime.timezone.utc) - t0
        ).total_seconds() < 1, "tailが遅い"
        ins = sw("### 5.2 [High] x\n", f"### 5.2 [High] x\n\n**{PL}**\n\n{MS}\n")
        ok, o = verdict(mkrep(mut=ins))
        assert ok and "1/3件（わかりやすい解説1件）" in o, o
        assert "5.2(わかりやすい解説3/3文)" in o and "5.1(" not in o, o
        assert "である調で統一" in o, o
        print("[OK確認] 5節の文体（です・ます調が過半の見出し。WARNのみ）")
        swaps = [
            ("4節のスコアが記録と違う", "| High | 7.5 | 8.7 |", "| High | 9.8 | 8.7 |"),
            ("4節の重大度が記録と違う", "| [5.2](#x) | High", "| [5.2](#x) | Low"),
            ("5節のスコアが記録と違う", "| CVSS v3.1 | 7.5（", "| CVSS v3.1 | 5.0（"),
            ("5節の見出しの重大度が記録と違う", "### 5.2 [High]", "### 5.2 [Low]"),
            ("6節のベーススコアが記録と違う", "ベーススコア: 7.5", "ベーススコア: 6.5"),
            ("6節のv4スコアが記録と違う", "- スコア: 8.7", "- スコア: 9.9"),
            ("6節のメトリクス値がベクターと違う", "| AV（x） | N |", "| AV（x） | L |"),
            # スコア欄の括弧の区分は計算どおり（0.0（None）をLowと書かない。v4.0も読み替えない）
            ("5節のv3.1の区分が計算と違う", "| CVSS v3.1 | 7.5（High）", "| CVSS v3.1 | 7.5（Low）"),
            ("5節のv4.0の区分が計算と違う", "| CVSS v4.0 | 8.7（High）", "| CVSS v4.0 | 8.7（Low）"),
            ("6節のベーススコアの区分が計算と違う", "ベーススコア: 7.5（High）", "ベーススコア: 7.5（Low）"),
            ("6節のv4スコアの区分が計算と違う", "- スコア: 8.7（High）", "- スコア: 8.7（Medium）"),
        ]
        ok, o = verdict(mkrep(mut=sw("ベーススコア: 7.5（High）", "ベーススコア: 7.5（High。注記）")))
        assert ok, f"区分の後ろの注記は区分の一致を妨げない: {o}"
        # v3.1=0.0: スコア欄は「0.0（None）」（v4.0も）、見出し・4節はLow、1節に件数の注記
        z3 = {"vector": V, "base_score": 0.0, "base_severity": "None"}
        zraw = {"F1": {"raw": {"v3": z3, "v4": {"vector": V4, "score": 0.0, "severity": "None"}}}}
        zeff = {"F1": (1, {"id": "5.1", "band": "Low"})}
        znote = "CVSS v3.1のスコアが0.0（None）の1件はLowに数えている。"

        def zrep(note, w3, w4):
            return "\n".join(["## 1. エグゼクティブサマリー", "", "| Low | 1 |", "", note, "",
                              "## 4. 指摘サマリー", "", "| [5.1](#x) | Low | 0.0 | 0.0 | a.js | CONFIRMED |", "",
                              "## 5. 指摘詳細", "", "### 5.1 [Low] x", "",
                              f"| CVSS v3.1 | 0.0（{w3}）。ベクター文字列: `{V}` |",
                              f"| CVSS v4.0 | 0.0（{w4}）。ベクター文字列: `{V4}` |", "", "## 6. リスク分析", ""])

        for txt_, want in ((zrep(znote, "None", "None"), 0), (zrep("", "None", "None"), 1),
                           (zrep(znote, "Low", "None"), 1), (zrep(znote, "None", "Low"), 1)):
            ng_ = []
            report_scores(txt_, zeff, zraw, False, ng_, [])
            assert len(ng_) == want, (want, ng_)
        print("[OK確認] 0.0（None）: スコア欄はNone、見出し・4節はLow、1節の件数の注記（欠ければNG）")
        res = [(n_, verdict(mkrep(mut=sw(a_, b_)))[0]) for n_, a_, b_ in swaps]
        res += nrres
        nohead = sw("**実害の有無（未使用の欠陥）**", "**概要**")
        after = sw(UNUSED_MSG + "。", "別の内容。\n\n**概要**\n\n" + UNUSED_MSG + "。")
        nomark = sw("CONFIRMED（未使用・実質問題なし）", "CONFIRMED")
        res += [
            ("unusedなのに報告書に未使用の記述が無い", verdict(mkrep(), dpu)[0]),
            (
                "unusedなのに4節に未使用が無い",
                verdict(mkrep(unused=(3,), mut=nomark), dpu)[0],
            ),
            ("同一指摘内の別メトリクスに同じ長文の根拠", verdict(mkrep(why=same))[0]),
            ("規則タグ・根拠を除くと同じ文", verdict(mkrep(why=tagged))[0]),
            (
                "未使用の記述が「実害の有無」の下に無い",
                verdict(mkrep(unused=(3,), mut=nohead), dpu)[0],
            ),
            (
                "未使用の記述が次の見出しより後ろにある",
                verdict(mkrep(unused=(3,), mut=after), dpu)[0],
            ),
            (
                "全指摘で同じ判定根拠(定型化)",
                verdict(mkrep(12, const), dp12, rp12, 12)[0],
            ),
        ]
        op = os.path.join(td, "ap.jsonl")
        rows = '{"a": 1}\n{"b": 2, "seq": 99, "ts": "x"}\n'
        for _ in range(2):
            assert append_rows(op, read_objs(rows))
        ao, ab = load(op)
        assert [o["seq"] for _, o in ao] == [1, 2, 3, 4] and not ab
        assert all(parse_ts(o["ts"]) for _, o in ao) and ao[1][1]["b"] == 2
        w = read_objs('{"v3": {}}', {"id": "F1", "kind": "alt", "of": "AC"})
        assert list(w[0]) == ["id", "kind", "of", "raw"] and read_objs("{bad") is None
        before = open(bd, encoding="utf-8").read()
        assert not append_rows(bd, w) and open(bd, encoding="utf-8").read() == before
        res.append(("--appendの入力が空", read_objs("") is not None))
        nodir = os.path.join(td, "x", "y")
        res.append(("--appendの出力先ディレクトリが無い", append_rows(nodir, w)))
        cli = [sys.executable, os.path.abspath(_MAIN_FILE)]
        both = cli + ["--append", op, "--final"]
        rc = subprocess.run(both, input=b"{}", stderr=subprocess.DEVNULL).returncode
        assert rc != 0, "--appendと他フラグの併用はエラー"
        memo = {k: 1 for k in BASE_K} | {"tmp": "F1", "st": "memo", "m3": {}}
        memo |= {"dev": [], "borderline": [], "rev": 1}
        mp_ = os.path.join(td, "memo.jsonl")
        assert append_rows(mp_, [memo]), "必須キーを満たすメモ行は追記できる"
        before = open(mp_, encoding="utf-8").read()
        short = {"tmp": "F2", "st": "memo"}
        res.append(("必須キーの無いメモ行の追記", append_rows(mp_, [short])))
        res.append(
            ("revが文字列のメモ行の追記", append_rows(mp_, [{**memo, "rev": "1"}]))
        )
        assert open(mp_, encoding="utf-8").read() == before, "拒否時は未変更"
        fin = {**memo, "st": "final"}
        res.append(("確定行のrevがメモ行と同じで追記", append_rows(mp_, [fin])))
        two = [{**memo, "tmp": "F2"}, {**fin, "tmp": "F2"}]
        res.append(("同じstdin内のメモ行と同じrevの確定行", append_rows(mp_, two)))
        np_ = os.path.join(td, "new.jsonl")
        res.append(("新規ファイルへのメモ行と同じrev", append_rows(np_, two)))
        assert not os.path.exists(np_), "拒否時はファイルを作らない"
        assert open(mp_, encoding="utf-8").read() == before, "拒否時は未変更"
        q = subprocess.run(
            cli + ["--append", mp_], input=json.dumps(fin).encode(), capture_output=True
        )
        assert q.returncode == 1 and "rev 2 以上" in q.stdout.decode("utf-8"), q
        assert append_rows(mp_, [{**fin, "rev": 2}]), "メモ最大rev+1の確定行"
        assert append_rows(mp_, [{**fin, "tmp": "F3"}]), "メモ行が無い確定行"
        two2 = [{**memo, "tmp": "F4", "rev": 3}, {**fin, "tmp": "F4", "rev": 4}]
        assert append_rows(mp_, two2), "同じstdin内のメモrev3→確定rev4"
        before = open(mp_, encoding="utf-8").read()
        memo2 = [{**memo, "rev": 2}]
        res.append(("確定行rev2の後にメモ行rev2", append_rows(mp_, memo2)))
        rev2 = [{**fin, "tmp": "F5"}, {**memo, "tmp": "F5"}]
        res.append(("同じstdin内の確定行の後に同じrevのメモ行", append_rows(mp_, rev2)))
        assert open(mp_, encoding="utf-8").read() == before, "拒否時は未変更"
        assert append_rows(mp_, [{**memo, "rev": 3}]), "確定行rev2の後のメモ行rev3"
        ao, ab = load(mp_)
        assert [o["seq"] for _, o in ao] == [1, 2, 3, 4, 5, 6] and not ab
        errs = []
        for extra in (["--kind", "alt"], ["--of", "AC"]):
            c = cli + ["--append-raw", op, "--id", "F1"] + extra
            q = subprocess.run(c, input=b"{}", stderr=subprocess.PIPE)
            errs.append((q.returncode, q.stderr.decode("utf-8")))
        assert errs[0][0] == 2 and "--of" in errs[0][1] and "必要" in errs[0][1], errs
        assert errs[1][0] == 2 and "--kind alt" in errs[1][1], errs
        old_ = p("legacy.jsonl", '{"a": 1}\n')
        q = subprocess.run(
            cli + ["--append", old_], input=b'{"b": 2}\n', stderr=subprocess.PIPE
        )
        assert q.returncode == 0 and "旧形式" in q.stderr.decode("utf-8")
        # stdinの文字コードがロケール（cp932）でも、UTF-8の日本語をそのまま追記できる
        jp_ = os.path.join(td, "jp.jsonl")
        env_ = {**os.environ, "PYTHONIOENCODING": "cp932:surrogateescape"}
        env_.pop("PYTHONUTF8", None)
        q = subprocess.run(
            cli + ["--append", jp_],
            input='{"why": "攻撃者が任意の値を送れる"}\n'.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=env_,
        )
        assert q.returncode == 0, q.stderr.decode("utf-8", "replace")
        assert load(jp_)[0][0][1]["why"] == "攻撃者が任意の値を送れる", "UTF-8のstdin"
        if fcntl:  # 並列に--appendしてもseqが重複しない
            pp = os.path.join(td, "par.jsonl")
            pipe, null = subprocess.PIPE, subprocess.DEVNULL
            procs = [
                subprocess.Popen(cli + ["--append", pp], stdin=pipe, stdout=null)
                for _ in range(8)
            ]
            for q in procs:
                q.communicate(b'{"a": 1}\n{"b": 2}\n')
            po, pb = load(pp)
            seqs = [o["seq"] for _, o in po]
            assert seqs == list(range(1, 17)) and not pb, "並列追記のseq"
            print("[OK確認] 並列8プロセスの--appendでseqが1..16の連番")
        return res

    with tempfile.TemporaryDirectory() as td:
        p = lambda n, s: (
            open(os.path.join(td, n), "w", encoding="utf-8").write(s),
            os.path.join(td, n),
        )[1]
        dp = p(
            "d.jsonl",
            "\n".join(
                json.dumps(x, ensure_ascii=False)
                for _, x in D + [(0, {**x, "st": "memo"}) for _, x in D]
            )
            + "\n",
        )
        rp = p(
            "r.jsonl", "\n".join(json.dumps(x, ensure_ascii=False) for _, x in R) + "\n"
        )
        rep = (
            "".join(f"### 5.{i} [High] x\n" for i in (1, 2, 3))
            + "".join(f"### 6.{i} [High] x\n`{V}` `{V4}`\n" for i in (1, 2, 3))
            + "## 7. 後続\n`"
            + V
            + "`\n"
        )
        with contextlib.redirect_stdout(io.StringIO()):
            assert run(dp, rp, p("rep.md", rep), 3, None, True), "報告書突合の正常系"
            bad = [
                (
                    "報告書ベクター不一致",
                    rep.replace(
                        "`" + V4 + "`", "`" + V4.replace("AV:N", "AV:L") + "`", 1
                    ),
                ),
                (
                    "報告書の見出し重大度違い",
                    rep.replace("### 6.2 [High]", "### 6.2 [Low]"),
                ),
                ("報告書5節の見出し不足", rep.replace("### 5.3 [High] x\n", "")),
            ]
            res = [(n, run(dp, rp, p("rep2.md", t), 3, None, True)) for n, t in bad]
            open(os.path.join(td, "b.bin"), "wb").write(b"\xff\xfe{")
            bd = p("bad.jsonl", "{bad\n" + json.dumps(a) + "\n")
            before = open(bd, encoding="utf-8").read()
            assert (
                not fill_ids(bd, rp, {}) and open(bd, encoding="utf-8").read() == before
            ), "--fill-idsが不正行を含むログを書き換えた"
            assert not fill_ids(
                dp,
                os.path.join(td, "nonexistent.jsonl"),
                {},
            ), "--fill-idsがraw無しで失敗しない"
            res += report_cases(td, p, dp, rp, bd)
            res += [
                ("非UTF-8", run(dp, os.path.join(td, "b.bin"), None, 3, None, True)),
                ("JSON不正行", run(p("j.jsonl", "{bad\n"), rp, None, 3, None, True)),
                ("dictでない行", run(p("l.jsonl", "[1]\n"), rp, None, 3, None, True)),
            ]
        for n, ok in res:
            if ok:
                fails += 1
                print(f"[未検出!] {n}")
            else:
                print(f"[NG検出] {n}")
    assert not fails, f"{fails}件が未検出"
    print(
        f"self-test OK (正常系 + 破壊{len(cases) + len(stamp_cases) + len(res)}ケース全てNG)"
    )


def _st_entry(main_globals, *args, **kwargs):
    """本体のモジュールの名前（globals()）を写し、selftest を実行して戻り値を返す。"""
    global _MAIN_FILE, _MAIN_GLOBALS
    g = globals()
    for k, v in main_globals.items():
        if not (k.startswith("__") and k.endswith("__")) and k not in g:
            g[k] = v
    _MAIN_FILE = main_globals["__file__"]
    _MAIN_GLOBALS = main_globals
    return selftest(*args, **kwargs)
