#!/usr/bin/env python3
"""5b補足2の検算。ペア表+群表から群を再導出し、鎖・不一致・欠落をNGにする。
同点で節点を共有する最大クリークは、構成IDの昇順列が辞書順で最小の組から1つずつ統合する。
第2引数に一時ID→最終番号の対応表(TSV: temp_id, final_number, work_id)を渡すと、判定表と最終番号の一致も検査する。
さらに --report 報告書.md で、別の最終指摘どうしの連鎖切断の組について、双方の5.Nの「修正内容の解説」に
相手の最終番号があるかを検査する（欠落はNG、5.Nの見出し・解説ブロックが無ければrc2）。
--unwritten ID1,ID2 で、未執筆項目（finding-final.md 5d補足）の一時IDに
関わる「対応表に一時IDが無い」WARNを除外し件数を1行で示す（対応表に無いIDが
全て指定内のペアだけ。除外した連鎖切断の組は列挙し、相互言及は検査しない。
ペア表に無いID・対応表にあるIDはWARN。対応表TSVが必要）。
--report では5c(c)の注記も検査する: 基準指摘（--base 5.N、無ければ5.Nの検証方式の行に「5c合成」か
推奨される修正に「合成した統合版」を持ち、推奨される修正に「(5.Nの…統合済み」の行が無い指摘）以外の各5.Nの
「推奨される修正」で、最後のコードブロック末尾の「(」で始まる行の並び（フェンス内）か閉じフェンス直後の行に
「(5.Nの修正案に統合済み。本diffは単独で適用する場合の参考)」（半角括弧）があり、番号が基準指摘であること。
欠落・文言違い・番号違いはNG。基準指摘が無ければ省略を表示し、注記があるのに基準を特定できない・基準が複数
見つかった（--base無し）・検査対象が0件・基準指摘自身に注記がある場合はWARN（rc0）。
合成に取り込んでいない指摘は --not-merged 5.N,5.M で除外する（注記があれば番号は検査する）。
後方互換: --report では、連鎖切断の組に関わらず5.Nの見出しの重複をrc2にする（以前は組の当事者だけ）。
限界: 5c群が複数あるとき、注記の番号はいずれかの基準に一致すればOK（群の対応は検査しない）。
限界: 番号の偶然一致・HTMLコメント内・####見出し・全角数字は区別しない。
限界: 表の内部整合だけを見る。共有CWEの実在・行重なりの正しさは検証しない。
コードフェンスの開閉はCommonMarkに沿う（fence_step。外側が````以上のフェンスの中の```の行やdiffの文脈行の「 ```」は閉じない。外側が```なら「 ```」で閉じる）。
限界: リスト・引用の中のフェンス（行頭の空白4文字以上・「> 」付き）はフェンスとして数えない。
5b補足4（同一箇所の指摘の相互参照）: 参考表の行 | I3-U5 | routes/users.js:20-34 | 同一箇所 | は、群の導出に
使わない（統合しない）。検査: 2列目が「ファイル:行」を含む、同じペアの重複が無い、ペア表で統合・非統合・
連鎖切断のどれかと判定したペアでない（以上NG）。対応表TSVがあれば両者が別の最終番号
であること（NG）、--report では連鎖切断と同じく双方の「修正内容の解説」に相手の最終番号があること（欠落は
NG）。同一箇所の行が無い表は従来どおり（ペア行が0件でも同一箇所の行があれば空表としない）。
--findings findings-log.jsonl（対応表TSVが必要）: 各行の一時ID（tmp_id・tmp・temp_id。対応表のIDに、
そのまま・ハイフン除去・ハイフンを「.」で合うもの）と file_line（または file/line）から、5b補足の重なり
（整数の閉区間、共有行数が長い方の半分以上）を満たし、ペア表に無く（統合・非統合・連鎖切断のどれでもない）、
同じ最終番号でもないペアを洗い出し、参考表に無ければNG（同一箇所の漏れ）、参考表にあるのに重ならなければ
WARN。最終番号どうしの組が20組を超えたらWARNでまとめ方を示す。--emit-same で参考表の行を出力する。
限界: findings の file/line が、報告書の確定した位置と違うことがある（Redの記載のまま）。行が数値でない・
「a.js,b.js / 43 / 12」の位置対応の書式は範囲なしとして扱う。
ペア行 | I3-U3 | 79 | 統合 |  (判定=統合/非統合/連鎖切断)   群行 | F6 | I3+U1 |
終了コード 0=OK(警告ありでも0) 1=NG 2=入力エラー"""

import itertools
import json
import re
import sys

DASH = "-‐‑–—－ー―"
NOTAIL = r"(?![0-9A-Za-z]|\.\d)"  # 5.1が5.12・5.1a・5.1.2の一部でない
# 修正内容の解説ブロックの終わり（report_templateの5.Nの小見出し。太字だけの行一般では切らない）
LABELS = (
    "概要|実害の有無|わかりやすい解説|技術的詳細解説|該当コード|攻撃シナリオ"
    "|推奨される修正|修正案の監査レビュー|CVSS|判定記録"
    # S1-3の新ブロック。ここで終えるので、相手の番号は従来どおり「修正内容の解説」自体に要る
    "|元の処理の意図と、修正による挙動の変化|設計方針に従えない場合の代替案"
    # 修正内容の解説の直後の新ブロック。ここでも終える（相手の番号は同じく「修正内容の解説」自体に要る）
    "|修正後に残るリスクと別経路"
)
# コードフェンスの行（CommonMark）: 行頭の空白0〜3文字＋同じ文字（`か~）3個以上＋残り
FENCE = re.compile(r"( {0,3})(`{3,}|~{3,})(.*)$")


def fence_step(ln, open_):
    """CommonMarkに沿ってコードフェンスの開閉を1行ずつ判定する。
    open_ は開いているフェンスの(文字, 個数)、外ならNone。(この行がフェンス行か, 次のopen_)を返す。
    開き: 行頭の空白0〜3文字＋```か~~~（3個以上）＋任意の情報文字列（```の情報文字列に`は不可）。
    閉じ: 開きと同じ文字で、同じかそれ以上の個数＋空白のみ（行頭の空白は3文字以内）。
    フェンスの中で閉じにならない行（外側が````の中の```、diffの文脈行の「 ```」、~~~の中の```、
    開きより短い```）は中身として扱う。フェンスの外の「 ```」（空白1つ）は開きになる"""
    m = FENCE.match(ln)
    if not m:
        return False, open_
    ch, n, rest = m.group(2)[0], len(m.group(2)), m.group(3)
    if not open_:
        if ch == "`" and "`" in rest:  # インラインコード（```x```）は開きでない
            return False, None
        return True, (ch, n)
    if ch == open_[0] and n >= open_[1] and not rest.strip():
        return True, None
    return False, open_


def derive(nodes, ok):
    nodes, out = set(nodes), []
    while True:
        merged = False
        seen = set()
        for n in sorted(nodes):
            if n in seen:
                continue
            st, comp = [n], set()
            while st:
                x = st.pop()
                if x not in comp:
                    comp.add(x)
                    st += [y for y in nodes if y != x and ok(x, y)]
            seen |= comp
            if len(comp) < 2:
                continue
            adj = {x: {y for y in comp if y != x and ok(x, y)} for x in comp}
            cl = []

            def bk(r, p, x):  # Bron-Kerbosch(ピボット付き)
                if not p and not x:
                    cl.append(r)
                    return
                u = max(p | x, key=lambda v: len(adj[v] & p))
                for v in sorted(p - adj[u]):
                    bk(r | {v}, p & adj[v], x & adj[v])
                    p = p - {v}
                    x = x | {v}

            bk(frozenset(), set(comp), set())
            k = max(len(c) for c in cl)
            top = [c for c in cl if len(c) == k]
            if k < 2:
                continue
            taken = (
                set()
            )  # 同点で節点を共有する組は、IDの昇順列が辞書順で最小の組から採る
            for c in sorted(top, key=sorted):
                if not (c & taken):
                    out.append(frozenset(c))
                    taken |= c
                    merged = True
        nodes -= set().union(*out) if out else set()
        if not merged:
            return out


def numkey(s):  # 5.2 < 5.10
    return [int(x) for x in re.findall(r"\d+", s)]


def mentions(report, cuts, label="連鎖切断"):
    """連鎖切断（または同一箇所）の組 {(甲, 乙): [ペア]} の双方の「修正内容の解説」に
    相手の最終番号があるか。(欠落の一覧, 構造エラーの一覧) を返す"""
    try:
        lines = open(report, encoding="utf-8").read().split("\n")
    except (OSError, UnicodeDecodeError) as e:
        return [], [str(e)]
    sec, dup, cur, blk, fence = {}, set(), None, False, None
    for ln in lines:
        s = ln.strip()
        isfence, fence = fence_step(ln, fence)  # 開閉はCommonMarkに沿う（fence_step）
        if isfence:
            pass
        elif not fence and re.match(r"#{1,3} ", s):  # 見出しで節・ブロックが終わる
            m = re.match(rf"### (\d+(?:\.\d+)+){NOTAIL}", s)
            cur, blk = m.group(1) if m else None, False
            if cur in sec:
                dup.add(cur)
            elif cur:
                sec[cur] = None
            continue
        elif not fence and cur and s.startswith("**修正内容の解説"):
            blk, sec[cur] = True, sec[cur] or ""  # 同じ行の本文も数える
        elif not fence and re.match(rf"\*\*({LABELS})", s):  # 次の節ラベルまで
            blk = False
        if blk and cur:
            sec[cur] += ln + "\n"
    miss, err = [], []
    for (a, b), ps in sorted(cuts.items(), key=lambda kv: list(map(numkey, kv[0]))):
        for x, y in ((a, b), (b, a)):
            if x not in sec or x in dup:
                err.append(f"### {x} の見出しが{'重複' if x in dup else '無い'}")
            elif sec[x] is None:
                err.append(f"### {x} に**修正内容の解説**が無い")
            elif not re.search(rf"(?<![0-9A-Za-z.]){re.escape(y)}{NOTAIL}", sec[x]):
                miss.append(
                    f"{label} {a}↔{b}（{', '.join(ps)}）: {x}の修正内容の解説に{y}が無い"
                )
    return miss, sorted(set(err))


NOTE5C = re.compile(r"\((5\.\d+)の修正案に統合済み。本diffは単独で適用する場合の参考\)")
NOTELIKE = re.compile(r"\(5\.\d+の[^()]*統合済み")  # 文言ゆれを含む注記らしい行
NM = "（合成に取り込んでいない指摘は --not-merged で除外）"


def notes5c(report, base=None, notmerged=()):
    """5c(c)の注記の検査。(基準指摘の一覧, 検査した件数, NGの一覧, WARNの一覧,
    構造エラーの一覧, 省略時の表示)を返す。検査しなければ基準指摘の一覧は空"""
    try:
        with open(report, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except (OSError, UnicodeDecodeError) as e:
        return [], 0, [], [], [str(e)], None
    sec, dup, cur, blk, fence = {}, set(), None, False, None
    for ln in lines:
        s = ln.strip()
        isfence, fence = fence_step(ln, fence)  # 開閉はCommonMarkに沿う（fence_step）
        if isfence:
            if blk:
                sec[cur]["fix"].append(("F", s))
            continue
        if fence:
            if blk:
                sec[cur]["fix"].append(("C", s))
            continue
        if re.match(r"#{1,3} ", s):
            m = re.match(rf"### (5\.\d+){NOTAIL}", s)
            cur, blk = (m.group(1) if m else None), False
            if cur in sec:
                dup.add(cur)
            elif cur:
                sec[cur] = {"fix": None, "base": False}
            continue
        if not cur:
            continue
        if s.startswith("**推奨される修正"):
            blk, sec[cur]["fix"] = True, sec[cur]["fix"] or []
            continue
        if re.match(rf"\*\*(修正内容の解説|{LABELS})", s):
            blk = False
        if s.startswith("|") and "検証方式" in s and "5c合成" in s:
            sec[cur]["base"] = True
        if blk:
            sec[cur]["fix"].append(("T", s))
            sec[cur]["base"] |= "合成した統合版" in s
    err = [f"### {x} の見出しが重複" for x in sorted(dup, key=numkey)]
    err += [f"### {b} の見出しが無い（--base）" for b in base or () if b not in sec]
    warn = [
        f"{x}: --not-merged の番号が5節に無い" for x in notmerged or () if x not in sec
    ]
    if err:
        return [], 0, [], warn, err, None
    noted = {  # 推奨される修正に注記らしい行を持つ節（基準の候補から外す）
        x for x in sec if any(NOTELIKE.match(t) for _, t in sec[x]["fix"] or [])
    }
    found = [x for x in sorted(sec, key=numkey) if sec[x]["base"] and x not in noted]
    bases = list(base) if base else found
    if not bases:
        if noted:
            warn.append("注記はあるが基準指摘を特定できない。--base 5.N を指定")
            return [], 0, [], warn, [], None
        return [], 0, [], warn, [], "SKIP: 5c基準指摘なし（検査省略）"
    if len(bases) > 1 and not base:
        warn.append(
            f"基準指摘が複数見つかった（{', '.join(bases)}）。--base 5.N を指定"
        )
        return [], 0, [], warn, [], None
    warn += [
        f"{x}: 基準指摘の推奨される修正に統合済みの注記がある（自己参照）"
        for x in bases
        if x in noted
    ]
    ng, n = [], 0
    for x in sorted(sec, key=numkey):
        fix = sec[x]["fix"]
        if x in bases:
            continue
        free = x in (notmerged or ())
        n += not free
        idx = [i for i, (k, _) in enumerate(fix or []) if k == "F"]
        # 最後のコードブロック末尾の「(」で始まる行の並びと、閉じフェンス直後の行
        cand = []
        if len(idx) >= 2:
            inner = [t for _, t in fix[idx[-2] + 1 : idx[-1]] if t]
            after = [t for _, t in fix[idx[-1] + 1 :] if t]
            while inner and inner[-1].startswith("("):
                cand.append(inner.pop())
            cand += after[:1]
        hit = [m.group(1) for m in map(NOTE5C.fullmatch, cand) if m]
        if hit:
            if hit[0] not in bases:
                ng.append(
                    f"{x}: 5c(c)の注記の番号{hit[0]}が基準指摘（{', '.join(bases)}）と違う"
                )
        elif free:
            continue
        elif fix is None or len(idx) < 2:
            ng.append(f"{x}: 推奨される修正にdiffが無い{NM}")
        elif any("統合済み" in t for _, t in fix):
            ng.append(
                f"{x}: 5c(c)の注記の文言か位置が所定と違う（diffの末行か直後に"
                f"「({bases[0]}の修正案に統合済み。本diffは単独で適用する場合の参考)」）"
            )
        else:
            ng.append(f"{x}: 推奨される修正のdiffの直後に5c(c)の注記が無い{NM}")
    if not n:
        warn.append("5c(c)の注記: 検査対象の指摘が0件")
    return bases, n, ng, warn, [], None


SAME_MANY = 20  # 同一箇所の組（最終番号どうし）がこれを超えたら、まとめ方を案内する


def spans(file_line):
    """`file/line` の文字列から {ファイル: 行の集合}（5b補足の展開: 「6,9-14」は6と9〜14、
    単一のNはN）。行が数値でない部分（全体・各所・-）は範囲を持たない"""
    out = {}
    for f, spec in re.findall(
        r"([^\s,:;、（）()]+?)\s*:\s*(\d+(?:\s*-\s*\d+)?(?:\s*,\s*\d+(?:\s*-\s*\d+)?)*)",
        str(file_line or ""),
    ):
        for part in re.split(r"\s*,\s*", spec):
            a, _, b = part.partition("-")
            lo, hi = int(a), int(b or a)
            if lo <= hi:
                out.setdefault(f, set()).update(range(lo, hi + 1))
    return out


def overlaps(x, y):
    """5b補足の重なり: 同じファイル名で共有する行が1行以上、かつ長い方の範囲の半分以上。
    重なるファイルと共有行の (ファイル, 行の集合)、無ければ None"""
    for f in sorted(set(x) & set(y)):
        sh = x[f] & y[f]
        if sh and 2 * len(sh) >= max(len(x[f]), len(y[f])):
            return f, sh
    return None


def compact(lines):
    """行の集合を「3-5,9」の形に"""
    out, xs = [], sorted(lines)
    for v in xs:
        if out and v == out[-1][1] + 1:
            out[-1][1] = v
        else:
            out.append([v, v])
    return ",".join(f"{a}" if a == b else f"{a}-{b}" for a, b in out)


def load_findings(path, known):
    """findings-log.jsonl から {一時ID: {ファイル: 行の集合}}。IDは tmp_id・tmp・temp_id の
    いずれかで、対応表のIDに合うもの（そのまま・ハイフン除去・ハイフンを「.」）を使う。
    同じIDの行は、file_line（または file/line）がある最後の行を使う。(結果, 読めない行数)"""
    out, bad = {}, 0
    with open(path, encoding="utf-8-sig") as fh:
        for ln in fh:
            if not ln.strip():
                continue
            try:
                o = json.loads(ln)
            except ValueError:
                bad += 1
                continue
            if not isinstance(o, dict):
                bad += 1
                continue
            raw = next((o[k] for k in ("tmp_id", "tmp", "temp_id") if o.get(k)), None)
            fl = o.get("file_line") or o.get("file/line")
            if raw is None or not fl:
                continue
            raw = str(raw)
            for c in (raw, re.sub(f"[{DASH}]", "", raw), re.sub(f"[{DASH}]", ".", raw)):
                if c in known:
                    out[c] = spans(fl)
                    break
    return out, bad


def main(
    path,
    tsv=None,
    report=None,
    unwritten=None,
    base=None,
    notmerged=None,
    findings=None,
    emit_same=False,
):
    if report and not tsv:
        print("ERROR: --report には一時ID対応表TSV（第2引数）が必要")
        return 2
    if (base or notmerged) and not report:
        print("ERROR: --base・--not-merged には --report が必要")
        return 2
    if unwritten is not None and not tsv:
        print("ERROR: --unwritten には一時ID対応表TSV（第2引数）が必要")
        return 2
    if (findings or emit_same) and not tsv:
        print("ERROR: --findings・--emit-same には一時ID対応表TSV（第2引数）が必要")
        return 2
    if emit_same and not findings:
        print("ERROR: --emit-same には --findings が必要")
        return 2
    try:
        lines = open(path, encoding="utf-8").read().split("\n")
    except (OSError, UnicodeDecodeError) as e:
        print("ERROR:", e)
        return 2
    pairs, groups, bad, warn, sloc = {}, {}, [], [], {}
    for i, l in enumerate(lines, 1):
        if not l.strip().startswith("|"):
            continue
        if re.fullmatch(r"[|\-: ]+", l.strip()):
            continue
        c = [x.strip() for x in l.strip().strip("|").split("|")]
        m = re.fullmatch(rf"([\w.]+)[{DASH}]([\w.]+)", c[0]) if c else None
        if len(c) >= 3 and m and c[2] in ("統合", "非統合", "連鎖切断"):
            k = frozenset(m.groups())
            if k in pairs:
                bad.append(f"L{i}: ペア重複 {c[0]}")
            pairs[k] = c[2]
        elif len(c) >= 3 and m and c[2] == "同一箇所":  # 5b補足4の参考表
            k = frozenset(m.groups())
            if k in sloc:
                bad.append(f"L{i}: 同一箇所のペア重複 {c[0]}")
            if not re.search(r"\S+:\d+", c[1]):
                bad.append(f"L{i}: 同一箇所の2列目が「ファイル:行」でない: {c[1][:40]}")
            sloc[k] = c[0]
        elif len(c) >= 2 and re.fullmatch(r"F\d+", c[0]):
            if c[0] in groups:
                bad.append(f"L{i}: 群キー重複 {c[0]}")
            groups[c[0]] = frozenset(c[1].split("+"))
        elif (
            len(c) >= 3
            and (any(d in c[0] for d in DASH) or re.match("統合|非統合|連鎖切断", c[2]))
            and c[0] != "ペア"
        ):
            warn.append(f"L{i}: 解釈できない行を無視した: {l.strip()[:50]}")
    if not pairs and not sloc:
        bad.append("ペア行が0件（空表・書式不一致）")
    ok = lambda a, b: pairs.get(frozenset((a, b))) in ("統合", "連鎖切断")
    nodes = {x for p in pairs for x in p} | {x for g in groups.values() for x in g}
    want, have = set(derive(nodes, ok)), set(groups.values())
    for n, g in groups.items():
        miss = [
            tuple(sorted(p))
            for p in itertools.combinations(sorted(g), 2)
            if pairs.get(frozenset(p)) != "統合"
        ]
        if miss:
            bad.append(f"{n}: 全ペアが「統合」でない(鎖): {miss}")
    for p, v in pairs.items():
        same = any(p <= g for g in have)
        if v == "統合" and not same:
            bad.append(f"{sorted(p)}: 統合なのに群が別")
        if v == "連鎖切断" and same:
            bad.append(f"{sorted(p)}: 連鎖切断なのに同一群")
    for p, raw in sloc.items():
        if p in pairs:
            bad.append(
                f"{raw}: 同一箇所の行に、ペア表で{pairs[p]}と判定したペアがある"
                "（同一箇所は共有CWEの無いペア。重なりを満たす共有CWEありのペアは"
                "5bで統合か連鎖切断になる）"
            )
    if want != have:
        bad.append(
            f"群が規則の導出と不一致: 期待{sorted(map(sorted, want))} 実際{sorted(map(sorted, have))}"
        )
    if tsv:
        try:
            rows = [
                ln.split("\t")
                for ln in open(tsv, encoding="utf-8").read().split("\n")
                if ln.strip()
            ]
        except (OSError, UnicodeDecodeError) as e:
            print("ERROR:", e)
            return 2
        fin, cuts, skipped, skipcut = {}, {}, 0, []
        for r in rows[1:] if rows and rows[0][0] == "temp_id" else rows:
            if len(r) >= 2:
                fin.setdefault(r[0], set()).add(r[1])
        for t, v in sorted(fin.items()):
            if len(v) > 1:
                bad.append(f"{t}: 一時IDが複数の最終番号に対応: {sorted(v)}")
        pids = {x for p in pairs for x in p}
        for u in sorted(set(unwritten or ())):
            if u not in pids:
                warn.append(f"{u}: --unwritten のIDがペア表に無い")
            if u in fin:
                warn.append(
                    f"{u}: --unwritten のIDが対応表にある"
                    "（対応表から外すか、指定を外す）"
                )
        for p, v in pairs.items():
            a, b = sorted(p)
            fa, fb = fin.get(a), fin.get(b)
            if fa is None or fb is None:
                if unwritten and {x for x in p if x not in fin} <= set(unwritten):
                    skipped += 1  # 対応表に無いIDが全て未執筆項目のペアだけ除外
                    if v == "連鎖切断":  # 相互言及は7節と相手の5.Nで人が確かめる
                        skipcut.append(f"{a}-{b}")
                else:
                    warn.append(f"{a}-{b}: 対応表に一時IDが無い")
                continue
            if v == "統合" and not (fa & fb):
                bad.append(f"{a}-{b}: 統合なのに最終番号が別")
            if v != "統合" and (fa & fb):
                bad.append(f"{a}-{b}: {v}なのに同じ最終番号に統合されている")
            elif v == "連鎖切断" and len(fa) == len(fb) == 1:  # 別の最終番号どうし
                k = tuple(sorted(fa | fb, key=numkey))
                cuts.setdefault(k, []).append(f"{a}-{b}")
        sames = {}  # 同一箇所の組（別の最終番号どうし）
        for p in sloc:
            a, b = sorted(p)
            fa, fb = fin.get(a), fin.get(b)
            if fa is None or fb is None:
                if not (unwritten and {x for x in p if x not in fin} <= set(unwritten)):
                    warn.append(f"{a}-{b}: 同一箇所の一時IDが対応表に無い")
                continue
            if fa & fb:
                bad.append(f"{a}-{b}: 同一箇所なのに同じ最終番号に統合されている")
            elif len(fa) == len(fb) == 1:
                k = tuple(sorted(fa | fb, key=numkey))
                sames.setdefault(k, []).append(f"{a}-{b}")
        if findings:  # 5b補足4の対象ペアを findings-log.jsonl の file/line から洗い出す
            try:
                loc, unread = load_findings(findings, set(fin))
            except (OSError, UnicodeDecodeError) as e:
                print("ERROR:", e)
                return 2
            want_s = {}
            for a, b in itertools.combinations(sorted(loc), 2):
                p, fa, fb = frozenset((a, b)), fin[a], fin[b]
                hit = overlaps(loc[a], loc[b])
                if hit and p not in pairs and not (fa & fb):
                    want_s[p] = f"{hit[0]}:{compact(hit[1])}"
            lost = sorted(set(want_s) - set(sloc), key=sorted)
            extra = [p for p in sloc if p not in want_s and all(x in loc for x in p)]
            for p in lost:
                bad.append(
                    f"{'-'.join(sorted(p))}: 同一箇所の漏れ（findingsのfile/lineが"
                    f"{want_s[p]}で重なり、5bで統合も連鎖切断もしていない）"
                )
            for p in sorted(extra, key=sorted):
                warn.append(
                    f"{sloc[p]}: 同一箇所の行だが、findingsのfile/lineでは重ならない"
                )
            nr = len(set(fin) - set(loc))
            if unread or nr:
                warn.append(
                    f"findings: file/lineを読めない行{unread}件・対応表の一時IDのうち"
                    f"findingsに無い{nr}件（照合の対象外）"
                )
            fins = {
                tuple(sorted(fin[a] | fin[b], key=numkey))
                for a, b in map(sorted, want_s)
            }
            if len(fins) > SAME_MANY:
                warn.append(
                    f"同一箇所の組が{len(fins)}組（最終番号どうし）で{SAME_MANY}組を超える: 参考表は"
                    "--emit-same の出力をそのまま貼り、修正内容の解説では相手の番号を1文に"
                    "列挙してよい（5b補足4）"
                )
            if emit_same:
                print("| ペア | 重なる位置 | 判定 |\n| --- | --- | --- |")
                for p in sorted(want_s, key=sorted):
                    print(f"| {'-'.join(sorted(p))} | {want_s[p]} | 同一箇所 |")
        if report:
            miss, err = mentions(report, cuts)
            if not err and sames:
                m2, err = mentions(report, sames, "同一箇所")
                miss += m2
            if err:
                print("\n".join("ERROR: 報告書の構造: " + x for x in err))
                return 2
            bad += miss
            bases, n5c, ng5c, w5c, err, skip = notes5c(report, base, notmerged)
            if err:
                print("\n".join("ERROR: 報告書の構造: " + x for x in err))
                return 2
            bad, warn = bad + ng5c, warn + w5c
    for w in warn:
        print("WARN:", w)
    if unwritten is not None and tsv:
        cut = f"。うち連鎖切断{len(skipcut)}組" if skipped else ""
        cut += f": {', '.join(skipcut)}" if skipcut else ""
        print(f"（未執筆項目として除外: {skipped}ペア{cut}）")
    print(
        "\n".join("NG: " + b for b in bad)
        or "OK: 全群がクリーク・導出と一致（表の内部整合のみ。CWE共有の実在は未検証）"
    )
    if report and not bad:
        print(f"OK: 連鎖切断{len(cuts)}組の修正内容の解説に相手の番号あり（双方向）")
        if sloc:
            print(
                f"OK: 同一箇所{len(sames)}組の修正内容の解説に相手の番号あり（双方向）"
            )
    if report and skip:
        print(skip)
    elif report and bases and n5c and not bad:
        print(f"OK: 5c(c)の注記あり（基準{', '.join(bases)}、{n5c}指摘）")
    return 1 if bad else 0


def self_test():
    """内蔵自己テスト: 正常系は全てOK(rc0)、破壊系は全てNG(rc1)、入力エラーはrc2。"""
    import os
    import random
    import tempfile
    import time

    def tbl(edges, groups, cut=()):
        c = {frozenset(e) for e in cut}
        t = "".join(
            f"| {a}-{b} | x | {'連鎖切断' if frozenset((a, b)) in c else '統合'} |\n"
            for a, b in edges
        )
        return t + "".join(
            f"| F{i} | {'+'.join(g)} |\n" for i, g in enumerate(groups, 1)
        )

    tri = [("A", "B"), ("A", "C"), ("B", "C")]
    tri2 = [("D", "E"), ("D", "F"), ("E", "F")]
    allcut = lambda e: e
    cases = [
        (
            "two_triangles_bridge_ok",
            tbl(
                tri + tri2 + [("C", "D")],
                [("A", "B", "C"), ("D", "E", "F")],
                cut=[("C", "D")],
            ),
            0,
        ),
        (
            "chain_tiebreak_ok",
            tbl([("A", "B"), ("B", "C")], [("A", "B")], cut=[("B", "C")]),
            0,
        ),
        (
            "chain_all_cut_ng",
            tbl([("A", "B"), ("B", "C")], [], cut=[("A", "B"), ("B", "C")]),
            1,
        ),
        (
            "bowtie_tiebreak_ok",
            tbl(
                tri + [("C", "D"), ("C", "E"), ("D", "E")],
                [("A", "B", "C"), ("D", "E")],
                cut=[("C", "D"), ("C", "E")],
            ),
            0,
        ),
        (
            "bowtie_none_ng",
            tbl(
                tri + [("C", "D"), ("C", "E"), ("D", "E")],
                [],
                cut=tri + [("C", "D"), ("C", "E"), ("D", "E")],
            ),
            1,
        ),
        (
            "triangle_tail_ok",
            tbl(tri + [("C", "D")], [("A", "B", "C")], cut=[("C", "D")]),
            0,
        ),
        (
            "two_triangles_bridge_overmerge",
            tbl(tri + tri2 + [("C", "D")], [("A", "B", "C", "D", "E", "F")]),
            1,
        ),
        (
            "two_triangles_bridge_undermerge",
            tbl(tri + tri2 + [("C", "D")], [], cut=tri + tri2 + [("C", "D")]),
            1,
        ),
        ("chain_merged", tbl([("A", "B"), ("B", "C")], [("A", "B", "C")]), 1),
        ("empty_table", "| ペア | 共有CWE | 判定 |\n|---|---|---|\n", 1),
        ("annotated_verdict", "| X-Y | 1 | 統合（SQLi） |\n", 1),
        ("dup_group_key", "| X-Y | 1 | 統合 |\n| F1 | X+Y |\n| F1 | X+Y |\n", 1),
        (
            "hyphen_id_warn_ok",
            "| A-1-B-2 | 79 | 統合 |\n| X-Y | 1 | 統合 |\n| F1 | X+Y |\n",
            0,
        ),
        # 5b補足4: 同一箇所の参考表（群の導出に使わない）
        (
            "same_ok",
            tbl([("A", "B")], [("A", "B")]) + "| A-C | a.js:1-3 | 同一箇所 |\n",
            0,
        ),
        ("same_only_ok", "| A-C | a.js:1-3, b.js:4 | 同一箇所 |\n", 0),
        ("same_dup", "| A-C | a.js:1 | 同一箇所 |\n| C-A | a.js:1 | 同一箇所 |\n", 1),
        ("same_no_location", "| A-C | 全体 | 同一箇所 |\n", 1),
        (
            "same_but_merged",
            tbl([("A", "B")], [("A", "B")]) + "| A-B | a.js:1 | 同一箇所 |\n",
            1,
        ),
        (
            "same_but_cut",
            tbl([("A", "B"), ("B", "C")], [("A", "B")], cut=[("B", "C")])
            + "| B-C | a.js:1 | 同一箇所 |\n",
            1,
        ),
    ]
    fails = 0
    d = tempfile.mkdtemp()
    for name, text, exp in cases:
        p = os.path.join(d, name + ".md")
        open(p, "w", encoding="utf-8").write(text)
        import contextlib
        import io

        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(p)
        ok = rc == exp
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    tp = os.path.join(d, "t.md")
    open(tp, "w", encoding="utf-8").write(
        tbl([("A", "B"), ("B", "C")], [("A", "B")], cut=[("B", "C")])
    )
    for name, tsv, exp in [
        ("mapping_ok", "A\t5.1\nB\t5.1\nC\t5.2\n", 0),
        ("mapping_overmerge", "A\t5.1\nB\t5.1\nC\t5.1\n", 1),
        ("mapping_split", "A\t5.1\nB\t5.2\nC\t5.3\n", 1),
        ("mapping_multi", "A\t5.1\nA\t5.2\nB\t5.1\nC\t5.3\n", 1),
    ]:
        mp = os.path.join(d, name + ".tsv")
        open(mp, "w", encoding="utf-8").write("temp_id\tfinal_number\twork_id\n" + tsv)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(tp, mp)
        ok = rc == exp
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    # --report: 連鎖切断B-C（5.1↔5.2）の双方の修正内容の解説に相手の番号
    rep = (
        "## 5. 指摘詳細\n\n### 5.1 [High] a\n\n**修正内容の解説**\n\n"
        "相手は認証の欠如（[5.2](#52-x)）。\n\n**修正案の監査レビュー**\n\n5.2も見た。\n\n"
        "### 5.2 [High] b\n\n**修正内容の解説**\n\n```\n**x**\n```\n**併用時**\n\n相手は5.1。\n"
        "\n## 6. リスク分析\n"
    )
    mok = os.path.join(d, "mapping_ok.tsv")
    inl = rep.replace("**修正内容の解説**\n\n`", "**修正内容の解説**: 相手は5.1\n\n`")
    nb = rep.replace(
        "相手は5.1。\n",
        "相手の説明。\n\n**元の処理の意図と、修正による挙動の変化**\n\n- 修正による挙動の変化: 5.1と連動\n"
        "\n**設計方針に従えない場合の代替案**\n\n| 案 | 内容 |\n| --- | --- |\n| 1 | 5.1 |\n",
    )
    # 修正内容の解説の直後の新ブロック「修正後に残るリスクと別経路」でも解説のブロックが終わる
    nr = rep.replace(
        "相手は5.1。\n",
        "相手の説明。\n\n**修正後に残るリスクと別経路**\n\n- 別経路: 5.1と同じ入力から到達できる（`a.js:1`）\n"
        "\n**元の処理の意図と、修正による挙動の変化**\n\n- 修正による挙動の変化: なし\n",
    )
    # コードフェンスの開閉（CommonMark）: 5.1の解説の前にフェンスを置き、中の見出しで節が切れないこと
    def fenced(*body):
        return rep.replace(
            "相手は認証の欠如", "\n".join(body) + "\n\n相手は認証の欠如", 1
        )

    h59 = "### 5.9 [Low] z"  # フェンスの中なら見出しでない（5.1の解説が切れない）
    fence_reports = [
        # 外側が````の中の「 ```」（diffの文脈行）は閉じでない。奇数個でも後続の見出しを見失わない
        ("report_fence_outer4", fenced("````diff", " ```", "-a", h59, "````")),
        ("report_fence_outer4_info", fenced("````diff", " ```js", h59, " ```", "````")),
        ("report_fence_tilde_mix", fenced("~~~diff", "```", h59, "~~~")),
        ("report_fence_backtick_mix", fenced("```diff", "~~~", h59, "```")),
        ("report_fence_short_close", fenced("````", "```", h59, "````")),
        ("report_fence_indent4", fenced("```", "    ```", h59, "```")),
        ("report_fence_info_after", fenced("```", "``` x", h59, "```")),
        ("report_fence_open_space1", fenced(" ```", h59, "   ```")),
    ]
    for name, text, tsv, exp in [
        ("report_ok", rep, mok, 0),
        *((n, t, mok, 0) for n, t in fence_reports),
        # フェンスの外の「 ```」（空白1つ）は開き。閉じが無ければ文書の末尾まで中身（見出しを見失う）
        ("report_fence_unclosed", fenced(" ```", "-a"), mok, 2),
        # 外側が```なら「 ```」で閉じる（CommonMark）。後の見出しは見出しとして数える
        ("report_fence_closed_by_space1", fenced("```diff", " ```", h59), mok, 1),
        ("report_one_side", rep.replace("（[5.2](#52-x)）", "（5.21）"), mok, 1),
        ("report_prefix_only", rep.replace("相手は5.1。", "相手は5.10。"), mok, 1),
        ("report_inline", inl.replace("相手は5.1。", "なし。"), mok, 0),
        ("report_no_heading", rep.replace("### 5.2 [High] b", "5.2 b"), mok, 2),
        ("report_no_block", rep.replace("**修正内容の解説**\n\n`", "`"), mok, 2),
        ("report_without_tsv", rep, None, 2),
        # S1-3の新ブロックは「修正内容の解説」の一部ではない: 相手の番号が新ブロックだけにあればNG
        ("report_newblock_only_ng", nb, mok, 1),
        ("report_newblock_ok", nb.replace("相手の説明。", "相手は5.1。"), mok, 0),
        # 相手の番号が「修正後に残るリスクと別経路」だけにあればNG（解説自体に要る）
        ("report_residual_only_ng", nr, mok, 1),
        ("report_residual_ok", nr.replace("相手の説明。", "相手は5.1。"), mok, 0),
    ]:
        rp = os.path.join(d, name + ".md")
        open(rp, "w", encoding="utf-8").write(text)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(tp, tsv, rp)
        ok = rc == exp
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    # 5b補足4: 同一箇所の組（A-C。5.1↔5.2）の相互言及と最終番号
    ts = os.path.join(d, "same.md")
    with open(ts, "w", encoding="utf-8") as fh:
        fh.write(tbl([("A", "B")], [("A", "B")]) + "| A-C | a.js:1-3 | 同一箇所 |\n")
    m1 = os.path.join(d, "same_merged.tsv")
    with open(m1, "w", encoding="utf-8") as fh:
        fh.write("A\t5.1\nB\t5.1\nC\t5.1\n")
    mab = os.path.join(d, "same_ab.tsv")
    with open(mab, "w", encoding="utf-8") as fh:
        fh.write("A\t5.1\nB\t5.1\n")
    rp0, rp1 = (os.path.join(d, n + ".md") for n in ("report_ok", "report_one_side"))
    for name, args, exp, has in [
        ("same_report_ok", (ts, mok, rp0), 0, ["OK: 同一箇所1組"]),
        ("same_report_one_side", (ts, mok, rp1), 1, ["同一箇所 5.1↔5.2（A-C）"]),
        ("same_same_final", (ts, m1), 1, ["A-C: 同一箇所なのに同じ最終番号"]),
        ("same_unknown_id", (ts, mab), 0, ["A-C: 同一箇所の一時IDが対応表に無い"]),
    ]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(*args)
        ok = rc == exp and all(h in buf.getvalue() for h in has)
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")

    # --findings: findings-log.jsonl の file/line から同一箇所の対象ペアを洗い出し、漏れをNG
    def fjson(path, rows):
        with open(path, "w", encoding="utf-8") as fh:
            for tid, fl in rows:
                fh.write(json.dumps({"tmp_id": tid, "file_line": fl}) + "\n")
        return path

    f_ok = fjson(
        os.path.join(d, "f_ok.jsonl"),
        [("A", "a.js:1-3"), ("B", "b.js:1"), ("C", "a.js:2-4")],
    )
    f_far = fjson(
        os.path.join(d, "f_far.jsonl"), [("A", "a.js:1-10"), ("C", "a.js:9-10")]
    )
    f_cut = fjson(  # B-Cは連鎖切断（ペア表にある）ので同一箇所の対象外
        os.path.join(d, "f_cut.jsonl"),
        [("A", "z.js:1"), ("B", "a.js:1-3"), ("C", "a.js:1-3")],
    )
    tno = os.path.join(d, "same_none.md")
    with open(tno, "w", encoding="utf-8") as fh:
        fh.write(tbl([("A", "B")], [("A", "B")]))
    th = os.path.join(d, "same_dot.md")
    with open(th, "w", encoding="utf-8") as fh:
        fh.write("| R1.1-R2.1 | x.js:1 | 同一箇所 |\n")
    mh = os.path.join(d, "same_dot.tsv")
    with open(mh, "w", encoding="utf-8") as fh:
        fh.write("R1.1\t5.1\nR2.1\t5.2\n")
    f_h = fjson(os.path.join(d, "f_h.jsonl"), [("R1-1", "x.js:1"), ("R2-1", "x.js:1")])
    many = [f"M{i}" for i in range(22)]
    tm, mm = os.path.join(d, "many.md"), os.path.join(d, "many.tsv")
    with open(tm, "w", encoding="utf-8") as fh:
        fh.write(
            "".join(
                f"| {a}-{b} | m.js:1 | 同一箇所 |\n"
                for a, b in itertools.combinations(many, 2)
            )
        )
    with open(mm, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{x}\t5.{i + 1}\n" for i, x in enumerate(many)))
    f_m = fjson(os.path.join(d, "f_m.jsonl"), [(x, "m.js:1") for x in many])
    for name, args, kw, exp, has in [
        ("findings_ok", (ts, mok), {"findings": f_ok}, 0, []),
        ("findings_lost", (tno, mok), {"findings": f_ok}, 1, ["A-C: 同一箇所の漏れ"]),
        (
            "findings_extra",
            (ts, mok),
            {"findings": f_far},
            0,
            ["findingsのfile/lineでは重ならない"],
        ),
        (
            "findings_emit",
            (tno, mok),
            {"findings": f_ok, "emit_same": True},
            1,
            ["| A-C | a.js:2-3 | 同一箇所 |"],
        ),
        ("findings_hyphen_id", (th, mh), {"findings": f_h}, 0, []),
        (
            "findings_hyphen_lost",
            (tno, mh),
            {"findings": f_h},
            1,
            ["R1.1-R2.1: 同一箇所の漏れ"],
        ),
        (
            "findings_missing_id",
            (ts, mok),
            {"findings": f_far},
            0,
            ["findingsに無い1件"],
        ),
        ("findings_cut_excluded", (tp, mok), {"findings": f_cut}, 0, []),
        ("findings_many", (tm, mm), {"findings": f_m}, 0, ["20組を超える"]),
        ("findings_without_tsv", (ts,), {"findings": f_ok}, 2, []),
        ("emit_without_findings", (ts, mok), {"emit_same": True}, 2, []),
    ]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(*args, **kw)
        ok = rc == exp and all(h in buf.getvalue() for h in has)
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    # 既存の連鎖切断だけの表では同一箇所の行を出さない（従来の出力のまま）
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(tp, mok, rp0)
    ok = rc == 0 and "同一箇所" not in buf.getvalue()
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] same_absent_unchanged: rc={rc} (期待0)")
    # --unwritten: 未執筆項目の一時IDに関わる「対応表に一時IDが無い」WARNだけを除外
    nc = os.path.join(d, "no_c.tsv")
    with open(nc, "w", encoding="utf-8") as fh:
        fh.write("A\t5.1\nB\t5.1\n")
    t2 = os.path.join(d, "t2.md")
    with open(t2, "w", encoding="utf-8") as fh:
        fh.write(
            tbl(
                [("A", "B"), ("B", "C"), ("D", "E")],
                [("A", "B"), ("D", "E")],
                [("B", "C")],
            )
            + "| C-E | x | 非統合 |\n"
        )
    m2 = os.path.join(d, "t2.tsv")
    with open(m2, "w", encoding="utf-8") as fh:
        fh.write("A\t5.1\nB\t5.1\nD\t5.2\n")
    miss = "対応表に一時IDが無い"
    for name, args, exp, has, hasnot in [
        ("unwritten_none", (tp, nc), 0, ["B-C: " + miss], ["未執筆"]),
        (
            "unwritten_c_cut",
            (tp, nc, None, ["C"]),
            0,
            ["（未執筆項目として除外: 1ペア。うち連鎖切断1組: B-C）"],
            [miss],
        ),
        (
            "unwritten_other_kept",
            (t2, m2, None, ["C"]),
            0,
            ["D-E: " + miss, "C-E: " + miss, "除外: 1ペア。うち連鎖切断1組: B-C）"],
            ["B-C: " + miss],
        ),
        (
            "unwritten_no_cut",
            (t2, m2, None, ["E"]),
            0,
            [
                "B-C: " + miss,
                "C-E: " + miss,
                "（未執筆項目として除外: 1ペア。うち連鎖切断0組）",
            ],
            ["D-E: " + miss],
        ),
        (
            "unwritten_unknown_id",
            (tp, nc, None, ["C", "Z"]),
            0,
            ["Z: --unwritten のIDがペア表に無い", "除外: 1ペア"],
            [miss],
        ),
        (
            "unwritten_in_tsv",
            (tp, mok, None, ["C"]),
            0,
            ["C: --unwritten のIDが対応表にある", "（未執筆項目として除外: 0ペア）"],
            ["うち連鎖切断"],
        ),
        (
            "unwritten_report_ok",
            (tp, nc, rp0, ["C"]),
            0,
            ["OK: 連鎖切断0組", "除外: 1ペア"],
            [miss],
        ),
        (
            "unwritten_report_ng_kept",
            (tp, mok, rp1, ["C"]),
            1,
            ["除外: 0ペア", "5.2が無い"],
            [],
        ),
        ("unwritten_without_tsv", (tp, None, None, ["C"]), 2, [], []),
    ]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(*args)
        out = buf.getvalue()
        ok = (
            rc == exp
            and all(h in out for h in has)
            and not any(h in out for h in hasnot)
        )
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    # 5c(c)の注記: 5.1が基準（検証方式に5c合成）。5.2は閉じフェンスの直後、5.3はフェンス内の末尾
    note = "(5.1の修正案に統合済み。本diffは単独で適用する場合の参考)"
    r5 = (
        "## 5. 指摘詳細\n\n### 5.1 [High] a\n\n**推奨される修正**\n\n"
        "全指摘の修正を合成した統合版である。\n\n```diff\n-a\n+b\n```\n\n"
        "**修正内容の解説**\n\n相手は5.2。\n\n**修正案の監査レビュー**\n\n"
        "| 検証方式 | 独立検証（5c合成diff） |\n\n"
        f"### 5.2 [High] b\n\n**推奨される修正**\n\n```diff\n-c\n+d\n```\n\n{note}\n\n"
        "**修正内容の解説**\n\n相手は5.1。\n\n"
        f"### 5.3 [Low] c\n\n**推奨される修正**\n\n```diff\n-e\n+f\n\n{note}\n"
        "(補足の1行)\n```\n\n**修正内容の解説**\n\nなし。\n\n## 6. リスク分析\n"
    )
    nob = r5.replace("合成した統合版", "x").replace("5c合成", "x")  # 基準の手がかり無し
    gone = r5.replace(f"\n\n{note}\n\n**", "\n\n**")  # 5.2の注記を削除
    n52 = r5.replace(f"\n{note}\n(", "\n(5.2の" + note[5:] + "\n(")  # 5.3の番号違い
    wide = r5.replace(f"{note}\n\n**", "（" + note[1:-1] + "）\n\n**")  # 全角括弧
    other = r5.replace(f"\n{note}\n(", "\n(5.1に統合済み)\n(")
    first = gone.replace("```diff\n-c", f"{note}\n\n```diff\n-c")  # diffの前
    mid = r5.replace(f"\n{note}\n(補足の1行)\n", f"\n{note}\n+g\n")  # 後にdiff行
    nodiff = r5.replace("```diff\n-c\n+d\n```", "要検討。")
    pos = "5c(c)の注記の文言か位置"
    fake = "合成した統合版にも含む。\n\n```diff\n-c"  # 非基準の節に基準の手がかり
    audit = "\n\n**修正案の監査レビュー**\n\n| 検証方式 | 5c合成diff |\n\n"
    allm = r5.replace("5.1。\n\n", "5.1。" + audit)  # 全節の検証方式に5c合成
    allm = allm.replace("なし。\n\n", "なし。" + audit)
    two = gone.replace(f"\n{note}\n(", "\n(5.2の" + note[5:] + "\n(")  # 5.3→5.2
    two = two.replace("5.1。\n\n", "5.1。" + audit)  # 5.1と5.2が基準
    selfref = r5.replace("+b\n```\n\n", f"+b\n```\n\n{note}\n\n")
    inner = r5.replace("-c\n+d", "-c\n### 5.9 [Low] z\n## 6. x\n+d")  # フェンス内
    # 外側が````のdiffに文脈行「 ```」（README.mdの変更など）。閉じは````だけ
    out4 = r5.replace("```diff\n-c\n+d\n```", "````diff\n-c\n ```\n+d\n````")
    # ~~~のdiffの中の```は閉じでない（5.2）。```のdiffの中の~~~も同じ（5.3、注記はフェンス内の末尾）
    tilde = r5.replace("```diff\n-c\n+d\n```", "~~~diff\n-c\n```\n+d\n~~~")
    tilde = tilde.replace("```diff\n-e", "```diff\n-e\n~~~")
    # 開きより短い```は閉じでない
    short = r5.replace("```diff\n-c\n+d\n```", "````diff\n-c\n```\n+d\n````")
    multi, nob5, zero = "基準指摘が複数見つかった（", "基準指摘を特定できない", "0件"
    for name, text, kw, exp, has in [
        ("c5_ok", r5, {}, 0, ["OK: 5c(c)の注記あり（基準5.1、2指摘）"]),
        ("c5_missing", gone, {}, 1, ["5.2: 推奨される修正のdiffの直後に"]),
        ("c5_wrong_number", n52, {}, 1, ["5.3: 5c(c)の注記の番号5.2が基準指摘（5.1）"]),
        ("c5_no_base", nob.replace(note, "x"), {}, 0, ["SKIP: 5c基準指摘なし"]),
        ("c5_wording_fullwidth", wide, {}, 1, ["5.2: " + pos]),
        ("c5_wording_other", other, {}, 1, ["5.3: " + pos]),
        ("c5_before_diff", first, {}, 1, ["5.2: " + pos]),
        ("c5_mid_fence", mid, {}, 1, ["5.3: " + pos]),
        ("c5_only_integrated", r5.replace("5c合成", "x"), {}, 0, ["基準5.1、2指摘"]),
        ("c5_base_opt", nob, {"base": ["5.1"]}, 0, ["基準5.1、2指摘"]),
        ("c5_base_opt_wrong", r5, {"base": ["5.2"]}, 1, ["5.1: 推", "番号5.1が"]),
        ("c5_base_opt_missing", r5, {"base": ["5.9"]}, 2, ["5.9 の見出しが無い"]),
        ("c5_not_merged", gone, {"notmerged": ["5.2", "5.8"]}, 0, ["、1指摘", "5.8: "]),
        ("c5_not_merged_num", n52, {"notmerged": ["5.3"]}, 1, ["番号5.2"]),
        ("c5_no_diff", nodiff, {}, 1, ["5.2: 推奨される修正にdiffが無い"]),
        ("c5_dup_heading", r5 + "### 5.2 [Low] d\n", {}, 2, ["5.2 の見出しが重複"]),
        ("c5_fake_base_noted", r5.replace("```diff\n-c", fake), {}, 0, ["基準5.1、2"]),
        ("c5_fake_base_missing", gone.replace("```diff\n-c", fake), {}, 0, [multi]),
        ("c5_all_marked", allm, {}, 0, ["OK: 5c(c)の注記あり（基準5.1、2指摘）"]),
        ("c5_all_marked_no_note", allm.replace(note, "x"), {}, 0, [multi, "!OK: 5c"]),
        ("c5_multi_base", two, {}, 0, [multi + "5.1, 5.2）", "!OK: 5c"]),
        ("c5_multi_base_opt", two, {"base": ["5.1", "5.2"]}, 0, ["基準5.1, 5.2、1"]),
        ("c5_notes_no_base", nob, {}, 0, [nob5, "!SKIP", "!OK: 5c"]),
        ("c5_zero", r5, {"notmerged": ["5.2", "5.3"]}, 0, [zero, "!OK: 5c"]),
        ("c5_self_ref_auto", selfref, {}, 0, [nob5]),
        ("c5_self_ref_opt", selfref, {"base": ["5.1"]}, 0, ["（自己参照）", "OK: 5c"]),
        ("c5_crlf", r5.replace("\n", "\r\n"), {}, 0, ["基準5.1、2指摘"]),
        ("c5_heading_in_fence", inner, {}, 0, ["基準5.1、2指摘"]),
        ("c5_fence_outer4_context", out4, {}, 0, ["OK: 5c(c)の注記あり（基準5.1、2指摘）"]),
        ("c5_fence_tilde_mix", tilde, {}, 0, ["OK: 5c(c)の注記あり（基準5.1、2指摘）"]),
        ("c5_fence_short_close", short, {}, 0, ["OK: 5c(c)の注記あり（基準5.1、2指摘）"]),
        (
            "c5_fence_outer4_missing",
            out4.replace(f"\n\n{note}\n\n**", "\n\n**"),
            {},
            1,
            ["5.2: 推奨される修正のdiffの直後に"],
        ),
    ]:
        rp = os.path.join(d, name + ".md")
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write(text)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(tp, mok, rp, None, kw.get("base"), kw.get("notmerged"))
        out = buf.getvalue()  # 「!」で始まる語は出力に無いこと
        ok = rc == exp and all(
            h[1:] not in out if h[0] == "!" else h in out for h in has
        )
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={rc} (期待{exp})")
    rp5 = os.path.join(d, "c5_ok.md")
    import subprocess

    for name, extra, exp in [
        ("cli_unwritten_ok", ["--unwritten", "C, X"], 0),
        ("cli_unwritten_bad_id", ["--unwritten", "C-D"], 2),
        ("cli_unwritten_empty", ["--unwritten", ","], 2),
        ("cli_unwritten_no_value", ["--unwritten"], 2),
        ("cli_base_ok", ["--report", rp5, "--base", "5.1"], 0),
        ("cli_base_bad_id", ["--report", rp5, "--base", "U1"], 2),
        ("cli_not_merged_ok", ["--not-merged", "5.2,5.3", "--report", rp5], 0),
        ("cli_not_merged_empty", ["--report", rp5, "--not-merged", ","], 2),
        ("cli_base_without_report", ["--base", "5.1"], 2),
    ]:
        r = subprocess.run(
            [sys.executable, os.path.abspath(__file__), tp, nc] + extra,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        opt = b"--base" if "base" in name or "merged" in name else b"--unwritten"
        ok = r.returncode == exp and (exp != 2 or opt in r.stdout)
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: rc={r.returncode} (期待{exp})")
    bp = os.path.join(d, "bad_utf8.md")
    open(bp, "wb").write(b"| X-Y | 1 \xff\xfe |\n")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = main(bp)
    ok = rc == 2
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] non_utf8: rc={rc} (期待2)")
    with contextlib.redirect_stdout(io.StringIO()):
        rc = main(os.path.join(d, "no_such.md"))
    ok = rc == 2
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] missing_file: rc={rc} (期待2)")

    # fence_step単体: 行の並びと、各行がフェンス行（開き・閉じ）か（1）中身・本文か（0）
    for name, seq, exp in [
        ("outer4_inner3", ["````diff", " ```", "-a", "````"], "1001"),
        ("outer3_space1_closes", ["```diff", " ```", "```"], "111"),
        ("tilde_inner_backtick", ["~~~", "```", "~~~"], "101"),
        ("backtick_inner_tilde", ["```", "~~~", "```"], "101"),
        ("short_close", ["````", "```", "````"], "101"),
        ("long_close", ["```", "`````", "```"], "111"),
        ("close_with_text", ["```", "``` x", "```  "], "101"),
        ("close_indent4", ["```", "    ```", "   ```"], "101"),
        ("open_indent4", ["    ```", "```"], "01"),
        ("open_space1", [" ```", "### x", "   ```"], "101"),
        ("inline_code", ["```x`y", "~~~x`y", "~~~"], "011"),
        ("two_backticks", ["``", "~~", "x"], "000"),
    ]:
        st, got = None, ""
        for ln in seq:
            isf, st = fence_step(ln, st)
            got += "1" if isf else "0"
        ok = got == exp
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] fence_{name}: {got} (期待{exp})")

    # 総当たり仕様実装との突合せ
    def spec(n, E):
        nodes, out = set(range(n)), []
        while True:
            seen, mg = set(), False
            for s in sorted(nodes):
                if s in seen:
                    continue
                comp, stk = set(), [s]
                while stk:
                    x = stk.pop()
                    if x not in comp:
                        comp.add(x)
                        stk += [y for y in nodes if y != x and frozenset((x, y)) in E]
                seen |= comp
                cl = [
                    set(c)
                    for k in range(len(comp), 1, -1)
                    for c in itertools.combinations(sorted(comp), k)
                    if all(frozenset(q) in E for q in itertools.combinations(c, 2))
                ]
                if not cl:
                    continue
                k = len(cl[0])
                top = [c for c in cl if len(c) == k]
                taken = set()
                for c in sorted(top, key=sorted):
                    if not (c & taken):
                        out.append(frozenset(c))
                        taken |= c
                        mg = True
            nodes -= set().union(*out) if out else set()
            if not mg:
                return set(out)

    rnd = random.Random(1)
    bad = 0
    for _ in range(300):
        n = rnd.randint(3, 9)
        pr = rnd.choice([0.2, 0.4, 0.6])
        E = {
            frozenset(e)
            for e in itertools.combinations(range(n), 2)
            if rnd.random() < pr
        }
        if set(derive(range(n), lambda x, y: frozenset((x, y)) in E)) != spec(n, E):
            bad += 1
    ok = bad == 0
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] random300_vs_bruteforce: mismatches={bad}")
    t = time.time()
    g = derive(range(22), lambda x, y: True)
    dt = time.time() - t
    ok = dt < 5 and [len(x) for x in g] == [22]
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] K22: {dt:.3f}s")
    print("SELF-TEST", "OK" if not fails else f"NG({fails})")
    return 1 if fails else 0


if __name__ == "__main__":
    av, rep, unw = sys.argv[1:], None, None
    if "--report" in av:  # --report 報告書.md（位置は問わない）
        i = av.index("--report")
        rep, av = (av[i + 1 : i + 2] or [""])[0], av[:i] + av[i + 2 :]
    if "--unwritten" in av:  # --unwritten ID1,ID2（位置は問わない）
        i = av.index("--unwritten")
        s, av = (av[i + 1 : i + 2] or [""])[0], av[:i] + av[i + 2 :]
        ids = [x.strip() for x in s.split(",") if x.strip()]
        # 空・不正なIDは使い方の誤り（""）
        unw = ids if ids and all(re.fullmatch(r"[\w.]+", x) for x in ids) else ""
    fnd, emit = None, False
    if "--findings" in av:  # --findings findings-log.jsonl（位置は問わない）
        i = av.index("--findings")
        fnd, av = (av[i + 1 : i + 2] or [""])[0], av[:i] + av[i + 2 :]
    if "--emit-same" in av:
        emit, av = True, [x for x in av if x != "--emit-same"]
    opt = {}
    for o in ("--base", "--not-merged"):  # 5.N,5.M（位置は問わない）
        if o in av:
            i = av.index(o)
            s, av = (av[i + 1 : i + 2] or [""])[0], av[:i] + av[i + 2 :]
            v = [x.strip() for x in s.split(",") if x.strip()]
            opt[o] = v if v and all(re.fullmatch(r"5\.\d+", x) for x in v) else ""
    if (
        av == ["--self-test"]
        and rep is None
        and unw is None
        and not opt
        and fnd is None
    ):
        sys.exit(self_test())
    sys.exit(
        main(
            av[0],
            av[1] if len(av) == 2 else None,
            rep,
            unw,
            opt.get("--base"),
            opt.get("--not-merged"),
            fnd,
            emit,
        )
        if len(av) in (1, 2)
        and rep != ""
        and unw != ""
        and fnd != ""
        and "" not in opt.values()
        else (
            print(
                "usage: check_5b_clique.py 表.md [対応表.tsv [--report 報告書.md"
                " [--base 5.N] [--not-merged 5.N,5.M]] [--unwritten ID1,ID2]"
                " [--findings findings-log.jsonl [--emit-same]]] | "
                "--self-test"
            )
            or 2
        )
    )
