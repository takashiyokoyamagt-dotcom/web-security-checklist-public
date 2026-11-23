#!/usr/bin/env python3
"""cvss-decisions.jsonl の機械的な完全性検査（標準ライブラリのみ。cvss依存なし）。
終了コード 0=OK / 1=NG（内部エラー・入力不正を含む。常に RESULT 行を出す）。
検査: 有効行数=採用件数 / 作業メモ行(st:memo)の存在 /
tmpの形式(一時IDの+連結)と対応表(--mapping)との一致 / 必須キー・型・列挙 /
規則タグ・borderline・dev・alt の整合 / altベクター=主ベクターの1メトリクス差 /
alt・帯・scoreの照合 / v3.1・v4.0 = raw出力 = 報告書6節 /
id重複・v3.1/v4.0の帯の食い違い（v4diff必須）。--fill-ids でid・rawを後埋め。
未使用フラグ（unused/unused_why）と並び順（同じ帯では未使用が末尾）。
seq/ts（連番・時刻）の単調性とメモ行→raw→確定行の時刻順（seq/tsが無い旧形式は--strictのときだけNG）。
値を上書きした指摘のrechk（再確認の記録）。
--report指定時、5節・6節のスコア・重大度・メトリクス値が記録と一致するか、
スコア欄の括弧の区分が計算の区分（0.0はNoneのまま。Lowへの読み替えは見出し・4節の重大度列だけ）と一致するか、
0.0の指摘があれば1節に「CVSS v3.1のスコアが0.0（None）のn件はLowに数えている」があるか、
6節の判定根拠が使い回しの定型文（同一指摘内の重複・指摘間の流用）ならNG/WARN、
同じ文が3指摘以上にあればWARN（文単位）。v4diff.whyがベクターの異なる指摘と同文ならWARN。
6節の判定根拠が非再現を理由にするのに7節に言及が無ければNG、7節・12節の陽性対照の記述の
食い違い・12節の「未検証」の欠落・条件を満たさないと自己申告した非再現の引き下げはWARN（A-5）。
5節の5dの4フィールド・攻撃シナリオの見出しで、です・ます調の文が過半の指摘はWARN（文体）。
S1-3の新ブロック「元の処理の意図と、修正による挙動の変化」「設計方針に従えない場合の代替案」も同じ基準。
修正内容の解説の直後の新ブロック「修正後に残るリスクと別経路」も同じ基準。
前提条件の確認 prem（任意。a〜fの6項目の[値 yes|no|unk|na, 根拠, 説明]。(e)(f)はnaにしない）がある行は、
形式（NG）と、yesの前提と矛盾しうる値（(a)AV:N・AC:L〔v4はAV:N・AT:N〕、(c)C:H／VC:H、(d)AC:L／AT:N、
(e)AV:N。v3.1とv4.0を別々に見る）で、--report時に6節の該当メトリクスの判定根拠に「前提(x)」が無いもの
をWARN（--reportなしは値だけでWARN）。yes/unkの「前提(x)」が6.Nのどこにも無い、premが一部の指摘に
だけある、もWARN。
--require-prem で prem の無い有効行をNG（新規実行用。prem の無い旧形式の記録は従来どおり）。
--append / --append-raw は、seq・tsを付けて記録へ追記する（--appendはCVSS-JUDGEのreasons行を読み飛ばす。
記録にあるreasons行も検査では無視する）。--self-test で自己検査。
--append は確定行のrevが同じtmpの作業メモ行の最大rev以下、作業メモ行のrevが同じtmpの
既存行の最大rev以下なら拒否する（--finalでは履歴行をWARN）。
Python 3.9以上で動く（`--final`・`--append`・`--fill-ids`を3.9でも確認済み）。
"""

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

try:
    import fcntl
except ImportError:  # Windows等はロック無し（並列に呼ばない）
    fcntl = None  # type: ignore[assignment]

V3 = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "NLH",
    "I": "NLH",
    "A": "NLH",
}
BASE_K = "tmp cat cwe type v3 v4 m3 v4map dev borderline by rev st".split()
FINAL_K = "id grp band sbs attn calc raw".split()
TAGS = ("default", "表:", "原則:", "迷:", "例外:", "逸脱:")
# NGメッセージ用のヒント（実運用で詰まった点。docs/HISTORY.md 43節）
TMP_HINT = "tmpは5bの一時ID（対応表TSVの第1列）を昇順に+で連結した形で、群の作業用ID（F12等）ではない"
TAG_HINT = (
    "許される接頭辞: default / 表:<行名> / 原則:<名> / 迷: / 例外: / 逸脱: のいずれかで始める"
    "（「例:」は不可。PR例外・AC/AT規則は「例外:」）"
)
HYPHEN_HINT = (
    "ハイフン入りの一時IDは、ハイフンを除いた形（make_idmap.py --strip-hyphen と同じ。"
    "ペア表・群表・tmpとも）で書く"
)
BORDER_HINT = (
    'borderlineはメトリクス名の文字列の配列（例: ["I"]。[["I",{...}]]の形は不可）。'
    "別案は m3.<メトリクス> の5番目の要素に辞書 {alt,score,why} で書く"
)
EVID = re.compile(
    r"^(grep:.+|\S+:\d+(-\d+)?(,\d+(-\d+)?)*)$"
)  # file:line / a.js:9,10 / C:\\x\\a.js:9
UNCALC = "未算出"
V4M = re.compile(
    r"(?<![A-Za-z])(AV|AC|AT|PR|UI|VC|VI|VA|SC|SI|SA)(?![A-Za-z])"
)  # v4diff.whyに必要なv4メトリクス名


def band_of(sev):
    return (
        "Low" if sev == "None" else sev
    )  # v3.1のNone区分(0.0)は規則により帯Low（cvss-scoring.md）


def load(p):
    try:
        lines = open(p, encoding="utf-8-sig").read().split("\n")
    except UnicodeDecodeError:
        return None, [f"{p}: UTF-8として読めない"]
    except OSError as e:
        return None, [f"{p}: 読めない ({e})"]
    out, ng = [], []
    for n, l in enumerate(lines, 1):
        if l.strip():
            try:
                o = json.loads(l)
                if isinstance(o, dict):
                    out.append((n, o))
                else:
                    ng.append(f"{p} L{n}: JSONオブジェクトでない")
            except ValueError as e:
                ng.append(f"{p} L{n}: JSON不正 ({e})")
    return out, ng


def vec(s):
    return dict(x.split(":", 1) for x in s.split("/")[1:])


def sc(v, k):  # 採用スコアと帯（環境メトリクスがあればそちら）
    if not isinstance(v, dict) or "vector" not in v or "error" in v:
        return None  # 算出エラー出力はvectorとerrorの両方を持つ
    if "environmental_score" in v:
        return v["environmental_score"], v.get("environmental_severity")
    return v.get(k), v.get("base_severity")


BASEK = ("CVSS",) + tuple(V3)


def basepart(s):  # 環境メトリクス(CR/IR/AR/MAV等)を除いたベクター部分
    return [x for x in str(s).split("/") if x.split(":", 1)[0] in BASEK]


BANDS = ("Critical", "High", "Medium", "Low")
REVST = {"final": "確定行のrevがメモ行以下", "memo": "作業メモ行のrevが先行行以下"}
RECHK = ("reason", "body", "sections", "rank", "flags")
# 前提条件の確認（cvss-scoring.md「前提条件の確認」）。yes＝評価を制約する前提が有る
PREM = {
    "a": "開発依存・ビルド時のみ",
    "b": "防御となる既存の仕組み",
    "c": "値が既に公開済み",
    "d": "攻撃者が引き起こせない条件",
    "e": "ホスト／ローカル侵入が前提",
    "f": "将来の付け忘れを仮定",
}
PREM_VALS = ("yes", "no", "unk", "na")
PREM_HINT = (
    'premは{"a":["yes","package.json:41","devDependenciesのみ"],…,"f":[…]}の形'
    "（a〜fの6項目。値はyes|no|unk|na、yes/noの根拠はfile:lineかgrep:式、"
    "yes/unkは説明を書く）"
)
UNUSED_MSG = "現状は未使用のため実質問題なし"
ROW = r"^\| ([A-Z]{1,2})（[^|]*\| [A-Z] \| ([^|]+) \|$"  # 6節のメトリクス行
DUP_NG_LEN, DUP_WARN_LEN, DUP_SIM = 40, 20, 0.9  # 判定根拠の重複検査の閾値


def parse_ts(s):
    if not isinstance(s, str):
        return None
    if not re.search(r"\d:\d\d", s):  # 日付のみは不可（時刻まで必須）
        return None
    try:
        d = datetime.datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)


def stamps(name, rows, strict, ng, warn):
    """全行のseq（増加する整数）とts（ISO 8601、追記順に非減少）。{行番号: 時刻}を返す"""
    out = {}
    if not any("seq" in r or "ts" in r for _, r in rows):
        if rows:
            (ng if strict else warn).append(
                f"{name}: seq/tsが無い（旧形式。判定直後の即時追記かを時刻で検証できない）"
            )
        return out
    ls = lt = None
    for n, r in rows:
        s, t = r.get("seq"), parse_ts(r.get("ts"))
        if not isinstance(s, int) or isinstance(s, bool) or t is None:
            ng.append(f"{name} L{n}: seq（整数）とts（ISO 8601）が全行に必要")
            continue
        if s != (ls or 0) + 1:
            ng.append(
                f"{name} L{n}: seq {s} が{(ls or 0) + 1}でない（1始まりの欠番なし連番）"
            )
        if lt is not None and t < lt:
            ng.append(f"{name} L{n}: tsが直前の行より前（追記順に時刻が進むこと）")
        ls, lt, out[n] = s, t, t
    return out


def timing(dec, raw, eff, rawline, strict, ng, warn):
    """メモ行→raw→確定行の時刻順と、全行が短時間に集中していないか（後者はWARNのみ）"""
    dts = stamps("decisions", dec, strict, ng, warn)
    rts = stamps("raw", raw, strict, ng, warn)
    if not dts:
        return
    fm = {}
    for n, r in dec:
        if r.get("st") == "memo" and n in dts:
            fm.setdefault(r.get("tmp"), dts[n])
    gaps = []
    for t, (n, r) in sorted(eff.items()):
        if r.get("st") != "final" or n not in dts or t not in fm:
            continue
        if dts[n] < fm[t]:
            ng.append(f"{t}: 確定行のtsが最初の作業メモ行より前")
        rt = rts.get(rawline.get(t))
        if rt is not None and not fm[t] <= rt <= dts[n]:
            ng.append(f"{t}: メモ行→raw出力→確定行の時刻順でない")
        gaps.append((dts[n] - fm[t]).total_seconds())
    if len(dts) >= 10:
        span = (max(dts.values()) - min(dts.values())).total_seconds()
        if span < 3 * len(dts):
            warn.append(
                f"decisionsの{len(dts)}行が{span:.0f}秒に集中（判定ごとの即時追記でなく事後一括生成の疑い）"
            )
    if len(gaps) >= 10 and sum(g < 5 for g in gaps) >= 0.8 * len(gaps):
        warn.append(
            "作業メモ行と確定行がほぼ同時刻の指摘が8割以上（判定直後の追記でなく事後生成の疑い）"
        )


def rechk_check(dec, eff, final, strict, ng, warn):
    """Arbiterが値（v3/v4ベクター）を上書きした指摘には、再確認の記録rechkが要る"""
    hist = {}
    for _, r in dec:
        if is_reasons(r):
            continue
        t, rv = r.get("tmp"), r.get("rev", 1)
        if isinstance(t, str) and isinstance(rv, int) and not isinstance(rv, bool):
            hist.setdefault(t, {})[rv] = r
    vals = lambda x: (x.get("v3"), x.get("v4"))
    for t, revs in sorted(hist.items()):
        if not final or t not in eff:
            continue
        ks = sorted(revs)
        changed = any(
            revs[b].get("by") == "arbiter" and vals(revs[a]) != vals(revs[b])
            for a, b in zip(ks, ks[1:])
        )
        rc = eff[t][1].get("rechk")
        if changed and rc is None:
            (ng if strict else warn).append(
                f"{t}: Arbiterが値を上書きしたがrechk（再確認の記録）が無い"
            )
        elif changed and (not isinstance(rc, list) or set(RECHK) - set(rc)):
            ng.append(f"{t}: rechkは{'/'.join(RECHK)}を全て含む配列")


def dup_pairs(rows):
    """[(メトリクス, 空白除去した文)]のうち、完全一致か類似度DUP_SIM以上の組と短い方の長さ"""
    out = []
    for (a, x), (b, y) in itertools.combinations(rows, 2):
        m = min(len(x), len(y))
        if m < DUP_WARN_LEN:
            continue
        sm = difflib.SequenceMatcher(None, x, y, autojunk=False)
        if x == y or (
            sm.real_quick_ratio() >= DUP_SIM
            and sm.quick_ratio() >= DUP_SIM
            and sm.ratio() >= DUP_SIM
        ):
            out.append((a, b, m))
    return out


def facts_check(eff, warn):
    """m3の「その行が示す事実」（短文）の使い回し。WARNのみ"""
    tot, dist = 0, set()
    for t, (n, r) in sorted(eff.items()):
        m3 = r.get("m3")
        if not isinstance(m3, dict):
            continue
        rows = [
            (m, re.sub(r"\s+", "", str(e[2])))
            for m, e in m3.items()
            if isinstance(e, list) and len(e) >= 3
        ]
        tot += len(rows)
        dist |= {x for _, x in rows}
        dp = dup_pairs(rows)
        if dp:
            warn.append(
                f"{t}: m3の事実が別メトリクスで重複（{dp[0][0]}と{dp[0][1]}ほか{len(dp)}組）"
            )
    if tot >= 40 and len(dist) / tot < 0.5:
        warn.append(f"m3の事実が使い回し（{tot}件中{len(dist)}通り）")


def order_check(eff, ng, warn):
    """5.Nの並び: 重大度の帯の降順（WARN）、同じ帯では未使用の指摘が末尾（NG）"""
    order, seen_u = [], set()
    for t, (n, r) in eff.items():
        m = re.fullmatch(r"5\.(\d+)", str(r.get("id", "")))
        if m and r.get("band") in BANDS:
            order.append((int(m.group(1)), t, r))
    order.sort(key=lambda x: x[0])
    for (_, _, a), (_, t, b) in zip(order, order[1:]):
        if BANDS.index(b["band"]) < BANDS.index(a["band"]):
            warn.append(f"{t}: 重大度順になっていない（{a['band']}の後に{b['band']}）")
    for _, t, r in order:
        if r.get("unused"):
            seen_u.add(r["band"])
        elif r["band"] in seen_u:
            ng.append(
                f"{t}: 同じ帯{r['band']}の未使用の指摘より後ろに使用中の指摘がある"
            )


def sect(txt, num):
    """`### {num}.N ` 見出しごとの{N: (見出し行, 本文)}。本文は次の見出し（#〜###）まで"""
    out, nxt = {}, re.compile(r"^#{1,3} ", re.M)
    for m in re.finditer(rf"^### {num}\.(\d+) .*$", txt, re.M):
        e = nxt.search(txt, m.end())
        out[m.group(1)] = (m.group(0), txt[m.end() : e.start() if e else len(txt)])
    return out


GROUPS = ({"C", "I", "A"}, {"VC", "VI", "VA"}, {"SC", "SI", "SA"})  # 対をなす影響欄
TAG = re.compile(r"^(基準からの逸脱|迷|例外|逸脱)[:：]|（根拠[:：][^）]*）")


def reasons_check(s6, ng, warn):
    """6節の判定根拠の重複。同一指摘内の別メトリクス、指摘間の流用、全体の多様性。
    比較前に規則タグの接頭辞と「（根拠: …）」を除く。C/I/A等の対同士はNGにしない"""
    tot, use, short = 0, {}, []
    for k, (_, body) in sorted(s6.items(), key=lambda x: int(x[0])):
        for ver, part in zip(
            ("v3.1", "v4.0"), re.split(r"^\*\*CVSS v4\.0\*\*", body, flags=re.M)
        ):
            rows = [(m, re.sub(r"\s+", "", x)) for m, x in re.findall(ROW, part, re.M)]
            tot += len(rows)
            for _, x in rows:
                use.setdefault(x, set()).add(k)
            for a, b, ln in dup_pairs([(m, TAG.sub("", x)) for m, x in rows]):
                pair = any({a, b} <= g for g in GROUPS)
                if ln >= DUP_NG_LEN and not pair:
                    ng.append(
                        f"6.{k}（{ver}）: {a}と{b}の判定根拠が同一/ほぼ同一（{ln}字以上）。"
                        "そのメトリクス固有の帰結（何が起きる/起きないか）で書く"
                    )
                elif k not in short:
                    short.append(k)
    if short:
        warn.append(
            f"別メトリクスで似た判定根拠がある指摘: {len(short)}件（6.{short[0]}ほか）"
        )
    rep = sorted(
        ((len(v), x) for x, v in use.items() if len(v) >= 4 and len(x) >= 15),
        reverse=True,
    )
    if rep:
        warn.append(
            "同じ判定根拠を4指摘以上で流用: "
            + "、".join(f"「{x[:16]}…」{c}指摘" for c, x in rep[:3])
        )
    if tot >= 40:
        if len(use) / tot < 0.6:
            ng.append(
                f"判定根拠が定型化（{tot}行中{len(use)}通り。指摘ごとに書き直す）"
            )
        elif len(use) / tot < 0.85:
            warn.append(f"判定根拠の流用が多い（{tot}行中{len(use)}通り）")


SENT_LEN, SENT_FIND = 20, 3  # 文単位の流用（WARN）: 正規化後の文長・指摘数の下限
OPEN_BR, CLOSE_BR = "（「『【［(", "）」』】］)"
ALNUM = re.compile(r"[0-9A-Za-z０-９Ａ-Ｚａ-ｚ]")


def sentences(cell):
    """判定根拠セルを文に分ける。「。」と、英数字が続かない「．！？」で切る。
    括弧と`コード`の中では切らない"""
    out, st, depth, code = [], 0, 0, False
    for i, ch in enumerate(cell):
        if ch == "`":
            code = not code
        elif code:
            continue
        elif ch in OPEN_BR:
            depth += 1
        elif ch in CLOSE_BR:
            depth = max(depth - 1, 0)
        elif depth == 0 and (
            ch == "。" or (ch in "．！？" and not ALNUM.match(cell, i + 1))
        ):
            out.append(cell[st : i + 1])
            st = i + 1
    return out + [cell[st:]]


def sent_key(s):  # 比較用: 全角半角(NFKC)・空白・末尾の句点を揃える
    s = re.sub(r"\s+", "", unicodedata.normalize("NFKC", s))
    return re.sub(r"[。.]+$", "", s)


def cut(s, n):
    return s[:n] + ("…" if len(s) > n else "")


def sentence_reuse(s6, warn):
    """6節の判定根拠の同じ文（SENT_LEN字以上）がSENT_FIND指摘以上にあればWARN。
    同じ指摘の中の重複（v3.1とv4.0の対応メトリクス等）は1指摘と数える"""
    use = {}  # 正規化した文 -> (最初の原文, {指摘: ["版 メトリクス"]})
    for k, (_, body) in sorted(s6.items(), key=lambda x: int(x[0])):
        for ver, part in zip(
            ("v3.1", "v4.0"), re.split(r"^\*\*CVSS v4\.0\*\*", body, flags=re.M)
        ):
            for m, x in re.findall(ROW, part, re.M):
                for s in sentences(TAG.sub("", x.strip())):
                    key = sent_key(s)
                    if len(key) >= SENT_LEN:
                        e = use.setdefault(key, (s.strip(), {}))[1].setdefault(k, [])
                        e += [] if f"{ver} {m}" in e else [f"{ver} {m}"]
    rep = [x for x in use.values() if len(x[1]) >= SENT_FIND]
    rep.sort(key=lambda x: -len(x[1]))  # 安定ソート: 同数なら6節での出現順
    if not rep:
        return

    def show(s, v):  # 文は40字・4指摘・1指摘あたり2欄まで（1行の長さを抑える）
        at = [
            f"6.{k}({'/'.join(ms[:2])}{'等' if len(ms) > 2 else ''})"
            for k, ms in v.items()
        ]
        more = f"ほか{len(at) - 4}指摘" if len(at) > 4 else ""
        return f"「{cut(s.rstrip('。．'), 40)}」{'・'.join(at[:4])}{more}"

    more = f"／ほか{len(rep) - 3}文" if len(rep) > 3 else ""
    warn.append(
        f"判定根拠の文単位の流用（同じ文が{SENT_FIND}指摘以上。{len(rep)}文）: "
        + "／".join(show(s, v) for s, v in rep[:3])
        + f"{more}。指摘ごとに事実を入れて書き直す"
    )


BASE4 = BASEK + ("AT", "VC", "VI", "VA", "SC", "SI", "SA")  # v3.1・v4.0の基準メトリクス


def why_reuse(eff, warn):
    """確定行のv4diff.whyが、基準ベクター（環境メトリクス等を除く）の異なる指摘と
    同じ文字列ならWARN。ベクターが同じ指摘どうしの同文は事実も同じなので数えない"""
    use = {}  # why -> {(v3, v4の基準部分): [id]}
    for t, (_, r) in sorted(eff.items()):
        vd = r.get("v4diff")
        w = vd.get("why") if isinstance(vd, dict) else None
        if r.get("st") == "final" and isinstance(w, str) and w.strip():
            vs = tuple(
                tuple(x for x in str(r.get(k)).split("/") if x.split(":")[0] in BASE4)
                for k in ("v3", "v4")
            )
            use.setdefault(w, {}).setdefault(vs, []).append(str(r.get("id") or t))
    rep = [(w, [i for xs in g.values() for i in xs]) for w, g in use.items()]
    rep = [x for x in rep if len(use[x[0]]) >= 2]
    rep.sort(key=lambda x: -len(x[1]))
    if not rep:
        return

    def show(w, xs):
        xs = sorted(xs, key=lambda s: (len(s), s))  # 5.9は5.10より前
        more = f"ほか{len(xs) - 4}指摘" if len(xs) > 4 else ""
        return f"{'・'.join(xs[:4])}{more}「{cut(w, 30)}」"

    more = f"／ほか{len(rep) - 3}組" if len(rep) > 3 else ""
    warn.append(
        "v4diff.whyの流用（ベクターの異なる指摘が同文）: "
        + "／".join(show(w, xs) for w, xs in rep[:3])
        + f"{more}。事実（スコア・メトリクス）を指摘ごとに入れて書き直す"
    )


NONREPRO = re.compile(
    r"再現せず|再現できな|再現しなかった|起きなかった|成立しなかった|発動しなかった"
    r"|停止しなかった|プロセスは生存|実機.{0,10}(?:確認|試験).{0,20}(?:なかった|せず)"
    r"|汚染(?:し|され)なかった|書き換え(?:なかった|られなかった)"
)  # 非再現を理由にした語（A-5）
NONREPRO_P = re.compile(r"再現しない")  # 実機・PoC・Arbiterの語と同じセルのときだけ
POC_CTX = re.compile(r"実機|PoC|Arbiter")
NONREPRO_W = re.compile(
    r"影響は観測|観測されなかった"
)  # 弱い語。実機等の語と共にあるときだけ
REPRO_CTX = re.compile(r"実機|Arbiter|再現|記録#?\d|original-app-reproduction")
ROWV = r"^\| ([A-Z]{1,2})（[^|]*\| ([A-Z]) \| ([^|]+) \|$"  # ROWに値を加えた形
IMPACT = {"C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA"}
PC_NEG = "無い 無く 無し 無か ない なく なし なか 取れていな 取っていな 取れず 取らず"
PC_NEG += " 実行していな 実施していな 行っていな 未実施 未取得"
PC_POS = "取って 取った 取り 取れた 取得し 用意し ある あり 確認済 実施し 実行し"
PC_NOT = re.compile(r"み?(?:ていな|ておらず|おらず|いな|ず|ません|ではな|でな|ない)")
REF = re.compile(r"(?<![\d.])[56]\.(\d+)(?!\d|\.\d)")  # 5.N/6.N（版番号6.5.1等は除く）
NOTREF = re.compile(
    r"(?:Critical|High|Medium|Low|スコア|CVSS|(?<![A-Za-z])[vV])[\s:：（(]{0,2}$"
)
WORD = re.compile(  # 英小文字の語（パッケージ名等）。ファイル名（a.js）・a.b形式は除く
    r"(?<![A-Za-z0-9_./-])[a-z][a-z0-9_-]*[a-z0-9](?![A-Za-z0-9_/-]|\.[A-Za-z])"
)
STOPW = set(  # 主題の比較で数えない一般語
    "multipart http https npm node grep json true false null name body id express"
    " query params req res app user users admin login api url path file error err"
    " status get post".split()
)
SELFNG = re.compile(  # 条件N・N条件・3つの条件を満たさない（否定形だけ）
    r"(?:条件[1-3１-３]|[1-3１-３]つ?の?条件)[^。]{0,20}?"
    r"(?:満たしていな|満たさ|満たせ(?:ず|な))"
)
NRKEY = re.compile(r"再現できなかった|再現しなかった|非再現")  # 7節の項の見出しの語
END7 = re.compile(  # 7節の既知の見出し（項の終わり）
    r"^(?:#{2,3} |\*\*(?:Blue Team|参照0件|判定に迷い|7\.\d))", re.MULTILINE
)


def chap(txt, num):
    """`## {num}. ` の章の本文（次の`## `まで）。無ければ空"""
    m = re.search(rf"^## {num}\. .*$", txt, re.MULTILINE)
    if not m:
        return ""
    e = re.compile(r"^## ", re.MULTILINE).search(txt, m.end())
    return txt[m.end() : e.start() if e else len(txt)]


def blocks(text):
    """段落・箇条書きの項目・太字で始まる行を単位に分ける（継続行は連結）"""
    out = []
    for ln in text.split("\n"):
        if not ln.strip() or re.match(r"\s*(?:[-*+] |\d+\. |\*\*)", ln) or not out:
            out.append("")
        out[-1] += ln.strip()
    return [b for b in out if b]


def refs(s):
    """指摘番号（5.N/6.N）の集合（"5.N"に揃える）。重大度・スコア・CVSS・vの後の数値と、
    「5.3/Medium」は除く（「5.16/5.25」は両方数える）"""
    return {
        "5." + m.group(1)
        for m in REF.finditer(s)
        if not re.match(r"/[A-Za-z]", s[m.end() : m.end() + 2])
        and not NOTREF.search(s[max(m.start() - 12, 0) : m.start()])
    }


def topics(s):
    s = re.sub(r"\]\(#[^)]*\)", "]", s)  # 目次リンクのアンカーは語に数えない
    return refs(s) | {w for w in WORD.findall(s) if w not in STOPW}


def pc_polarity(s, i):
    """s[i:]が「陽性対照」の直後。有ならTrue、無ならFalse、読めなければNone。
    括弧の補足を飛ばし、助詞の後14字で最初に現れる語（同じ位置なら長い語）で決める"""
    w = re.sub(r"^（[^）]{0,60}）", "", s[i : i + 90])
    if w[:1] not in ("は", "が", "を", "に", "も"):
        return None
    wl = w.split("。")[0]
    w = wl[:14]
    hit = [
        (w.find(t), -len(t), p, t)
        for p, ts in ((False, PC_NEG), (True, PC_POS))
        for t in ts.split()
        if t in w
    ]
    if not hit:
        return None
    j, _n, p, t = min(hit)
    return p and not PC_NOT.match(
        wl, j + len(t)
    )  # 肯定の語の直後の否定（取っておらず等）


def pc_claims(text, lead=True):
    """陽性対照の有無の記述: [(有か, 主題（その文の番号・語。leadなら項目の先頭文の分も）,
    文, 項目)]"""
    out = []
    for b in blocks(text):
        ss = sentences(b)
        for s in ss:
            for m in re.finditer("陽性対照", s):
                p = pc_polarity(s, m.end())
                if p is not None:
                    tp = topics(s) | (topics(ss[0]) if lead else set())
                    out.append((p, tp, s.strip(), b))
    return out


def nr_scope(t7):
    """7節の「実機で再現できなかった主張」の項（太字だけの見出し行から、7節の既知の見出しか
    次の##/###まで）。無ければ7節全体。行ごとに見る（閉じない太字行でも線形）"""
    pos = 0
    for ln in t7.split("\n"):
        x = ln.rstrip()
        if x.startswith("**") and x.endswith("**") and len(x) > 4 and NRKEY.search(x):
            e = END7.search(t7, pos + len(ln))
            return t7[pos : e.start() if e else len(t7)]
        pos += len(ln) + 1
    return t7


def nonrepro_cells(s6):
    """6節の判定根拠で非再現を理由にした語のあるセル: [(N, "v3.1 AC", 引き下げ側か)]。
    引き下げ側の値（AC:H・AT:P・影響のL/N）のセルか、実機・再現等の語を含むセルに限る。
    「影響は観測されていない」等の弱い語は実機・再現等の語、「再現しない」は実機・PoC・
    Arbiterの語を含むセルだけ。限界: 「〜にならなかった」型（エラーにならなかった等）は検出しない"""
    out = []
    for k, (_, body) in sorted(s6.items(), key=lambda x: int(x[0])):
        for ver, part in zip(
            ("v3.1", "v4.0"), re.split(r"^\*\*CVSS v4\.0\*\*", body, flags=re.MULTILINE)
        ):
            for m, v, x in re.findall(ROWV, part, re.MULTILINE):
                down = (m, v) in (("AC", "H"), ("AT", "P")) or (
                    m in IMPACT and v in ("L", "N")
                )
                ctx = REPRO_CTX.search(x)
                if (
                    (NONREPRO.search(x) and (down or ctx))
                    or (NONREPRO_W.search(x) and ctx)
                    or (NONREPRO_P.search(x) and POC_CTX.search(x))
                ):
                    out.append((k, f"{ver} {m}", down))
    return out


def repro_check(txt, ng, warn):
    """A-5の6・7・12節の整合。6節の非再現を理由にした根拠が7節で言及されなければNG。
    7節と12節の陽性対照の有無の食い違い、12節の「未検証」の欠落、条件を満たさないと
    自己申告した非再現の引き下げへの使用はWARN。戻り値は表示用の該当セルの一覧"""
    hits = nonrepro_cells(sect(txt, 6))
    t7, t12 = chap(txt, 7), chap(txt, 12)
    seen = refs(nr_scope(t7))
    by = {}
    for k, cell, _ in hits:
        by.setdefault(k, []).append(cell)
    if by and not re.search(r"^## 7\. ", txt, re.MULTILINE):
        ng.append(
            f"7節の見出し（`## 7. `）が見つからない。非再現を理由にした6.{next(iter(by))}等の"
            "7節での言及を確かめられない（A-5）"
        )
        by = {}
    for k, cells in by.items():
        if "5." + k not in seen:
            ng.append(
                f"6.{k}: 判定根拠（{'・'.join(cells)}）が非再現を理由にしているが、7節に言及が無い"
                f"（A-5。7節「実機で再現できなかった主張」に5.{k}・送った入力・陽性対照の有無を書く）"
            )
    c7, c12 = pc_claims(t7), pc_claims(t12, lead=False)
    bad = [
        (sorted(a[1] & b[1]), a[2], b[2])
        for a in c7
        for b in c12
        if a[0] != b[0] and a[1] & b[1]
    ]
    if bad:
        w, s7, s12 = bad[0]
        warn.append(
            f"7節と12節で陽性対照の有無の記述が食い違う（A-5。{len(bad)}組。"
            f"{'・'.join(w[:3])}: 7節「{cut(s7, 40)}」／12節「{cut(s12, 40)}」）。"
            "条件2を満たすかを確かめ、両節の記述を揃える"
        )
    if "未検証" not in t12 and any(not c[0] for c in c7):
        warn.append(
            "7節に陽性対照が無いと書いた非再現があるが、12節に「未検証」の記載が無い（A-5）"
        )
    own = set()  # 条件を満たさないと自己申告した7節の項目の指摘番号
    for b in blocks(t7):
        if SELFNG.search(b) or any(not c[0] for c in pc_claims(b)):
            own |= refs(b)
    used = [f"6.{k}({cell})" for k, cell, down in hits if down and "5." + k in own]
    if used:
        warn.append(
            "7節で陽性対照が無い／条件を満たさないとされた非再現が、6節で引き下げの根拠に"
            "使われている（A-5。人間が確認）: "
            + "・".join(used[:4])
            + (f"ほか{len(used) - 4}欄" if len(used) > 4 else "")
        )
    return [f"6.{k}({cell})" for k, cell, _ in hits]


def harm_text(body, name="実害の有無"):
    """見出し「**{name}…**」の直下から、次の見出し風の行（`**…**`だけの行）までの本文。
    見出しの直後の最初の本文行は、全体が太字でも本文として扱う"""
    hm = re.search(rf"^\*\*{re.escape(name)}[^*\n]*\*\*[ \t]*\n", body, re.MULTILINE)
    if not hm:
        return ""
    rest = body[hm.end() :]
    eol = rest.find("\n", len(rest) - len(rest.lstrip()))
    first = eol if eol >= 0 else len(rest)
    nxt = re.compile(r"^\*\*[^\n]*\*\*[ \t]*$", re.M).search(rest, first)
    return rest[: nxt.start() if nxt else len(rest)]


STYLE_FIELDS = {  # 5d補足（文体）の対象（見出しの前方一致）: 表示用の略称
    "わかりやすい解説": "わかりやすい",
    "技術的詳細解説": "技術的詳細",
    "修正内容の解説": "修正内容",
    "該当コードの問題点": "問題点",
    "攻撃シナリオ": "攻撃シナリオ",
    # S1-3の新ブロック（修正内容の解説の後の太字だけの行で始まる別ブロック）
    "元の処理の意図と、修正による挙動の変化": "元の処理の意図",
    "設計方針に従えない場合の代替案": "代替案",
    # 修正内容の解説の直後の新ブロック（太字だけの行で始まる別ブロック）
    "修正後に残るリスクと別経路": "残るリスク",
}
DESU = re.compile(  # 文末の括弧の補足・句点を除いた後で照合。なりすます・冷ます等は除く
    r"(?:です|(?<![す励冷覚醒済悩澄さ飲])ます|でした|ました|ません|でしょう"
    r"|ください|ましょう)か?$"
)
TAIL_LEN, TAIL_END = 300, " 。．.！!？?"  # 文末の判定に使う末尾の字数・除く文字


def tail(s):
    """文末の句点等と、末尾の括弧の補足（入れ子可）を除いた文（末尾TAIL_LEN字だけを見る）"""
    s = s[-TAIL_LEN:].rstrip(TAIL_END)
    while s.endswith(("）", ")")):
        depth = 0
        for i in range(len(s) - 1, -1, -1):
            depth += (s[i] in "）)") - (s[i] in "（(")
            if depth == 0:
                break
        if depth:  # 対応しない括弧
            break
        s = s[:i].rstrip(TAIL_END)
    return s


# コードフェンスの行（CommonMark）: 行頭の空白0〜3文字＋同じ文字（`か~）3個以上＋残り
FENCE = re.compile(r"( {0,3})(`{3,}|~{3,})(.*)$")


def fence_step(ln, open_):
    """CommonMarkに沿ってコードフェンスの開閉を1行ずつ判定する。
    open_ は開いているフェンスの(文字, 個数)、外ならNone。(この行がフェンス行か, 次のopen_)を返す。
    開き: 行頭の空白0〜3文字＋```か~~~（3個以上）＋任意の情報文字列（```の情報文字列に`は不可）。
    閉じ: 開きと同じ文字で、同じかそれ以上の個数＋空白のみ（行頭の空白は3文字以内）。
    フェンスの中で閉じにならない行（外側が````の中の```、diffの文脈行の「 ```」、~~~の中の```、
    開きより短い```）は中身として扱う。フェンスの外の「 ```」（空白1つ）は開きになる。
    限界: リスト・引用の中のフェンス（行頭の空白4文字以上・「> 」付き）はフェンスとして数えない"""
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


def prose(text):
    """コードブロック・引用（>）・表（|）の行を除き、インラインコードを伏せた本文。
    コードフェンスの開閉はCommonMarkに沿う（fence_step）"""
    out, fence = [], None
    for ln in text.split("\n"):
        s = ln.lstrip()
        isfence, fence = fence_step(ln, fence)
        if isfence:
            pass
        elif not fence and not s.startswith((">", "|")):
            out.append(re.sub(r"`[^`\n]*`", "コード", ln))
    return "\n".join(out)


def style_check(s5, warn):
    """5節の各指摘のSTYLE_FIELDSの見出しごとに、です・ます調の文末の文が過半（かつ2文以上）
    ならその指摘をWARN。見出しごとに判定する（短い解説が長い欄に薄められないように）。
    文は段落・箇条書きの項目ごとにsentences()で分ける。限界: 括弧が対応しない文末、
    括弧の無い例文・引用、DESUで除いていない普通体の「〜ます」の動詞は誤って判定しうる"""
    hits, per = [], {}
    for k, (_, body) in sorted(s5.items(), key=lambda x: int(x[0])):
        bad = []
        for f in STYLE_FIELDS:
            ss = [
                s.strip()
                for b in blocks(prose(harm_text(body, f)))
                for s in sentences(b)
                if s.strip()
            ]
            d = sum(1 for s in ss if DESU.search(tail(s)))
            if d >= 2 and d * 2 > len(ss):
                bad.append((f, f"{d}/{len(ss)}文"))
                per[f] = per.get(f, 0) + 1
        if len(bad) == 1:
            hits.append(f"5.{k}({bad[0][0]}{bad[0][1]})")
        elif bad:  # 複数欄は略称だけ
            hits.append(f"5.{k}({'・'.join(STYLE_FIELDS[f] for f, _ in bad)})")
    if hits:
        more = f"ほか{len(hits) - 3}件" if len(hits) > 3 else ""
        kinds = "・".join(f"{f}{c}件" for f, c in per.items())
        warn.append(
            f"5節でです・ます調の文が過半の指摘（文体）: {len(hits)}/{len(s5)}件"
            f"（{kinds}） {'、'.join(hits[:3])}{more}。"
            "である調で統一。文末を「〜である」「〜できる」に"
            "（文末の語による機械判定。例文のです・ます調も数える）"
        )


def sev_word(c, w, where, ng):
    """スコアの括弧内の区分（0.0（None）等）が計算の区分と違えばNG。区分の語が無い括弧は見ない"""
    if c and w and c.group(2) and c.group(2) != w:
        ng.append(
            f"{where}の区分{c.group(2)}が計算{w}と不一致"
            "（スコア欄は計算どおり。None→Lowは見出し・重大度列・件数表だけ。cvss-scoring.md）"
        )


def report_scores(txt, eff, rawmain, strict, ng, warn):
    """報告書のスコア・重大度・メトリクス値が、記録（raw出力・確定行）と一致するか"""
    s5, s6 = sect(txt, 5), sect(txt, 6)
    f1 = lambda x: f"{x:.1f}"
    zero = 0  # v3.1が0.0（None）でLowに数えた指摘の数（1節の注記の件数）
    for t, (n, r) in sorted(eff.items()):
        k, rw = str(r.get("id", "")).split(".")[-1], rawmain.get(t)
        if not rw or k not in s5:
            continue
        v3, v4 = rw["raw"].get("v3"), rw["raw"].get("v4")
        e3 = sc(v3, "base_score")
        s4 = v4.get("score") if isinstance(v4, dict) and "error" not in v4 else None
        w4 = v4.get("severity") if s4 is not None else None
        head, body = s5[k]
        zero += bool(e3 and e3[0] == 0)
        m = re.match(r"### 5\.\d+ \[(\w+)\]", head)
        if r.get("band") and m and m.group(1) != r["band"]:
            ng.append(f"{t}: 報告書5.{k}の見出しの重大度が{r['band']}でない")
        row = re.search(
            rf"^\| \[5\.{k}\]\(.*?\) \| (\w+) \| ([^|]+?) \| ([^|]+?) \|(.*)$",
            txt,
            re.M,
        )
        if not row:
            warn.append(f"{t}: 4節に5.{k}の行が無い")
        else:
            if r.get("band") and row.group(1) != r["band"]:
                ng.append(f"{t}: 4節5.{k}の重大度が{r['band']}でない")
            for i, v in ((2, e3 and e3[0]), (3, s4)):
                if v is not None and row.group(i) != f1(v):
                    ng.append(
                        f"{t}: 4節5.{k}のスコア{row.group(i)}が記録{f1(v)}と不一致"
                    )
            if r.get("unused") and "未使用" not in row.group(4):
                ng.append(f"{t}: unusedなのに4節5.{k}の判定欄に「未使用」が無い")
        for lab, v, w in (("CVSS v3.1", e3 and e3[0], e3 and e3[1]), ("CVSS v4.0", s4, w4)):
            c = re.search(rf"^\| {re.escape(lab)} \| ([\d.]+)（([A-Za-z]*)", body, re.M)
            if c and v is not None and c.group(1) != f1(v):
                ng.append(f"{t}: 5.{k}の{lab}のスコア{c.group(1)}が記録{f1(v)}と不一致")
            sev_word(c, w, f"{t}: 5.{k}の{lab}", ng)
        # 判定は見出し「実害の有無」の直下の本文だけ（他指摘への言及で誤検知しない）
        has = UNUSED_MSG in harm_text(body)
        if r.get("unused") and not has:
            ng.append(
                f"{t}: unusedなのに5.{k}の「実害の有無」の下に「{UNUSED_MSG}」が無い"
            )
        elif has and not r.get("unused"):
            (ng if strict else warn).append(
                f"{t}: 5.{k}は未使用と述べるが記録にunusedが無い"
            )
        if r.get("unused") and re.search(r"欠如|不在|欠落|未実装|無し|なし", head):
            warn.append(
                f"{t}: unusedだが5.{k}の見出しが欠如・不在を述べる"
                "（防御機構の不在は未使用でない。判定質問③）"
            )
        if k not in s6:
            continue
        b6 = s6[k][1]
        for pat, v, w in (
            (r"ベーススコア", v3.get("base_score") if e3 else None, e3 and v3.get("base_severity")),
            (r"環境スコア", v3.get("environmental_score") if e3 else None, e3 and v3.get("environmental_severity")),
            (r"スコア", s4, w4),
        ):
            c = re.search(rf"^- {pat}: ([\d.]+)（([A-Za-z]*)", b6, re.M)
            if c and v is not None and c.group(1) != f1(v):
                ng.append(f"{t}: 6.{k}の{pat}{c.group(1)}が記録{f1(v)}と不一致")
            sev_word(c, w, f"{t}: 6.{k}の{pat}", ng)
        for ver, part in zip(
            ("v3", "v4"), re.split(r"^\*\*CVSS v4\.0\*\*", b6, flags=re.M)
        ):
            if r.get(ver) == UNCALC or not isinstance(r.get(ver), str):
                continue
            want = vec(r[ver])
            mrows = re.findall(r"^\| ([A-Z]{1,2})（[^|]*\| ([A-Z]) \|", part, re.M)
            for mt, val in mrows:
                if mt in want and want[mt] != val:
                    ng.append(
                        f"{t}: 6.{k}の{mt}の値{val}がベクター({want[mt]})と不一致"
                    )
    s1 = re.search(r"^## 1\..*?(?=^## |\Z)", txt, re.M | re.S)
    note = f"CVSS v3.1のスコアが0.0（None）の{zero}件はLowに数えている"
    if zero and s1 and note not in s1.group(0):
        ng.append(f"1節の件数表の下に「{note}。」が無い（cvss-scoring.md）")


def prem_problems(p):
    """premの形式の問題の一覧（空なら正しい形）"""
    if not isinstance(p, dict):
        return [f"premが辞書でない。{PREM_HINT}"]
    miss = [k for k in PREM if k not in p]
    extra = sorted(set(p) - set(PREM), key=str)
    if miss or extra:
        return [f"premの項目の欠落{miss}・不明{extra}。{PREM_HINT}"]
    out = []
    for k in PREM:
        e = p[k]
        if not (
            isinstance(e, list) and len(e) >= 3 and all(isinstance(x, str) for x in e)
        ):
            out.append(f"prem.{k}が[値, 根拠, 説明]の文字列の配列でない")
        elif e[0] not in PREM_VALS:
            out.append(f"prem.{k}の値{e[0]!r}がyes|no|unk|naでない")
        elif e[0] in ("yes", "no") and not EVID.match(e[1]):
            out.append(f"prem.{k}の根拠がfile:line / grep:式 でない: {e[1]!r}")
        elif e[0] in ("yes", "unk") and not e[2].strip():
            out.append(f"prem.{k}が{e[0]}なのに説明が空")
        elif e[0] == "na" and k in PREM_NO_NA:
            out.append(f"prem.{k}はnaにしない（全ての指摘に当てはまる。yes|no|unk）")
    return [x + "。" + PREM_HINT for x in out[:1]] + out[1:]


# 前提が「yes」のとき、矛盾しうるメトリクスの値と、反映の理由を書く6節の行（版ごと）。
# (a)はv3.1のAV:NかつAC:L（v4.0はAV:NかつAT:N）のとき。どれも、該当行の判定根拠に「前提(x)」が
# あれば反映済みとしてWARNにしない（cvss-scoring.md「前提条件の確認」）
PREM_CONTRA = {
    "a": (
        (3, {"AV": "N", "AC": "L"}, ("AV", "AC")),
        (4, {"AV": "N", "AT": "N"}, ("AV", "AT")),
    ),
    "c": ((3, {"C": "H"}, ("C",)), (4, {"VC": "H"}, ("VC",))),
    "d": ((3, {"AC": "L"}, ("AC",)), (4, {"AT": "N"}, ("AT",))),
    "e": ((3, {"AV": "N"}, ("AV",)), (4, {"AV": "N"}, ("AV",))),
}
PREM_FIX = {
    "a": "本番に載らないことをAV・AC（v4.0はAT）に反映するか、反映しない理由を書く",
    "c": "この指摘で新たに漏れるものだけで判定するか、理由を書く",
    "d": (
        "v3.1はACの判定根拠に「前提(d): …のためAC:Lのままとする（理由）」と書き、"
        "v4.0はAT:Pにするか理由を書く"
    ),
    "e": "AV:L等にするか、ネットワークから届く理由を書く",
}
PREM_NO_NA = ("e", "f")  # 全ての指摘に当てはまる項目（naを使わない）


def prem_check(eff, require, ng, warn):
    """前提条件の確認（prem）の有無と形式（NG。一部だけにあるのはWARN）"""
    have = [t for t, (_, r) in sorted(eff.items()) if "prem" in r]
    lack = [t for t in sorted(eff) if t not in have]
    if require:
        for t in lack:
            ng.append(f"{t}: prem（前提条件の確認）が無い（--require-prem）")
    elif have and lack:
        more = f"ほか{len(lack) - 5}件" if len(lack) > 5 else ""
        warn.append(
            f"premが一部の指摘にだけある（{len(have)}/{len(eff)}件。"
            f"無い指摘: {', '.join(lack[:5])}{more}）"
        )
    for t in have:
        ng += [f"{t}: {x}" for x in prem_problems(eff[t][1]["prem"])]


def reason_rows(body):
    """6.Nの本文から {版(3/4): {メトリクス: 判定根拠}}"""
    out = {3: {}, 4: {}}
    for ver, part in zip((3, 4), re.split(r"^\*\*CVSS v4\.0\*\*", body, flags=re.M)):
        for m in re.finditer(
            r"^\| ([A-Z]{1,2})（[^|]*\| [A-Z] \| ([^|]*) \|", part, re.M
        ):
            out[ver][m.group(1)] = m.group(2)
    return out


def prem_report(eff, s6, warn):
    """premのyesと矛盾するメトリクスの選択に、6節の該当行の「前提(x)」が無ければWARN
    （s6=None は --report なし: 値だけで判定する）。yes・unkの前提が6.Nのどこにも書かれて
    いないときもWARN"""
    for t, (_, r) in sorted(eff.items()):
        p = r.get("prem")
        if not isinstance(p, dict) or prem_problems(p):
            continue
        try:
            vs = {
                3: vec(r["v3"]) if r.get("v3") not in (None, UNCALC) else {},
                4: vec(r["v4"]) if r.get("v4") not in (None, UNCALC) else {},
            }
        except (ValueError, AttributeError, TypeError):
            continue  # ベクターの形式は別の検査がNGにする
        k = str(r.get("id", "")).split(".")[-1]
        body = s6[k][1] if s6 is not None and k in s6 else None
        rows = reason_rows(body) if body is not None else {3: {}, 4: {}}
        done = set()
        for x, specs in PREM_CONTRA.items():
            if p[x][0] != "yes":
                continue
            tag = re.compile(rf"前提[(（]{x}[)）]")
            fails = []
            for ver, cond, mets in specs:
                if vs[ver] and all(vs[ver].get(m) == v for m, v in cond.items()):
                    if not any(tag.search(rows[ver].get(m, "")) for m in mets):
                        name = "v3.1" if ver == 3 else "v4.0"
                        fails.append(
                            name + " " + "・".join(f"{m}:{v}" for m, v in cond.items())
                        )
            if fails:
                done.add(x)
                where = f"6.{k}の" if body is not None else ""
                warn.append(
                    f"{t}: 前提({x}){PREM[x]}なのに{'／'.join(fails)}で、{where}該当メトリクス"
                    f"の判定根拠に「前提({x})」が無い（{PREM_FIX[x]}）"
                )
        if body is None:
            continue
        miss = [
            x
            for x in PREM
            if x not in done
            and p[x][0] in ("yes", "unk")
            and not re.search(rf"前提[(（]{x}[)）]", body)
        ]
        if miss:
            warn.append(
                f"{t}: 前提{'・'.join(f'({x})' for x in miss)}が有・不明なのに"
                f"6.{k}の判定根拠に「前提({miss[0]})」等の記載が無い"
                "（メトリクスの選択への反映を書く）"
            )


def low_revs(rows):
    """revが先行する同じtmpの行より大きくない行。[(添字, tmp, rev, st, 必要なrev)]
    final: 作業メモ行の最大rev以下（同じ値では有効行がメモ行のままになる）
    memo: メモ・確定行の最大rev以下（追記しても有効行にならず無視される）"""
    memo, top, out = {}, {}, []
    for i, o in enumerate(rows):
        t, rv, st = o.get("tmp"), o.get("rev"), o.get("st")
        if not isinstance(t, str) or type(rv) is not int or st not in REVST:
            continue
        ref = (memo if st == "final" else top).get(t)
        if ref is not None and rv <= ref:
            out.append((i, t, rv, st, top[t] + 1))
        top[t] = max(top.get(t, rv), rv)
        if st == "memo":
            memo[t] = max(memo.get(t, rv), rv)
    return out


def check(
    dec,
    raw,
    report=None,
    adopted=None,
    idmap=None,
    final=False,
    mapping=None,
    strict=False,
    require_prem=False,
):
    ng, warn = [], []
    NG = ng.append
    eff, seen = {}, set()
    for n, r in dec:
        if is_reasons(r):
            continue
        t, rv = r.get("tmp"), r.get("rev", 1)
        if not isinstance(t, str) or not isinstance(rv, int) or isinstance(rv, bool):
            NG(f"L{n}: tmp/revの型が不正")
            continue
        if (t, rv, r.get("st")) in seen:
            NG(f"L{n}: {t} rev{rv} が重複")
            continue
        seen.add((t, rv, r.get("st")))
        if t not in eff or rv > eff[t][1]["rev"]:
            eff[t] = (n, r)
    rawmain, rawalt, rawline = {}, {}, {}
    for n, r in raw:
        if not isinstance(r.get("raw"), dict) or "id" not in r:
            NG(f"raw L{n}: id/rawキーが無い")
            continue
        if r.get("kind") == "alt":
            rawalt[(r["id"], r.get("of"))] = r
        else:
            if r["id"] in rawmain:  # 値の上書き後の再追記。最後の行が有効
                warn.append(f"raw L{n}: {r['id']} を再追記（最後の行を採用）")
            rawmain[r["id"]] = r
            rawline[r["id"]] = n
    if adopted is not None and len(eff) != adopted:
        NG(f"有効行数{len(eff)} != 採用件数{adopted}")
    if set(rawmain) != set(eff):
        NG(f"rawとdecisionsのtmp集合が不一致: {sorted(set(rawmain) ^ set(eff))}")
    ids = {}
    tmps = {x for t in eff for x in t.split("+") if x}
    memo = {r.get("tmp") for _, r in dec if r.get("st") == "memo"}
    timing(dec, raw, eff, rawline, strict, ng, warn)
    rechk_check(dec, eff, final, strict, ng, warn)
    if final:
        for t, (n, r) in sorted(eff.items()):
            if t not in memo:
                NG(
                    f"{t}: 作業メモ行(st:memo)が無い（5f-2の2段書込み①。判定直後に追記する）"
                )
            if not re.fullmatch(r"[A-Za-z0-9.]+(\+[A-Za-z0-9.]+)*", t):
                NG(
                    f"{t}: tmpの形式が不正（統合した一時IDを+で連結する。例: I3+U1）。{TMP_HINT}。{HYPHEN_HINT}"
                )
            if mapping is not None:
                want = mapping.get(str(r.get("id", "")))
                if want is None:
                    NG(f"{t}: id {r.get('id')} が一時ID対応表に無い")
                elif set(t.split("+")) != want:
                    NG(
                        f"{t}: tmpが対応表の一時ID{sorted(want)}と一致しない。{TMP_HINT}"
                    )
        lows = low_revs([r for _, r in dec])
        # 有効行が正しければ履歴行はWARNのみ（--strictでも。既存記録の再検査用）
        for st, what in REVST.items():
            low = [f"L{dec[x[0]][0]}" for x in lows if x[3] == st]
            if low:
                warn.append(
                    f"{what}の履歴行あり（{len(low)}行: {','.join(low)}）。"
                    "報告書2節の判定記録欄に開示すること"
                )
    for t, (n, r) in sorted(eff.items()):
        need = BASE_K + (FINAL_K if final else [])
        miss = [k for k in need if k not in r or (k in FINAL_K and r[k] is None)]
        if miss:
            NG(f"{t}: 必須キー欠落/null {miss}")
            continue
        if r["st"] == "memo" and r["rev"] > 1 and not r.get("rev_why"):
            NG(f"{t}: 値変更のmemo行(rev>1)にrev_why無し")
        u, uw = r.get("unused"), r.get("unused_why")
        if u is not None and not isinstance(u, bool):
            NG(f"{t}: unusedは真偽値")
        elif u and not (isinstance(uw, str) and "0件" in uw):
            NG(f"{t}: unused=trueにはunused_why（grep式→参照0件）が要る")
        elif not u and uw:
            NG(f"{t}: unused_whyがあるのにunusedがtrueでない")
        if final and r["st"] != "final":
            NG(f"{t}: 有効行がst=finalでない")
            continue
        if (
            not isinstance(r["m3"], dict)
            or not isinstance(r["dev"], list)
            or not isinstance(r["borderline"], list)
        ):
            NG(f"{t}: m3/dev/borderlineの型")
            continue
        badel = [
            k
            for k in ("dev", "borderline")
            if not all(isinstance(x, str) for x in r[k])
        ]
        if badel:
            NG(
                f"{t}: {'・'.join(badel)}の要素が文字列（メトリクス名）でない。{BORDER_HINT}"
            )
            continue
        unk = sorted(
            {x for k in ("dev", "borderline") for x in r[k]} - set(V3), key=str
        )
        if unk:
            NG(f"{t}: dev/borderlineに未知のメトリクス名 {unk}。{BORDER_HINT}")
            continue
        rw = rawmain.get(t)
        v3s = r["v3"]
        v3ok = v3s != UNCALC
        rv3 = rw["raw"].get("v3") if rw else None
        rv4 = rw["raw"].get("v4") if rw else None
        if rw:
            e3 = sc(rv3, "base_score")
            e4 = rv4 if isinstance(rv4, dict) else {}
            if e3 is None:
                if v3s != UNCALC:
                    NG(f"{t}: raw v3が算出エラーなのにv3が「{UNCALC}」でない")
                warn.append(f"{t}: v3未算出（照合免除。重大度は暫定）")
            elif rv3["vector"] != v3s:
                NG(f"{t}: v3がraw出力と不一致")
            if "error" in e4 or "vector" not in e4:
                if r["v4"] != UNCALC:
                    NG(f"{t}: raw v4が算出エラーなのにv4が「{UNCALC}」でない")
                warn.append(f"{t}: v4未算出（照合免除）")
            elif e4["vector"] != r["v4"]:
                NG(f"{t}: v4がraw出力と不一致")
            # v4diff: v3.1の基準値の帯とv4.0のseverity（共にNone→Low）が異なる指摘にだけ必須（環境重大度ではなく基準値同士を比べる）
            if final:
                vd = r.get("v4diff")
                b3 = rv3.get("base_severity") if isinstance(rv3, dict) else None
                mismatch = bool(
                    e3 and b3 and e4.get("severity") and "error" not in e4
                ) and band_of(b3) != band_of(e4["severity"])
                if vd is not None and not mismatch:
                    NG(
                        f"{t}: v4diffがあるが、帯が一致する/v3.1かv4.0が未算出（v4diffは帯が食い違う指摘にだけ書く）"
                    )
                if mismatch:
                    if not (
                        isinstance(vd, dict)
                        and vd.get("cause") in ("spec", "judgment")
                        and isinstance(vd.get("why"), str)
                        and V4M.search(vd["why"])
                    ):
                        NG(
                            f"{t}: v3.1基準値の帯{band_of(b3)}とv4.0の{band_of(e4['severity'])}が異なるが、v4diff{{cause:spec|judgment, why:差が出たv4メトリクス名+理由}}が無い/不正"
                        )
                    elif vd["cause"] == "judgment" and r.get("attn") != "high":
                        NG(f"{t}: v4diff=judgmentならattn=high")
                    elif vd["cause"] == "spec" and r.get("v4map") != "std":
                        NG(
                            f"{t}: v4diff=specはv4map=stdのときのみ（非標準の対応付けは判断）"
                        )
            if e3 and band_of(e3[1]) != r.get("band", band_of(e3[1])):
                NG(
                    f"{t}: band {r.get('band')} != raw {e3[1]}（None(0.0)のみLowを要求）"
                )
        if not v3ok:
            continue
        try:
            v3 = vec(v3s)
        except ValueError:
            NG(f"{t}: v3形式不正")
            continue
        tagd, tagb = set(), set()
        for m, allowed in V3.items():
            e = r["m3"].get(m)
            if not (isinstance(e, list) and len(e) >= 4):
                NG(f"{t}: m3.{m} は4要素以上の配列")
                continue
            if e[0] != v3.get(m) or e[0] not in allowed:
                NG(f"{t}: m3.{m}={e[0]} がv3ベクター({v3.get(m)})と不一致")
            if not EVID.match(str(e[1])):
                NG(f"{t}: m3.{m} 証拠が file:line / grep:式 でない: {e[1]!r}")
            if not str(e[2]).strip():
                NG(f"{t}: m3.{m} 事実が空")
            if not str(e[3]).startswith(TAGS):
                NG(f"{t}: m3.{m} 規則タグが不正: {e[3]!r}。{TAG_HINT}")
            if str(e[3]).startswith("逸脱:"):
                tagd.add(m)
            if str(e[3]).startswith(("迷:", "例外:", "逸脱:")):
                tagb.add(m)
        if set(r["dev"]) != tagd:
            NG(f"{t}: dev={sorted(r['dev'])} が「逸脱:」タグ{sorted(tagd)}と不一致")
        if not tagb <= set(r["borderline"]) or not set(r["dev"]) <= set(
            r["borderline"]
        ):
            NG(f"{t}: 迷/例外/逸脱タグのメトリクスがborderlineに無い")
        diff = False
        for m in r["borderline"]:
            e = r["m3"].get(m)
            if not (isinstance(e, list) and len(e) >= 5 and isinstance(e[4], dict)):
                NG(f"{t}: borderline {m} に5要素目のalt(dict)が無い。{BORDER_HINT}")
                continue
            a = e[4]
            ar = rawalt.get((t, m))
            if a.get("alt") == e[0] or a.get("alt") not in V3.get(m, ""):
                NG(f"{t}: alt({m})の値が不正/主値と同じ")
                continue
            if not ar:
                NG(f"{t}: alt({m})のスクリプト実行がraw出力に無い")
                continue
            want = ["CVSS:3.1"] + [
                f"{k}:{a['alt'] if k == m else v3[k]}" for k in V3 if k in v3
            ]
            av = ar["raw"].get("v3", {})
            if basepart(av.get("vector", "")) != want:
                NG(f"{t}: alt({m})のベクターが主ベクターの{m}のみ差し替えではない")
            s2 = sc(av, "base_score")
            if not s2:
                NG(f"{t}: alt({m})のraw v3が算出エラー")
                continue
            if a.get("score") != f"{s2[0]}/{s2[1]}":
                NG(f"{t}: alt({m})のscore {a.get('score')} != raw {s2[0]}/{s2[1]}")
            if band_of(s2[1]) != r.get("band"):
                diff = True
        if final:
            if r["sbs"] != diff:
                NG(f"{t}: sbs={r['sbs']} だが別案の帯変化は{diff}")
            if r["sbs"] and r["attn"] != "high":
                NG(f"{t}: sbs=trueならattn=high")
            if r["borderline"] and r["attn"] == "none":
                NG(f"{t}: borderlineがあるのにattn=none")
            if r["attn"] not in ("none", "low", "high"):
                NG(f"{t}: attn不正")
            if r["attn"] != "none" and not r.get("attn_why"):
                NG(f"{t}: attn_why無し")
            if r["raw"] != rawline.get(t):
                NG(
                    f"{t}: raw={r['raw']} がraw出力の主行の行番号{rawline.get(t)}と不一致"
                )
            if r["id"] in ids:
                NG(f"{t}: id {r['id']} が{ids[r['id']]}と重複")
            ids[r["id"]] = t
            if idmap is not None and idmap.get(t) != r["id"]:
                NG(f"{t}: id {r['id']} != 対応表 {idmap.get(t)}{idmap_hint(t, idmap)}")
        for k in (
            "attn_why",
            "rev_why",
            "grp",
        ):  # 自由文に、この記録のtmp（一時ID）そのものを書かない（F5ロードバランサ等の一般語は対象外）
            if any(
                re.search(
                    r"(?<![A-Za-z0-9_])" + re.escape(x) + r"(?![A-Za-z0-9_])",
                    str(r.get(k, "")),
                )
                for x in tmps
            ):
                NG(f"{t}: {k}に一時IDらしき記述")
    facts_check(eff, warn)
    prem_check(eff, require_prem, ng, warn)
    if final:
        order_check(eff, ng, warn)
        why_reuse(eff, warn)
    nr = []  # 非再現を理由にした6節の判定根拠（--report時。表示のみ）
    if report is not None:
        try:
            txt = open(report, encoding="utf-8-sig").read()
        except (OSError, UnicodeDecodeError) as e:
            NG(f"報告書を読めない: {e}")
            txt = None
        if txt is not None:
            heads = re.findall(r"^### 5\.(\d+) ", txt, re.M)
            if len(heads) != len(eff) or (
                adopted is not None and len(heads) != adopted
            ):
                NG(
                    f"報告書5節の見出し{len(heads)}件 != 有効行数{len(eff)}/採用{adopted}"
                )
            secs = {
                m.group(1): txt[
                    m.end() : (
                        re.compile(r"^#{1,3} ", re.M).search(txt, m.end())
                        or re.search(r"\Z", txt)
                    ).start()
                ]
                for m in re.finditer(r"^(?=### 6\.(\d+) )(.*)$", txt, re.M)
            }
            hd = {
                m.group(1): m.group(0)
                for m in re.finditer(r"^### 6\.(\d+) .*$", txt, re.M)
            }
            for t, (n, r) in eff.items():
                k = str(r.get("id", "")).split(".")[-1]
                if k not in hd:
                    NG(f"{t}: 報告書6.{k}が無い")
                    continue
                body = secs.get(k, "")
                if any(
                    v != UNCALC and f"`{v}`" not in body for v in (r["v3"], r["v4"])
                ):
                    NG(f"{t}: 報告書6.{k}のベクターが記録と不一致")
                if r.get("band") and f"[{r['band']}]" not in hd[k]:
                    NG(f"{t}: 報告書6.{k}の見出しの重大度が{r['band']}でない")
                if r.get("dev") and "基準からの逸脱" not in body:
                    NG(f"{t}: devがあるのに報告書6.{k}に「基準からの逸脱」が無い")
        if txt is not None:
            rows = {}
            for m in re.finditer(
                r"^\| ([A-Z]{1,2})（[^|]*\| [A-Z] \| ([^|]+) \|$", txt, re.M
            ):
                rows.setdefault(m.group(1), []).append(m.group(2).strip())
            for k, v in rows.items():
                if k in ("AV", "AC", "PR", "UI", "C", "I", "A", "VC", "VI", "VA") and (
                    len(v) >= 4 and len(set(v)) / len(v) < 0.3
                ):
                    warn.append(
                        f"6節の{k}の判定根拠が使い回し（{len(v)}行中{len(set(v))}通り）。指摘ごとにコード上の事実で書き直す"
                    )
            reasons_check(sect(txt, 6), ng, warn)
            sentence_reuse(sect(txt, 6), warn)
            report_scores(txt, eff, rawmain, strict, ng, warn)
            prem_report(eff, sect(txt, 6), warn)
            nr = repro_check(txt, ng, warn)
            style_check(sect(txt, 5), warn)
    else:
        warn.append("報告書突合: 未実施（--reportなし）")
        prem_report(eff, None, warn)
    print(
        "  有効行数:",
        len(eff),
        " by=post:",
        sum(1 for _, r in eff.values() if r.get("by") == "post"),
        " attn=high:",
        sum(1 for _, r in eff.values() if r.get("attn") == "high"),
        " sbs:",
        sum(1 for _, r in eff.values() if r.get("sbs")),
    )
    if nr:
        more = f"ほか{len(nr) - 6}欄" if len(nr) > 6 else ""
        print(
            f"  非再現を理由にした判定根拠（A-5）: {len(nr)}欄 {'・'.join(nr[:6])}{more}"
        )
    for m in warn:
        print("WARN:", m)
    for m in ng:
        print("NG:", m)
    print("RESULT:", f"NG ({len(ng)})" if ng else "OK")
    return not ng


def run(
    dp,
    rp,
    report=None,
    adopted=None,
    idmap=None,
    final=False,
    mapping=None,
    strict=False,
    require_prem=False,
):
    try:
        d, e1 = load(dp)
        r, e2 = load(rp)
        if d is None or r is None:
            for m in e1 + e2:
                print("NG:", m)
            print("RESULT: NG (入力不正)")
            return False
        for m in e1 + e2:
            print("NG:", m)
        ok = check(d, r, report, adopted, idmap, final, mapping, strict, require_prem)
        return ok and not (e1 or e2)
    except Exception as e:  # 想定外の形でもTracebackにしない
        print("NG: 内部エラー", type(e).__name__, e)
        print("RESULT: NG (内部エラー)")
        return False


def idmap_hint(t, idmap):
    """--idmap／--fill-ids でtmpがキーに無いときのヒント（連結順の違い・作業用IDでの記録）"""
    if t in idmap:
        return ""
    srt = "+".join(sorted(str(t).split("+")))
    if srt != t and srt in idmap:
        return (
            f"。idmapのキーは構成一時IDを昇順に連結した形（{srt}）。tmpも同じ順で書く"
        )
    return f"。{TMP_HINT}（idmapのキーはtmpと完全に同じ文字列）"


def fill_ids(dp, rp, idmap):
    d, e1 = load(dp)
    r, e2 = load(rp)
    if (
        d is None or r is None or e1 or e2
    ):  # 不正行を含むログは書き換えない（追記専用ログを壊さない）
        for m in (e1 or []) + (e2 or []):
            print("NG:", m)
        print("RESULT: NG (--fill-ids 中止。ファイルは未変更)")
        return False
    rawline = {x.get("id"): n for n, x in r if x.get("kind") != "alt"}
    for n, x in d:
        t = x.get("tmp")
        if t not in rawline:
            print(f"WARN: {t}: raw出力に主行が無い（rawは未設定のまま）")
        if t not in idmap:
            print(f"WARN: {t}: 対応表に無い（idは未設定のまま）{idmap_hint(t, idmap)}")
    with open(dp + ".tmp", "w", encoding="utf-8") as f:
        for n, x in d:
            t = x.get("tmp")
            x["id"] = idmap.get(t, x.get("id"))
            x["raw"] = rawline.get(t, x.get("raw"))
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    os.replace(dp + ".tmp", dp)
    print("fill-ids: 完了")
    return True


def is_reasons(o):
    """CVSS-JUDGEのreasons行（判定根拠r3/r4。stもrevも無い）。記録には入れない（build_findingsがout/judge-K.jsonlから読む）"""
    return o.get("st") is None and ("r3" in o or "r4" in o)


def row_problems(o):
    """st が memo/final の行の必須キーと型（--finalの検査と同じ基準）。問題の一覧を返す"""
    if o.get("st") not in ("memo", "final"):
        return []
    out = [f"必須キー欠落 {k}" for k in BASE_K if k not in o]
    rv = o.get("rev")
    if "tmp" in o and not isinstance(o["tmp"], str):
        out.append("tmpは文字列")
    if "rev" in o and (not isinstance(rv, int) or isinstance(rv, bool)):
        out.append("revは整数")
    for k, typ in (("m3", dict), ("dev", list), ("borderline", list)):
        if k in o and not isinstance(o[k], typ):
            out.append(f"{k}の型")
    for k in ("dev", "borderline"):
        if isinstance(o.get(k), list) and not all(isinstance(x, str) for x in o[k]):
            out.append(f"{k}の要素が文字列でない。{BORDER_HINT}")
    if "prem" in o:
        out += prem_problems(o["prem"])
    return out


def append_rows(path, objs, show=False):
    """各行にseq（連番）とts（UTC）を付けて追記する。手書きのseq/tsは上書きする。
    排他ロック（fcntl.flock）を取ってから末尾のseqを読むので、並列実行でも重複しない"""
    bad_rows = [(i, row_problems(o)) for i, o in enumerate(objs, 1) if row_problems(o)]
    for i, pr in bad_rows:
        print(f"NG: stdin {i}行目: {'、'.join(pr)}")
    if bad_rows:
        print("RESULT: NG (--append中止。ファイルは未変更)")
        return False

    # revが同じtmpの先行行より大きくなければ拒否（同じ呼び出し内の行も含む）
    def low(old):
        k = len(old)
        out = [x for x in low_revs(old + objs) if x[0] >= k]
        for i, t, rv, st, need in out:
            print(
                f"NG: stdin {i - k + 1}行目: {t} の{REVST[st]}（rev {rv}。"
                f"{'有効行がメモ行のまま' if st == 'final' else '無視される'}）。"
                f"rev {need} 以上にする"
            )
        if out:
            print("RESULT: NG (--append中止。ファイルは未変更)")
        return out

    if low([]):  # 新規ファイルを作る前に、stdin内だけで判定できる分を拒否する
        return False
    try:
        with open(path, "ab") as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)
            # tsはロックを取った後、seqの算出と同じ区間で決める（並列でも時刻が逆行しない）
            now = datetime.datetime.now(datetime.timezone.utc)
            now = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            n = mx = 0
            tail = b""
            old = []
            if os.path.getsize(path):
                old, bad = load(path)
                if old is None or bad:
                    for m in bad:
                        print("NG:", m)
                    print("RESULT: NG (--append中止。ファイルは未変更)")
                    return False
                n = len(old)
                seqs = [o["seq"] for _, o in old if type(o.get("seq")) is int]
                mx = max(seqs, default=0)
                if old and not seqs:
                    print(
                        f"WARN: {path} は旧形式（seq/ts無し）。追記はするが、"
                        "--strictの検査ではNGになる",
                        file=sys.stderr,
                    )
                with open(path, "rb") as g:
                    g.seek(-1, os.SEEK_END)
                    tail = b"" if g.read(1) == b"\n" else b"\n"
            if low([o for _, o in old]):
                return False
            f.write(tail)
            base = max(n, mx)
            for i, o in enumerate(objs, 1):
                o = {**o, "seq": base + i, "ts": now}
                f.write((json.dumps(o, ensure_ascii=False) + "\n").encode("utf-8"))
                if show:  # 追記した生出力をArbiterが確認できるよう表示する
                    print(json.dumps(o, ensure_ascii=False))
            f.flush()
    except OSError as e:
        print(f"NG: {path} に追記できない（ディレクトリの有無・権限を確認）: {e}")
        print("RESULT: NG (--append中止)")
        return False
    print(f"append: {len(objs)}行 (seq {base + 1}-{base + len(objs)}, ts {now})")
    return True


def read_objs(text, wrap=None):
    """stdinのJSON Linesを辞書のリストにする。wrapがあれば全体を1個のJSONとみなして包む"""
    try:
        if wrap is None:
            objs = [json.loads(x) for x in text.split("\n") if x.strip()]
        else:
            objs = [{**wrap, "raw": json.loads(text)}]
    except ValueError as e:
        print("NG: stdinのJSONが不正:", e)
        return None
    if not objs or not all(isinstance(o, dict) for o in objs):
        print("NG: stdinにJSONオブジェクトが無い")
        return None
    return objs


def selftest(verbose=False):
    """自己検査の本体は scripts/selftests/st_check_cvss_decisions.py（本体の読込を減らすため分けた）。"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "selftests"))
    import st_check_cvss_decisions

    return st_check_cvss_decisions._st_entry(globals(), verbose)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--decisions")
    ap.add_argument("--raw")
    ap.add_argument("--report")
    ap.add_argument("--adopted", type=int)
    ap.add_argument(
        "--idmap",
        help='JSONファイルのパス、または { で始まるJSON文字列。{"I3+U1":"5.3"} の形'
        "（キー＝その最終項目の構成一時IDを昇順に+で連結した文字列＝decisionsのtmp。作業用IDではない）",
    )
    ap.add_argument(
        "--mapping", help="一時ID→最終番号の対応表TSV(temp_id, final_number, work_id)"
    )
    ap.add_argument("--final", action="store_true")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="seq/tsが無い記録とrechkが無い上書きもNGにする（新規実行用。旧形式の再検査では付けない）",
    )
    ap.add_argument(
        "--require-prem",
        action="store_true",
        help="prem（前提条件の確認）が無い有効行をNGにする（新規実行用）",
    )
    ap.add_argument("--fill-ids", action="store_true")
    ap.add_argument(
        "--append",
        metavar="FILE",
        help="stdinのJSON Lines（1行1オブジェクト）にseq・tsを付けてFILEへ追記する",
    )
    ap.add_argument(
        "--append-raw",
        metavar="FILE",
        help="stdin（calculate_cvss.pyの出力）を{id,raw,seq,ts}に包んでFILEへ追記する（--idが必要）",
    )
    ap.add_argument("--id", help="--append-rawの一時ID（tmp）")
    ap.add_argument("--kind", choices=["alt"], help="--append-rawで別案の行にする")
    ap.add_argument("--of", help="--kind altの別案のメトリクス名（AC等）")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        selftest()
        sys.exit(0)
    if a.append or a.append_raw:
        others = (
            a.decisions,
            a.raw,
            a.report,
            a.adopted,
            a.idmap,
            a.mapping,
            a.final,
            a.strict,
            a.fill_ids,
            a.require_prem,
        )
        if (a.append and a.append_raw) or any(x not in (None, False) for x in others):
            ap.error("--append/--append-rawは他の検査・後埋めのフラグと併用できない")
        if a.append_raw:
            if not a.id:
                ap.error("--append-rawには--idが必要")
            if a.kind and not a.of:
                ap.error("--kind altには--of <メトリクス名>が必要")
            if a.of and not a.kind:
                ap.error("--ofは--kind altと併用する")
            wrap = {"id": a.id, **({"kind": a.kind, "of": a.of} if a.kind else {})}
        # stdinはバイト列でUTF-8として読む（Windowsのロケール（cp932）での復号を避ける）
        raw_in = sys.stdin.buffer.read().decode("utf-8-sig")
        objs = read_objs(raw_in, wrap if a.append_raw else None)
        if objs and a.append:
            skip = [o for o in objs if is_reasons(o)]
            objs = [o for o in objs if not is_reasons(o)]
            if skip:
                print(f"skip: reasons行{len(skip)}行（記録に入れない。build_findingsがout/judge-K.jsonlから読む）")
                if not objs:
                    sys.exit(0)
        sys.exit(0 if objs and append_rows(a.append or a.append_raw, objs, True) else 1)
    if not (a.decisions and a.raw):
        ap.error("--decisions と --raw が必要")
    try:
        if a.idmap and a.idmap.lstrip().startswith("{"):
            idm = json.loads(a.idmap)
        else:
            idm = json.load(open(a.idmap, encoding="utf-8")) if a.idmap else None
    except (OSError, ValueError) as e:
        print("NG: idmapを読めない:", e)
        print("RESULT: NG (入力不正)")
        sys.exit(1)
    if idm is not None and not isinstance(idm, dict):
        print("NG: idmapはJSONオブジェクト")
        print("RESULT: NG (入力不正)")
        sys.exit(1)
    if a.fill_ids:
        sys.exit(0 if fill_ids(a.decisions, a.raw, idm or {}) else 1)
    mp: dict[str, set[str]] | None = None
    if a.mapping:
        try:
            rows = [
                ln.split("\t")
                for ln in open(a.mapping, encoding="utf-8").read().split("\n")
                if ln.strip()
            ]
        except (OSError, UnicodeDecodeError) as e:
            print("NG: mappingを読めない:", e)
            print("RESULT: NG (入力不正)")
            sys.exit(1)
        mp = {}
        for r_ in rows[1:] if rows and rows[0][0] == "temp_id" else rows:
            if len(r_) >= 2:
                mp.setdefault(r_[1], set()).add(r_[0])
    sys.exit(
        0
        if run(
            a.decisions,
            a.raw,
            a.report,
            a.adopted,
            idm,
            a.final,
            mp,
            a.strict,
            a.require_prem,
        )
        else 1
    )
