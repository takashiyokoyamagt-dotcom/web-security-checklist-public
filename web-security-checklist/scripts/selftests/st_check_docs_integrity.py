"""check_docs_integrity.py の自己検査（--self-test）の本体。本体から分けた（読込を減らすため。P6）。
単独では実行しない。`python3 scripts/check_docs_integrity.py --self-test` が呼ぶ。
本体のモジュールの名前（関数・定数）をこのモジュールの名前空間に写してから、元のコードをそのまま実行する。"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unicodedata

_MAIN_FILE = None  # 本体のファイルのパス（_st_entry が入れる）
_MAIN_GLOBALS = None  # 本体の globals()。本体の定数を一時的に変える検査はここを書き換える


def selftest(src: str) -> bool:
    """現在の文書の一時コピーで、正常系がOK・破壊ケースが想定のコードで検出されるか。
    置換が空振りしたケース（文書の変更で前提が崩れた）は失敗として記録し、続行する"""

    def fresh(td: str, name: str) -> str:
        d = os.path.join(td, name)
        os.makedirs(d)
        shutil.copy2(os.path.join(src, "SKILL.md"), d)
        for sub in ("references", "assets", "scripts", "docs", "adapters"):
            if os.path.isdir(os.path.join(src, sub)):
                shutil.copytree(os.path.join(src, sub), os.path.join(d, sub))
        return d

    def text(d, rel):
        with open(os.path.join(d, rel), encoding="utf-8") as f:
            return f.read()

    def put(d, rel, s):
        with open(os.path.join(d, rel), "w", encoding="utf-8", newline="") as f:
            f.write(s)

    def rsub(rel, pat, repl):  # 正規表現で1箇所置換（空振りは前提崩れ）
        def f(d):
            s, n = re.subn(pat, repl, text(d, rel), count=1, flags=re.MULTILINE)
            assert n == 1, f"前提崩れ: {rel} に {pat[:40]!r} が無い"
            put(d, rel, s)

        return f

    def sub(rel, old, new):
        return rsub(rel, re.escape(old), new.replace("\\", "\\\\"))

    def append(rel, s):
        def f(d):
            put(d, rel, text(d, rel) + s)

        return f

    def create(rel, s):
        def f(d):
            put(d, rel, s)

        return f

    def mkdir(rel):  # 文書名のディレクトリ（読めない）
        def f(d):
            os.makedirs(os.path.join(d, rel))

        return f

    def remove(rel):
        def f(d):
            os.remove(os.path.join(d, rel))

        return f

    def raw(rel, fn):  # バイト列を書き換える
        def f(d):
            p = os.path.join(d, rel)
            with open(p, "rb") as fh:
                b = fh.read()
            with open(p, "wb") as fh:
                fh.write(fn(b))

        return f

    def jedit(rel, fn):  # JSONファイルを読んで fn(dict) で書き換える
        def f(d):
            doc = json.loads(text(d, rel))
            fn(doc)
            put(d, rel, json.dumps(doc, ensure_ascii=False, indent=2) + "\n")

        return f

    def both(*fs):
        def f(d):
            for x in fs:
                x(d)

        return f

    def g0_over(d):  # 予算を1B超えるまで、各G0ファイルへ上限内で分けて足す
        sizes, _ = load(d, [], [])
        need = G0_BUDGET - sum(sizes[r] for r in G0_FILES) + 1
        for r in sorted(G0_FILES, key=lambda r: sizes[r] - SIZE_RANGE[r][1]):
            k = min(need, SIZE_RANGE[r][1] - sizes[r])
            if k > 0:
                append(r, "x" * k)(d)
                need -= k
        assert need <= 0, "前提崩れ: 上限内でG0予算を超えられない"

    def size_over(d):
        rel = "references/checklists/principles.md"
        n = len(text(d, rel).encode("utf-8"))
        append(rel, "x" * (SIZE_RANGE[rel][1] - n + 1))(d)

    def shrink(d):  # 中身の大部分が消えた（下限の半分のバイト数に切り詰める）
        rel = "references/checklists/principles.md"
        b = text(d, rel).encode("utf-8")[: SIZE_RANGE[rel][0] // 2]
        put(d, rel, b.decode("utf-8", "ignore"))

    def dup_body(d):  # 本文の行を先頭の追加ブロックへ複製する
        rel = "references/pipeline/fix-audit-strictness.md"
        lines = text(d, rel).split("\n")
        k = lines.index(END)
        x = next(ln for ln in lines[k + 1 :] if len(norm(ln)) >= DUP_MIN)
        put(d, rel, "\n".join(lines[:1] + [x] + lines[1:]))

    def move_token(d):  # agent-rolesのトークン行を本文末尾へ移す
        rel = "references/core/agent-roles.md"
        t = TOKEN_RE.search(text(d, rel))
        assert t, "前提崩れ: agent-rolesにトークンが無い"
        put(d, rel, text(d, rel).replace(t.group(0) + "\n", "", 1) + t.group(0) + "\n")

    def same_hex(d):  # cvss-scoringのトークン値をfinding-arbiterと同じにする
        a = TOKEN_RE.search(text(d, "references/pipeline/finding-arbiter.md"))
        assert a, "前提崩れ: finding-arbiterにトークンが無い"
        rsub("references/cvss/cvss-scoring.md", r"(GATE-TOKEN:G3B-)\w+", r"\g<1>" + a[3])(d)

    def leak(d):  # mode3-reportのトークン値をSKILL.mdへ書く
        t = TOKEN_RE.search(text(d, "references/modes/mode3-report.md"))
        assert t, "前提崩れ: mode3-reportにトークンが無い"
        append("SKILL.md", f"\n参考: {t[3]}\n")(d)

    def swap(rel, pa, pb):  # paとpbに一致する行を入れ替える
        def f(d):
            ls = text(d, rel).split("\n")
            ia = next(i for i, x in enumerate(ls) if re.search(pa, x))
            ib = next(i for i, x in enumerate(ls) if re.search(pb, x))
            ls[ia], ls[ib] = ls[ib], ls[ia]
            put(d, rel, "\n".join(ls))

        return f

    def move_out(d):  # G6のgateマーカーを追加ブロックの外（末尾）へ移す
        ls = text(d, GATE_DOC).split("\n")
        i = next(i for i, x in enumerate(ls) if x.startswith("<!--gate:G6 "))
        put(d, GATE_DOC, "\n".join(ls[:i] + ls[i + 1 :] + [ls[i]]))

    def blank_desc(d):  # descriptionの値（続く字下げ行）を空にする
        rsub("SKILL.md", r"^description:.*\n(?:[ \t].*\n)*", "description: >-\n")(d)

    pr, sk, fa = "references/checklists/principles.md", "SKILL.md", "references/pipeline/finding-arbiter.md"
    cv, m2, ar = "references/cvss/cvss.md", "references/modes/mode2-audit-review.md", GATE_DOC
    html, rep = "references/modes/mode3-html.md", "references/modes/mode3-report.md"
    cs = "references/cvss/cvss-scoring.md"
    di = "references/design/design-intent.md"
    df = "references/design/design-fields.md"
    da = "references/design/design-audit.md"
    dg = "references/design/design-integrated.md"
    vj = "references/sources/VERSIONS.json"
    g3_line = r"^(- G3（[^\n]*?), `references/checklists/principles\.md`"
    tok = r"^GATE-TOKEN:.*"
    # (名前, 破壊, 期待コード)。WARN_CODESはWARNで検出（size-gone以外はNGが無いことも求める）
    cases = [
        ("サイズ超過", size_over, "size-max"),
        ("サイズ下限（中身の大部分が消えた）", shrink, "size-min"),
        ("表に無いファイル", create("references/new-doc.md", "x\n"), "size-unlisted"),
        ("表のファイルが無い", remove("references/modes/category-map.md"), "size-gone"),
        ("コードフェンスが奇数", append(pr, "```\n"), "fence"),
        ("BOM", raw(pr, lambda b: b"\xef\xbb\xbf" + b), "bom"),
        ("CRLF", raw(pr, lambda b: b.replace(b"\n", b"\r\n")), "crlf"),
        ("UTF-8でない", raw(pr, lambda b: b + b"\xff\xfe\n"), "utf8"),
        ("G0予算超過（各ファイルは上限内）", g0_over, "g0-budget"),
        ("G0ファイルの欠落", remove(cv), "g0-missing"),
        ("split:endの欠落", sub(fa, END + "\n", ""), "marker-count"),
        ("split:addの入れ子", sub(cv, "\n", f"\n{ADD}\nx\n{END}\n"), "marker-nest"),
        ("対応の無いsplit:end", append(pr, END + "\n"), "marker-orphan"),
        ("split:addが閉じていない", append(pr, ADD + "\n"), "marker-unclosed"),
        (
            "マーカーが単独行でない",
            sub(m2, "\n" + END, "\n文。" + END),
            "marker-inline",
        ),
        ("表記違い（空白）", sub(cv, END, "<!-- split:end -->"), "marker-variant"),
        (
            "表記違い（大文字・全角）",
            sub(cv, END, "<！--Split:End-->"),
            "marker-variant",
        ),
        (
            "追加ブロックの行数超過",
            sub(cv, ADD + "\n", ADD + "\nx" * 6 + "\n"),
            "add-cap",
        ),
        ("追加ブロックへの本文複製", dup_body, "add-dup"),
        ("frontmatterの先頭が---でない", rsub(sk, r"\A", "\n"), "fm-open"),
        ("frontmatterの閉じ---の欠落", rsub(sk, r"^---\n(?=\n# )", ""), "fm-close"),
        ("frontmatterのname違い", rsub(sk, r"^name: .*$", "name: other"), "fm-name"),
        ("frontmatterのdescriptionが空", blank_desc, "fm-desc"),
        (
            "G0必読一覧の見出しが無い",
            sub(sk, "必読ファイル（G0", "必読（G0"),
            "list-none",
        ),
        (
            "G0必読の欠落（件数）",
            rsub(sk, r"^4\. `references/cvss/cvss\.md`.*\n", ""),
            "list-count",
        ),
        (
            "G0必読の中身違い（件数は同じ）",
            sub(sk, "4. `" + cv, "4. `" + fa),
            "list-content",
        ),
        (
            "モード2必読の欠落",
            rsub(sk, r"^6\. `references/core/agent-roles.*\n", ""),
            "list-count",
        ),
        (
            "モード2必読の順序だけ違う",
            swap(sk, r"^1\. `references/modes/mode2-", r"^2\. `"),
            "list-order",
        ),
        ("ゲート一覧の重複", rsub(sk, r"^(- G6（.*\n)", r"\1\1"), "gate-dup"),
        ("ゲート一覧の順序", swap(sk, r"^- G5（", r"^- G6（"), "gate-order"),
        (
            "SKILL.mdのG3からcwe-top25を消す",
            sub(sk, ", `references/sources/cwe-top25.md`", ""),
            "gate-files",
        ),
        (
            "SKILL.mdとgateマーカーの両方のG3からprinciplesを消す",
            both(rsub(sk, g3_line, r"\1"), sub(ar, ",references/checklists/principles.md", "")),
            "gate-files",
        ),
        (
            "分割構成の件数不一致",
            sub(sk, "- 13ファイル（", "- 14ファイル（"),
            "split-count",
        ),
        ("ゲートファイルの欠落", remove("references/modes/mode3-by-source.md"), "gate-exist"),
        ("mode3-full-audit.mdの欠落", remove(ar), "gm-nodoc"),
        ("gateマーカーの欠落（G5）", rsub(ar, r"^<!--gate:G5 .*\n", ""), "gm-set"),
        ("R1マーカーの欠落", rsub(ar, r"^<!--gate:R1 .*\n", ""), "gm-set"),
        (
            "gateマーカーの順序",
            swap(ar, r"^<!--gate:G6 ", r"^<!--gate:G7 "),
            "gm-order",
        ),
        (
            "mode3-onlyの欠落",
            sub(ar, "<!--gate:G3 mode3-only ", "<!--gate:G3 "),
            "gm-mode3",
        ),
        ("gateマーカーが追加ブロックの外", move_out, "gm-outside"),
        ("gateマーカーのキー文の欠落", sub(ar, "【ゲートG3（", "【G3（"), "gm-key"),
        (
            "gateマーカーのfilesだけ違う",
            sub(ar, ",references/checklists/principles.md", ""),
            "gm-files",
        ),
        (
            "R1マーカーにfiles=",
            sub(ar, "R1 mode3-only-->", "R1 mode3-only files=x.md-->"),
            "gm-files",
        ),
        ("G2マーカーの欠落", rsub(ar, r"^<!--gate:G2 .*\n", ""), "gm-set"),
        (
            "G2マーカーのconditionalの欠落",
            sub(ar, "mode3-only conditional files=", "mode3-only files="),
            "gm-cond",
        ),
        (
            "G3マーカーにconditionalが付いている",
            sub(ar, "<!--gate:G3 mode3-only ", "<!--gate:G3 mode3-only conditional "),
            "gm-cond",
        ),
        (
            "G2の「設計書なし」の記録指示の欠落（gateマーカー側）",
            sub(ar, "「G2: 設計書なし（探索:", "「設計書なし（探索:"),
            "gm-cond-none",
        ),
        (
            "G2のfilesだけ違う（gateマーカー）",
            sub(
                ar,
                "conditional files=references/design/design-intent.md",
                "conditional files=x.md",
            ),
            "gm-files",
        ),
        (
            "SKILL.mdのゲート一覧からG2を消す",
            rsub(sk, r"^- G2（.*\n", ""),
            "gate-order",
        ),
        (
            "SKILL.mdのG2の「条件付き」の欠落",
            sub(sk, "- G2（手順1のRed起動前。条件付き）", "- G2（手順1のRed起動前）"),
            "gate-cond",
        ),
        (
            "SKILL.mdのG3に「条件付き」が付いている",
            sub(sk, "- G3（手順3の前）", "- G3（手順3の前。条件付き）"),
            "gate-cond",
        ),
        (
            "SKILL.mdの最終応答の報告文にG2の扱いが無い",
            sub(sk, "。G2は設計書が無ければ「G2: 設計書なし（探索: …）」", ""),
            "gate-cond-report",
        ),
        (
            "SKILL.mdのG2のファイルが違う",
            sub(
                sk,
                "もあれば`references/design/design-intent.md`。",
                "もあれば`references/cvss/cvss.md`。",
            ),
            "gate-files",
        ),
        (
            "モード2のゲートM4の行の欠落",
            sub(sk, "**遅延ロード（ゲートM4", "**遅延（ゲートM4"),
            "m2-gate",
        ),
        (
            "モード2のゲートM4からcvss-scoringを消す",
            sub(sk, "と`references/cvss/cvss-scoring.md`（5fの判定基準", "と（5fの判定基準"),
            "m2-gate",
        ),
        (
            "モード2の条件付き必読(d)の欠落",
            sub(sk, "(d) 設計書の候補", "(e) 設計書の候補"),
            "m2-cond",
        ),
        ("G2のファイルの欠落", remove(di), "gate-exist"),
        (
            "design-fields.mdの欠落（Red/Blue用。ゲート対象外）",
            remove(df),
            "ref-missing",
        ),
        (
            "design-audit.mdの欠落（5e専用監査用。ゲート対象外）",
            remove(da),
            "ref-missing",
        ),
        (
            "design-integrated.mdの欠落（統合修正版用。ゲート対象外）",
            remove(dg),
            "ref-missing",
        ),
        ("G2のGATE-TOKEN行の欠落", rsub(di, tok + "\n", ""), "tok-missing"),
        (
            "G2のトークンとゲートの不一致",
            rsub(di, "^GATE-TOKEN:G2-", "GATE-TOKEN:G3C-"),
            "tok-gate",
        ),
        (
            "G2ファイルのキー文の欠落",
            sub(di, "本ファイルはゲートG2", "本ファイルはG2"),
            "tok-key",
        ),
        (
            "想定外のGATE-TOKEN行",
            append(pr, "GATE-TOKEN:G3C-abcdef\n"),
            "tok-unexpected",
        ),
        ("トークンファイルの欠落", remove(html), "tok-nofile"),
        ("GATE-TOKEN行の欠落", rsub(rep, tok + "\n", ""), "tok-missing"),
        (
            "GATE-TOKEN行の重複（同じファイル）",
            rsub(html, f"({tok}\n)", r"\1\1"),
            "tok-multi",
        ),
        ("GATE-TOKEN行の形式不正", rsub(html, tok, "GATE-TOKEN:G6-XYZ"), "tok-format"),
        (
            "トークンとゲートの不一致",
            rsub(html, "^GATE-TOKEN:G6-", "GATE-TOKEN:G7-"),
            "tok-gate",
        ),
        ("トークンのファイルが一覧に無い", sub(sk, f"`{fa}`, ", ""), "tok-unlisted"),
        ("GATE-TOKEN行が先頭の追加ブロックの外", move_token, "tok-pos"),
        ("トークン名の重複（G3B→G3A）", sub(cs, "G3B-", "G3A-"), "tok-dup-name"),
        ("トークン値の重複（別ファイル）", same_hex, "tok-dup-value"),
        ("トークン値の漏洩", leak, "tok-leak"),
        (
            "ゲートファイルのキー文の欠落",
            sub(html, "本ファイルはゲートG6で", "本ファイルはG6で"),
            "tok-key",
        ),
        (
            "G1の一覧にトークンファイルが無い",
            rsub(sk, r"^(- G1（[^）]*）: )`[^`]*`", r"\1"),
            "tok-gate-none",
        ),
        ("GATE-TOKEN行の総数の不一致", append(pr, "GATE-TOKENの説明\n"), "tok-total"),
        ("参照先の消失", remove("references/modes/category-map.md"), "ref-missing"),
        (
            "裸のファイル名が見つからない",
            append(pr, "\n`no-such-file.md`\n"),
            "ref-bare",
        ),
        ("SKILL.mdの欠落", remove(sk), "no-skill"),
        ("SKILL.mdがUTF-8でない", raw(sk, lambda b: b"\xff" + b), "gate-noskill"),
        ("読めない文書（ディレクトリ）", mkdir("references/dir.md"), "read"),
        ("frontmatterが閉じずに終わる", create(sk, "---\nname: x\n"), "fm-close"),
        ("VERSIONS.jsonの欠落", remove(vj), "ver-missing"),
        ("VERSIONS.jsonがJSONでない", create(vj, "{broken"), "ver-json"),
        (
            "VERSIONSのschemaが違う",
            jedit(vj, lambda d: d.update(schema=2)),
            "ver-schema",
        ),
        (
            "VERSIONSのsourcesが空",
            jedit(vj, lambda d: d.update(sources={})),
            "ver-schema",
        ),
        (
            "VERSIONSのstale_after_monthsが不正",
            jedit(vj, lambda d: d.update(stale_after_months=0)),
            "ver-field",
        ),
        (
            "VERSIONSの確認日の形式不正",
            jedit(vj, lambda d: d["sources"]["asvs"].update(confirmed_on="2026-9-2")),
            "ver-field",
        ),
        (
            "VERSIONSのadoptedが空",
            jedit(vj, lambda d: d["sources"]["ipa"].update(adopted="")),
            "ver-field",
        ),
        (
            "VERSIONSの影響ファイルが実在しない",
            jedit(
                vj,
                lambda d: d["sources"]["asvs"]["affects"][0].update(
                    file="references/x.md"
                ),
            ),
            "ver-file",
        ),
        (
            "採用版の文字列がreferencesの本文に無い（referencesの版を変えた）",
            lambda d: put(d, pr, text(d, pr).replace("v5.0.0", "v5.1.0")),
            "ver-text",
        ),
        (
            "VERSIONSの確認日が実在しない日付",
            jedit(vj, lambda d: d["sources"]["ipa"].update(confirmed_on="2026-02-30")),
            "ver-field",
        ),
        (
            "VERSIONSのconfirmed_basisが不正",
            jedit(vj, lambda d: d["sources"]["ipa"].update(confirmed_basis="user")),
            "ver-field",
        ),
        (
            "VERSIONSのadopted_inが誤り（別のファイルを指す）",
            jedit(
                vj,
                lambda d: d["sources"]["ipa"].update(adopted_in="references/cvss/cvss.md"),
            ),
            "ver-text",
        ),
        (
            "VERSIONSのadopted_inが実在しないファイル",
            jedit(
                vj, lambda d: d["sources"]["ipa"].update(adopted_in="references/x.md")
            ),
            "ver-text",
        ),
        (
            "VERSIONSのreferencedのfileがsheetsに無い",
            jedit(
                vj,
                lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"][
                    "referenced"
                ][0].update(file="No_Such_Cheat_Sheet"),
            ),
            "ver-field",
        ),
        (
            "確認日がreferencesの本文と違う（CWE）",
            sub("references/sources/cwe-top25.md", "確認日 2026-10-10", "確認日 2026-10-11"),
            "ver-date",
        ),
        (
            "確認日がreferencesの本文と違う（ASVS）",
            sub(pr, "確認日: 2026-09-02", "確認日: 2026-09-03"),
            "ver-date",
        ),
        (
            "check_sources.pyの欠落（検証を読み込めない）",
            remove("scripts/check_sources.py"),
            "ver-import",
        ),
        (
            "採用版の文字列がreferencesの本文に無い（CWEの年度を変えた）",
            sub(
                "references/sources/cwe-top25.md", "CWE Top 25 2025年版", "CWE Top 25 2026年版"
            ),
            "ver-text",
        ),
        (
            "CWEの順位がreferencesの表と違う（表の行の入れ替え）",
            swap("references/sources/cwe-top25.md", r"^\| CWE-79 \|", r"^\| CWE-89 \|"),
            "ver-rank",
        ),
        (
            "Cheat Sheet名がreferencesの表と違う（VERSIONS側の削除）",
            jedit(
                vj,
                lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"][
                    "referenced"
                ].pop(0),
            ),
            "ver-sheets",
        ),
        (
            "Cheat Sheet名がreferencesの表と違う（referencesに足した）",
            sub(
                "references/sources/owasp-cheatsheets.md",
                "File Upload |",
                "File Upload, New Sheet |",
            ),
            "ver-sheets",
        ),
    ]
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        ng, warn, _ = check(fresh(td, "ok"))
        if ng or warn:
            fails += 1
            print("[失敗] 正常系がOKでない:", (ng + warn)[:3])
        else:
            print("[OK] 正常系（NG・WARNなし）")
        for i, (name, mutate, code) in enumerate(cases):
            kind = "warn" if code in WARN_CODES else "ng"
            clean = kind == "warn" and code != "size-gone"
            d = fresh(td, f"c{i}")
            try:  # 置換の空振り等は失敗として記録し、残りのケースを続ける
                mutate(d)
            except (AssertionError, OSError, StopIteration, ValueError) as e:
                fails += 1
                print(f"[前提崩れ] {name}: {type(e).__name__} {e}")
                continue
            ng, warn, _ = check(d)
            hit = [
                m for m in (ng if kind == "ng" else warn) if m.startswith(f"[{code}]")
            ]
            if not hit:
                fails += 1
                print(
                    f"[未検出!] {name}（期待: {kind} [{code}]）NG={ng[:2]} WARN={warn[:2]}"
                )
            elif clean and ng:
                fails += 1
                print(f"[失敗] {name}: WARNのみのはずがNGもある {ng[:2]}")
            else:
                print(f"[{'NG' if kind == 'ng' else 'WARN'}検出] {name} -> {hit[0]}")
            if code == "g0-budget" and any(m.startswith("[size-max]") for m in ng):
                fails += 1
                print(
                    f"[失敗] {name}: サイズ超過も出ている（G0単独の検出になっていない）"
                )
    if fails:
        print(f"self-test NG ({fails}件)")
        return False
    print(f"self-test OK (正常系 + 破壊{len(cases)}ケース全て想定のコードで検出)")
    return True


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
