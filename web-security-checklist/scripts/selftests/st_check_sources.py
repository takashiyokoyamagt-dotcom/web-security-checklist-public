"""check_sources.py の自己検査（--self-test）の本体。本体から分けた（読込を減らすため。P6）。
単独では実行しない。`python3 scripts/check_sources.py --self-test` が呼ぶ。
本体のモジュールの名前（関数・定数）をこのモジュールの名前空間に写してから、元のコードをそのまま実行する。"""
from __future__ import annotations

import argparse
import datetime
import difflib
import html
import http.client
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_MAIN_FILE = None  # 本体のファイルのパス（_st_entry が入れる）
_MAIN_GLOBALS = None  # 本体の globals()。本体の定数を一時的に変える検査はここを書き換える


# 自己テスト用の VERSIONS.json 相当のデータ（同梱の references/sources/VERSIONS.json とは独立。
# 更新手順で VERSIONS.json の確認日や採用版を変えても自己テストが落ちないようにする）
_CATS = ["1 入力値検証", "2 認証"]
_SHEETS = [f"Sheet{i:02d}_Cheat_Sheet" for i in range(20)] + [
    "Input_Validation_Cheat_Sheet",
    "Logging_Cheat_Sheet",
    "Session_Management_Cheat_Sheet",
    "Password_Storage_Cheat_Sheet",
    "Mass_Assignment_Cheat_Sheet",
    "HTTP_Headers_Cheat_Sheet",
]
TEST_DOC = {
    "schema": 1,
    "stale_after_months": 6,
    "sources": {
        "asvs": {
            "title": "OWASP ASVS",
            "adopted": "v5.0.0",
            "adopted_text": "v5.0.0",
            "adopted_in": "references/checklists/principles.md",
            "confirmed_on": "2026-09-02",
            "confirmed_basis": "human",
            "check": {
                "method": "github_releases",
                "url": "https://api.github.com/repos/OWASP/ASVS/releases?per_page=30",
                "page": "https://github.com/OWASP/ASVS/releases",
            },
            "affects": [{"file": "references/checklists/principles.md", "categories": _CATS}],
        },
        "cwe_top25": {
            "title": "CWE Top 25",
            "adopted": "2025",
            "adopted_text": "2025年版",
            "adopted_in": "references/sources/cwe-top25.md",
            "adopted_detail": {
                "ranking": ["CWE-79", "CWE-89"] + [f"CWE-{1000 + i}" for i in range(23)]
            },
            "confirmed_on": "2026-10-10",
            "confirmed_basis": "human",
            "check": {
                "method": "cwe_top25",
                "url": "https://cwe.mitre.org/top25/",
                "list_url": (
                    "https://cwe.mitre.org/top25/archive/{year}/{year}_cwe_top25.html"
                ),
                "page": "https://cwe.mitre.org/top25/",
            },
            "affects": [
                {"file": "references/sources/cwe-top25.md", "categories": [], "scope": "表"},
                {"file": "references/checklists/principles.md", "categories": _CATS},
            ],
        },
        "ipa": {
            "title": "IPA「安全なウェブサイトの作り方」",
            "adopted": "改訂第7版",
            "adopted_text": "改訂第7版",
            "adopted_in": "references/sources/ipa-secure-website.md",
            "adopted_detail": {"printing": 4, "published": "2021-03-31"},
            "confirmed_on": "2026-10-12",
            "confirmed_basis": "introduced",
            "check": {
                "method": "ipa_page",
                "url": "https://www.ipa.go.jp/security/vuln/websecurity/about.html",
            },
            "affects": [{"file": "references/sources/ipa-secure-website.md", "categories": []}],
        },
        "owasp_cheatsheets": {
            "title": "OWASP Cheat Sheet Series",
            "adopted": "シート一覧",
            "adopted_in": "references/sources/owasp-cheatsheets.md",
            "adopted_detail": {
                "sheets": _SHEETS,
                "referenced": [
                    {
                        "name": "Input Validation",
                        "file": "Input_Validation_Cheat_Sheet",
                    },
                    {"name": "Logging", "file": "Logging_Cheat_Sheet"},
                    {
                        "name": "Session Management",
                        "file": "Session_Management_Cheat_Sheet",
                    },
                    {
                        "name": "Password Storage",
                        "file": "Password_Storage_Cheat_Sheet",
                    },
                    {
                        "name": "HTTP Security Response Headers",
                        "file": None,
                        "likely_current": "HTTP_Headers_Cheat_Sheet",
                    },
                ],
            },
            "confirmed_on": "2026-10-12",
            "confirmed_basis": "introduced",
            "check": {
                "method": "github_dir",
                "url": (
                    "https://api.github.com/repos/OWASP/CheatSheetSeries"
                    "/contents/cheatsheets"
                ),
                "page": "https://cheatsheetseries.owasp.org/",
            },
            "affects": [{"file": "references/sources/owasp-cheatsheets.md", "categories": []}],
            "known_issues": ["テスト用の既知の課題"],
        },
    },
}


def self_test() -> int:
    import contextlib
    import copy
    import email.message
    import io
    import tempfile

    fails = 0

    def check(name, ok, detail=""):
        nonlocal fails
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}{'' if ok else ': ' + str(detail)}")

    today = datetime.date(2026, 10, 12)
    real_path = default_versions()
    real = copy.deepcopy(
        TEST_DOC
    )  # 以降のテストの入力。同梱の VERSIONS.json には依存しない
    check("テスト用の TEST_DOC が検証を通る", validate_versions(real) == [])
    try:
        load_versions(real_path)
        check("同梱の VERSIONS.json が検証を通る", True)
    except VersionsError as e:
        check("同梱の VERSIONS.json が検証を通る", False, e)
    S = real["sources"]

    def js(o):
        return json.dumps(o).encode()

    def fake(table):
        """URL→bytes か例外の表から get を作る（呼ばれたURLを calls に記録）"""
        calls = []

        def get(url):
            calls.append(url)
            if url not in table:
                raise FetchError(f"想定外のURL {url}", retry=False)
            v = table[url]
            if isinstance(v, Exception):
                raise v
            return v

        get.calls = calls
        return get

    def runone(key, table, mutate=None, doc=None):
        d = copy.deepcopy(doc or real)
        if mutate:
            mutate(d["sources"][key])
        g = fake(table)
        return one(key, d["sources"][key], g, False, today), g

    # --- ASVS ---
    au = S["asvs"]["check"]["url"]

    def rel(
        tag, pre=False, draft=False, name="n", body="b", pub="2025-05-30T09:35:31Z"
    ):
        return {
            "tag_name": tag,
            "prerelease": pre,
            "draft": draft,
            "name": name,
            "body": body,
            "published_at": pub,
            "html_url": f"https://github.com/x/releases/tag/{tag}",
        }

    base_rel = [
        rel("latest", name="Bleeding Edge"),
        rel("v5.0.0_release"),
        rel("v4.0.3_release"),
    ]
    r, g = runone("asvs", {au: js(base_rel)})
    check(
        "ASVS: 一致（開発版タグ latest は無視。1リクエスト）",
        r["status"] == "same" and r["latest"] == "v5.0.0" and len(g.calls) == 1,
        r,
    )
    r, _ = runone(
        "asvs", {au: js([rel("v5.1.0_release", body="新機能\n\n追加 V18"), *base_rel])}
    )
    check(
        "ASVS: マイナー更新は差あり（抜粋・URL・新しい版の列挙）",
        r["status"] == "diff"
        and r["latest"] == "v5.1.0"
        and r["details"]["newer_versions"] == ["v5.1.0"]
        and "新機能 追加 V18" in r["details"]["notes_excerpt"]
        and r["details"]["release_url"].endswith("v5.1.0_release")
        and r["details"]["tree_url"].endswith("/tree/v5.1.0_release"),
        r,
    )
    r, _ = runone("asvs", {au: js([rel("v6.0.0"), rel("v5.1.0_release"), *base_rel])})
    check(
        "ASVS: メジャー更新は差あり（章構成の注意・タグ形式の違いを許す）",
        r["status"] == "diff"
        and r["latest"] == "v6.0.0"
        and any("メジャー" in c for c in r["changes"])
        and r["details"]["newer_versions"] == ["v5.1.0", "v6.0.0"],
        r,
    )
    r, _ = runone(
        "asvs",
        {au: js([rel("v6.0.0", pre=True), rel("v7.0.0", draft=True), *base_rel])},
    )
    check("ASVS: prerelease・draft は無視", r["status"] == "same", r)
    r, _ = runone("asvs", {au: js([rel("latest")])})
    check(
        "ASVS: 安定版のタグが無ければ確認できず",
        r["status"] == "unknown" and r["reason"],
        r,
    )
    r, _ = runone("asvs", {au: b"{not json"})
    check(
        "ASVS: JSON壊れは確認できず（Tracebackにしない）",
        r["status"] == "unknown" and "JSON" in r["reason"],
        r,
    )
    r, _ = runone("asvs", {au: js({"message": "API rate limit exceeded"})})
    check(
        "ASVS: 配列でない応答は確認できず（メッセージ付き）",
        r["status"] == "unknown" and "rate limit" in r["reason"],
        r,
    )
    r, _ = runone("asvs", {au: FetchError("タイムアウト")})
    check(
        "ASVS: タイムアウトは確認できず",
        r["status"] == "unknown" and r["reason"] == "タイムアウト",
        r,
    )
    r, _ = runone("asvs", {au: js([rel("v4.0.3_release")])})
    check(
        "ASVS: 採用版が最新より新しいと差あり（想定外の注記）",
        r["status"] == "diff" and any("想定外" in c for c in r["changes"]),
        r,
    )
    r, _ = runone(
        "asvs", {au: js(base_rel)}, lambda s: s.update(adopted="v5.0.0_release")
    )
    check(
        "ASVS: VERSIONSのadoptedが _release 付きでも比較できる",
        r["status"] == "same",
        r,
    )

    # --- CWE ---
    cu, tpl = S["cwe_top25"]["check"]["url"], S["cwe_top25"]["check"]["list_url"]
    old_rank = S["cwe_top25"]["adopted_detail"]["ranking"]

    def arch(*years):
        return "".join(
            f'<a href="/top25/archive/{y}/{y}_cwe_top25.html">{y}</a>' for y in years
        ).encode()

    def table(ids):
        rows = "".join(
            f'<tr><td style="x"><b>{i + 1}</b></td>\n'
            f'<td><a href="/d/{c[4:]}.html">{c}</a></td><td>n</td></tr>'
            for i, c in enumerate(ids)
        )
        return f"<table>{rows}</table>".encode()

    r, g = runone("cwe_top25", {cu: arch(2023, 2024, 2025)})
    check(
        "CWE: 一致（1リクエスト）",
        r["status"] == "same" and r["latest"] == "2025" and len(g.calls) == 1,
        r,
    )
    new_rank = ["CWE-89", "CWE-79"] + old_rank[2:24] + ["CWE-1321"]
    r, g = runone(
        "cwe_top25",
        {cu: arch(2024, 2025, 2026), tpl.format(year=2026): table(new_rank)},
    )
    ch = r["changes"]
    check(
        "CWE: 年の繰り上がりは差あり（追加・除外・順位変動を出す。2リクエスト）",
        r["status"] == "diff"
        and r["latest"] == "2026"
        and "追加: CWE-1321（25位）" in ch
        and f"除外: {old_rank[24]}（旧25位）" in ch
        and "順位変動: CWE-79 1位→2位" in ch
        and "順位変動: CWE-89 2位→1位" in ch
        and len(g.calls) == 2,
        r,
    )
    r, _ = runone(
        "cwe_top25",
        {
            cu: arch(2025, 2026),
            tpl.format(year=2026): FetchError("HTTP 404", retry=False),
        },
    )
    check(
        "CWE: 年は違うが順位表を取得できないときも差あり（未確認と明記）",
        r["status"] == "diff" and any("未確認" in c for c in r["changes"]),
        r,
    )
    r, _ = runone(
        "cwe_top25",
        {cu: arch(2025, 2026), tpl.format(year=2026): b"<html>no table</html>"},
    )
    check(
        "CWE: 順位表を解析できないときも差あり（未確認と明記）",
        r["status"] == "diff" and any("未確認" in c for c in r["changes"]),
        r,
    )
    r, _ = runone(
        "cwe_top25", {cu: arch(2025, 2026), tpl.format(year=2026): table(old_rank)}
    )
    check(
        "CWE: 年は違うが順位が同じなら、その旨を出す",
        r["status"] == "diff" and any("同じ" in c for c in r["changes"]),
        r,
    )
    welcome = b"<p>Welcome to the 2026 Common Weakness Enumeration (CWE) Top 25</p>"
    r, _ = runone(
        "cwe_top25", {cu: arch(2025) + welcome, tpl.format(year=2026): table(old_rank)}
    )
    check(
        "CWE: リンクより新しい「Welcome to the YYYY」の年も拾う",
        r["status"] == "diff" and r["latest"] == "2026",
        r,
    )
    r, _ = runone("cwe_top25", {cu: b"<html>no links</html>"})
    check("CWE: 年が見つからなければ確認できず", r["status"] == "unknown", r)
    r, _ = runone("cwe_top25", {cu: arch(2099)})
    check("CWE: 未来すぎる年（2099）は無視して確認できず", r["status"] == "unknown", r)
    r, _ = runone(
        "cwe_top25", {cu: FetchError("証明書を検証できない", retry=False, cert=True)}
    )
    check(
        "CWE: 証明書エラーは確認できず",
        r["status"] == "unknown" and "証明書" in r["reason"],
        r,
    )

    # --- IPA ---
    iu = S["ipa"]["check"]["url"]

    def ipa(*entries):
        body = "".join(f"<li> 日本語版（{e}）</li>" for e in entries)
        fake_js = "<script>日本語版（2099年1月1日改訂第99版公開）</script>"
        return f"<html>{fake_js}<body>{body}<p>旧版（改訂第6版）</p></body></html>".encode()

    r, g = runone("ipa", {iu: ipa("2021年3月31日改訂第7版第4刷公開")})
    check(
        "IPA: 一致（1リクエスト）",
        r["status"] == "same" and r["latest"] == "改訂第7版" and len(g.calls) == 1,
        r,
    )
    r, _ = runone(
        "ipa", {iu: ipa("2021年3月31日改訂第7版第4刷公開", "2030年4月1日改訂第8版公開")}
    )
    check(
        "IPA: 版の繰り上がりは差あり（script内の偽の記述は無視）",
        r["status"] == "diff"
        and r["latest"] == "改訂第8版"
        and r["details"]["latest_edition"] == 8,
        r,
    )
    r, _ = runone("ipa", {iu: ipa("2027年1月5日改訂第7版第5刷公開")})
    check(
        "IPA: 同じ版の新しい刷・日付は差あり（刷の更新と説明）",
        r["status"] == "diff"
        and r["latest"] == "改訂第7版"
        and any("刷" in c for c in r["changes"]),
        r,
    )
    spaced = (
        "<html><body>\n日本語版（ 2021年 3月 31日\n改訂第7版第4刷公開）</body></html>"
    )
    r, _ = runone("ipa", {iu: spaced.encode()})
    check("IPA: 空白・改行が途中に入っていても読める", r["status"] == "same", r)
    r, _ = runone("ipa", {iu: "<html>サイトの変更</html>".encode()})
    check(
        "IPA: 版の記述が無ければ確認できず（推測しない）",
        r["status"] == "unknown" and r["latest"] is None,
        r,
    )
    r, _ = runone("ipa", {iu: ipa("2021年2月31日改訂第7版第4刷公開")})
    check("IPA: 実在しない日付は無視して確認できず", r["status"] == "unknown", r)
    r, _ = runone("ipa", {iu: FetchError("HTTP 503")})
    check(
        "IPA: HTTP 503 は確認できず",
        r["status"] == "unknown" and "503" in r["reason"],
        r,
    )
    r, _ = runone(
        "ipa",
        {iu: ipa("2021年3月31日改訂第7版第4刷公開")},
        lambda s: s["adopted_detail"].clear(),
    )
    check("IPA: 刷・日付の記録が無ければ版だけで比べる", r["status"] == "same", r)

    # --- Cheat Sheet ---
    ku = S["owasp_cheatsheets"]["check"]["url"]
    sheets = list(S["owasp_cheatsheets"]["adopted_detail"]["sheets"])

    def listing(stems, extra=()):
        return js([{"name": s + ".md", "type": "file"} for s in stems] + list(extra))

    r, g = runone(
        "owasp_cheatsheets",
        {
            ku: listing(
                sheets,
                [{"name": "README.md", "type": "file"}, {"name": "sub", "type": "dir"}],
            )
        },
    )
    check(
        "Cheat Sheet: 一致（シート以外のファイル・ディレクトリは無視。1リクエスト）",
        r["status"] == "same" and len(g.calls) == 1,
        r,
    )
    r, _ = runone(
        "owasp_cheatsheets", {ku: listing(sheets + ["Brand_New_Cheat_Sheet"])}
    )
    check(
        "Cheat Sheet: 追加は差あり",
        r["status"] == "diff"
        and r["details"]["added"] == ["Brand_New_Cheat_Sheet"]
        and any("追加: Brand New" in c for c in r["changes"]),
        r,
    )
    kept = [
        s
        for s in sheets
        if s != "Logging_Cheat_Sheet" and s != "Session_Management_Cheat_Sheet"
    ]
    r, _ = runone("owasp_cheatsheets", {ku: listing(kept)})
    check(
        "Cheat Sheet: 削除は差あり（参照中のシートの削除を最初に警告）",
        r["status"] == "diff"
        and r["changes"][0].startswith("references/sources/owasp-cheatsheets.md が参照中")
        and "Logging" in r["changes"][0]
        and "Session Management" in r["changes"][0],
        r,
    )
    ren = [
        (
            s
            if s != "Password_Storage_Cheat_Sheet"
            else "Password_Storage_And_Hashing_Cheat_Sheet"
        )
        for s in sheets
    ]
    r, _ = runone("owasp_cheatsheets", {ku: listing(ren)})
    check(
        "Cheat Sheet: 改名は削除＋追加で示し、改名の可能性を添える",
        r["status"] == "diff"
        and r["details"]["removed"] == ["Password_Storage_Cheat_Sheet"]
        and r["details"]["added"] == ["Password_Storage_And_Hashing_Cheat_Sheet"]
        and r["details"]["rename_candidates"]
        == [
            ["Password_Storage_Cheat_Sheet", "Password_Storage_And_Hashing_Cheat_Sheet"]
        ]
        and any("改名の可能性" in c for c in r["changes"]),
        r,
    )
    ren3 = [
        (
            s
            if s != "Mass_Assignment_Cheat_Sheet"
            else "Mass_Assignment_Prevention_Cheat_Sheet"
        )
        for s in sheets
    ]
    ren3 = [
        (
            s
            if s != "HTTP_Headers_Cheat_Sheet"
            else "HTTP_Security_Response_Headers_Cheat_Sheet"
        )
        for s in ren3
    ]
    r, _ = runone("owasp_cheatsheets", {ku: listing(ren3)})
    check(
        "Cheat Sheet: 単語が増えた改名（語の包含）も改名の可能性にする",
        r["status"] == "diff"
        and sorted(r["details"]["rename_candidates"])
        == [
            ["HTTP_Headers_Cheat_Sheet", "HTTP_Security_Response_Headers_Cheat_Sheet"],
            ["Mass_Assignment_Cheat_Sheet", "Mass_Assignment_Prevention_Cheat_Sheet"],
        ],
        r["details"],
    )
    ren2 = [s if s != "Logging_Cheat_Sheet" else "Zebra_Cheat_Sheet" for s in sheets]
    r, _ = runone("owasp_cheatsheets", {ku: listing(ren2)})
    check(
        "Cheat Sheet: 名前が遠い削除・追加は改名の可能性にしない",
        r["status"] == "diff" and r["details"]["rename_candidates"] == [],
        r,
    )
    r, _ = runone("owasp_cheatsheets", {ku: js({"message": "Not Found"})})
    check(
        "Cheat Sheet: 配列でない応答は確認できず",
        r["status"] == "unknown" and "Not Found" in r["reason"],
        r,
    )
    r, _ = runone("owasp_cheatsheets", {ku: js([])})
    check(
        "Cheat Sheet: 空の一覧は確認できず（全削除と誤判定しない）",
        r["status"] == "unknown",
        r,
    )
    r, _ = runone(
        "owasp_cheatsheets",
        {
            ku: js(
                [
                    {"name": f"X{i}_Cheat_Sheet.md", "type": "file"}
                    for i in range(DIR_LIMIT)
                ]
            )
        },
    )
    check(
        "Cheat Sheet: 上限件数の一覧は欠落の可能性で確認できず",
        r["status"] == "unknown" and "上限" in r["reason"],
        r,
    )
    r, _ = runone(
        "owasp_cheatsheets",
        {
            ku: FetchError(
                rate_limit_msg(
                    {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1791764487"}
                )
                or "",
                retry=False,
            )
        },
    )
    check(
        "Cheat Sheet: レート制限は確認できず（回復時刻つき）",
        r["status"] == "unknown"
        and "60回/時" in r["reason"]
        and "UTC頃に回復" in r["reason"],
        r,
    )
    r, _ = runone("owasp_cheatsheets", {ku: js([1, None, "x", {"name": 5}])})
    check(
        "Cheat Sheet: 想定外の要素は無視（シートが無ければ確認できず）",
        r["status"] == "unknown",
        r,
    )

    # --- 通信層 ---
    def hdr(**kw):
        m = email.message.Message()
        for k, v in kw.items():
            m[k.replace("_", "-")] = v
        return m

    def raiser(exc):
        def op(req, timeout, ctx):
            raise exc

        return op

    def code(c, **h):
        return urllib.error.HTTPError("https://x", c, "m", hdr(**h), None)

    def fe(exc):
        try:
            get_once("https://x", 1, None, raiser(exc))
        except FetchError as e:
            return e
        return None

    e = fe(code(403, X_RateLimit_Remaining="0", X_RateLimit_Reset="1791764487"))
    check(
        "通信: 403＋残り0はレート制限（再試行しない）",
        e and "レート制限" in str(e) and not e.retry,
        e,
    )
    e = fe(code(403, X_RateLimit_Remaining="12"))
    check(
        "通信: 残りがある403は一般のHTTPエラー",
        e and str(e) == "HTTP 403" and not e.retry,
        e,
    )
    e = fe(code(404))
    check("通信: 404 は再試行しない", e and str(e) == "HTTP 404" and not e.retry, e)
    e = fe(code(503))
    check("通信: 503 は再試行する", e and e.retry, e)
    e = fe(urllib.error.URLError(socket.timeout("t")))
    check("通信: タイムアウト", e and str(e) == "タイムアウト", e)
    e = fe(urllib.error.URLError(ssl.SSLCertVerificationError(1, "bad")))
    check(
        "通信: 証明書エラー（cert=True・再試行しない）", e and e.cert and not e.retry, e
    )
    e = fe(http.client.IncompleteRead(b""))
    check("通信: HTTP応答の異常", e and "異常" in str(e), e)
    check(
        "通信: 上限ちょうどの応答は受け入れる",
        len(get_once("https://x", 1, None, lambda r, t, c: b"x" * MAX_BYTES))
        == MAX_BYTES,
    )
    try:
        get_once("https://x", 1, None, lambda r, t, c: b"x" * (MAX_BYTES + 1))
        check("通信: 上限超過", False)
    except FetchError as ex:
        check("通信: 上限超過", "超える" in str(ex), ex)
    try:
        http_get("http://x/", 1)
        check("通信: HTTP（非TLS）のURLを拒否", False)
    except FetchError as ex:
        check("通信: HTTP（非TLS）のURLを拒否", "HTTPS以外" in str(ex), ex)
    seen = []

    def op2(req, timeout, ctx):
        seen.append((req.get_header("User-agent"), req.full_url, timeout))
        return b"ok"

    check(
        "通信: User-Agent に web-security-checklist・タイムアウトを渡す",
        get_once("https://x/y", 7, None, op2) == b"ok"
        and seen == [(UA, "https://x/y", 7)]
        and "web-security-checklist" in UA,
        seen,
    )
    n = []

    def flaky(url):
        n.append(url)
        if len(n) == 1:
            raise FetchError("HTTP 503")
        return b"ok"

    sl = []
    check(
        "通信: 503は1回だけ再試行（1秒待つ）",
        with_retry(flaky, sl.append)("u") == b"ok" and len(n) == 2 and sl == [1],
        (n, sl),
    )
    n2 = []

    def dead(url):
        n2.append(1)
        raise FetchError("HTTP 404", retry=False)

    try:
        with_retry(dead, sl.append)("u")
    except FetchError:
        pass
    check("通信: 404は再試行しない（1回）", len(n2) == 1)
    t = Tls(
        exists=lambda p: p == "/private/etc/ssl/cert.pem",
        paths=lambda: ssl.DefaultVerifyPaths(None, None, "", "", "", ""),
        make_ctx=lambda c: "ctx:" + c,
    )
    check(
        "通信: 既定のCAが無い環境では既知のバンドルへ1回だけ切り替える",
        t.fallback() and t.ctx == "ctx:/private/etc/ssl/cert.pem" and not t.fallback(),
        t.ctx,
    )

    # --- VERSIONS.json の検証 ---
    def bad(mutate, expect):
        d = copy.deepcopy(real)
        mutate(d)
        p = validate_versions(d)
        return any(expect in x for x in p), p

    for name, mut, exp in (
        ("schemaが違う", lambda d: d.update(schema=2), "schema"),
        ("sourcesが空", lambda d: d.update(sources={}), "sources"),
        (
            "キーが不正",
            lambda d: d["sources"].update({"Bad-Key": d["sources"]["asvs"]}),
            "原典のキー",
        ),
        ("adoptedが無い", lambda d: d["sources"]["asvs"].pop("adopted"), "adopted"),
        (
            "confirmed_onが実在しない日付",
            lambda d: d["sources"]["asvs"].update(confirmed_on="2026-02-30"),
            "confirmed_on",
        ),
        (
            "methodが未知",
            lambda d: d["sources"]["asvs"]["check"].update(method="x"),
            "check.method",
        ),
        (
            "urlがhttpsでない",
            lambda d: d["sources"]["asvs"]["check"].update(url="http://x"),
            "check.url",
        ),
        ("affectsが無い", lambda d: d["sources"]["asvs"].pop("affects"), "affects"),
        (
            "affectsのcategoriesが不正",
            lambda d: d["sources"]["asvs"]["affects"][0].update(categories="x"),
            "affects[0]",
        ),
        (
            "ASVSの版の形式が不正",
            lambda d: d["sources"]["asvs"].update(adopted="5"),
            "v5.0.0",
        ),
        (
            "CWEの年が不正",
            lambda d: d["sources"]["cwe_top25"].update(adopted="25"),
            "4桁の年",
        ),
        (
            "CWEの順位に重複",
            lambda d: d["sources"]["cwe_top25"]["adopted_detail"].update(
                ranking=["CWE-1", "CWE-1"]
            ),
            "ranking",
        ),
        (
            "list_urlに{year}が無い",
            lambda d: d["sources"]["cwe_top25"]["check"].update(list_url="https://x/"),
            "list_url",
        ),
        (
            "IPAの版の形式が不正",
            lambda d: d["sources"]["ipa"].update(adopted="7"),
            "改訂第N版",
        ),
        (
            "IPAの刷が不正",
            lambda d: d["sources"]["ipa"]["adopted_detail"].update(printing="4"),
            "printing",
        ),
        (
            "IPAの日付が不正",
            lambda d: d["sources"]["ipa"]["adopted_detail"].update(
                published="2021-13-01"
            ),
            "published",
        ),
        (
            "シート一覧が重複",
            lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"].update(
                sheets=["a", "a"]
            ),
            "sheets",
        ),
        (
            "シート一覧が空",
            lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"].update(
                sheets=[]
            ),
            "sheets",
        ),
        (
            "referencedが不正",
            lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"].update(
                referenced=[1]
            ),
            "referenced",
        ),
        (
            "confirmed_basisが無い",
            lambda d: d["sources"]["asvs"].pop("confirmed_basis"),
            "confirmed_basis",
        ),
        (
            "confirmed_basisが不正",
            lambda d: d["sources"]["asvs"].update(confirmed_basis="user"),
            "confirmed_basis",
        ),
        (
            "referencedのfileがsheetsに無い",
            lambda d: d["sources"]["owasp_cheatsheets"]["adopted_detail"]["referenced"][
                0
            ].update(file="Nope_Cheat_Sheet"),
            "sheets に無い",
        ),
        (
            "known_issuesが不正",
            lambda d: d["sources"]["asvs"].update(known_issues="x"),
            "known_issues",
        ),
    ):
        ok, p = bad(mut, exp)
        check(f"VERSIONS検証: {name}をNGにする", ok, p)
    check("VERSIONS検証: 最上位が配列ならNG", validate_versions([]) != [])

    # --- main（引数・終了コード・出力） ---
    def cli(argv, table=None, versions=None, doc=None, clock=None, raw=None, inject_today=True):
        a = parse_args(argv)
        if doc is None and versions is None:
            doc = copy.deepcopy(TEST_DOC)
        if doc is not None:
            tf = tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8"
            )
            json.dump(doc, tf)
            tf.close()
            a.versions = tf.name
        elif versions is not None:
            a.versions = versions
        g = fake(table or {})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            t = today if inject_today else None
            rc = main(a, None, t, clock, raw) if raw else main(a, g, t)
        if doc is not None:
            os.unlink(a.versions)
        return rc, out.getvalue(), err.getvalue(), g

    ok_table = {
        au: js(base_rel),
        cu: arch(2025),
        iu: ipa("2021年3月31日改訂第7版第4刷公開"),
        ku: listing(sheets),
    }
    rc, out, err, g = cli([], ok_table)
    check(
        "CLI: 全部一致は rc=0・各原典1リクエスト（計4）",
        rc == 0
        and out.count("[一致]") == 4
        and "差あり0件・一致4件" in out
        and len(g.calls) == 4,
        (rc, out),
    )
    rc, out, err, g = cli(
        [], {**ok_table, cu: arch(2025, 2026), tpl.format(year=2026): table(old_rank)}
    )
    check(
        "CLI: 差ありは rc=10・警告文・影響範囲・既知の課題の表示",
        rc == 10
        and "[差あり] CWE Top 25" in out
        and "影響: references/sources/cwe-top25.md" in out
        and "更新するかはユーザーに確認" in out
        and "既知の課題:" in out,
        (rc, out),
    )
    rc, out, err, g = cli([], {**ok_table, iu: FetchError("HTTP 503", retry=False)})
    check(
        "CLI: 確認できずのみは rc=0・警告にしない",
        rc == 0
        and "[確認できず] IPA" in out
        and "警告あり" not in out
        and "確認できず1件" in out,
        (rc, out),
    )
    rc, out, err, g = cli(["--offline"])
    check(
        "CLI: --offline は通信せず rc=0（確認せず4件）",
        rc == 0 and out.count("[確認せず]") == 4 and not g.calls,
        (rc, out, g.calls),
    )
    rc, out, err, g = cli(["--source", "ipa"], ok_table)
    check(
        "CLI: --source は指定した原典だけ確認する",
        rc == 0 and g.calls == [iu] and out.count("[一致]") == 1,
        (rc, g.calls),
    )
    rc, out, err, g = cli(["--source", "nope"], ok_table)
    check(
        "CLI: 未知の --source は rc=2",
        rc == 2 and "nope" in err and not g.calls,
        (rc, err),
    )
    rc, out, err, g = cli(
        ["--json"], {**ok_table, ku: listing(sheets + ["New_Cheat_Sheet"])}
    )
    try:
        doc = json.loads(out)
    except ValueError:
        doc = {}
    check(
        "CLI: --json はJSON（summary・warn・results）で rc=10",
        rc == 10
        and doc.get("warn") is True
        and doc.get("summary", {}).get("diff") == 1
        and len(doc.get("results", [])) == 4
        and doc["results"][3]["status"] == "diff"
        and doc["results"][3]["details"]["added"] == ["New_Cheat_Sheet"]
        and doc.get("schema") == SCHEMA,
        (rc, out[:200]),
    )
    d2 = copy.deepcopy(real)
    del d2["sources"]["asvs"]["check"]
    rc, out, err, g = cli([], ok_table, doc=d2)
    check(
        "CLI: VERSIONS.json が不正なら rc=2（通信しない）",
        rc == 2 and "check" in err and not g.calls,
        (rc, err),
    )
    rc, out, err, g = cli([], ok_table, versions="/nonexistent/VERSIONS.json")
    check(
        "CLI: VERSIONS.json が無ければ rc=2", rc == 2 and "読めない" in err, (rc, err)
    )
    tf = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    )
    tf.write("{broken")
    tf.close()
    rc, out, err, g = cli([], ok_table, versions=tf.name)
    os.unlink(tf.name)
    check(
        "CLI: VERSIONS.json がJSONでなければ rc=2", rc == 2 and "JSON" in err, (rc, err)
    )
    argc = []
    for argv in (
        ["--timeout", "0"],
        ["--timeout", "nan"],
        ["--timeout", "-1"],
        ["--timeout", "inf"],
        ["--bogus"],
    ):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(argv)
            argc.append(0)
        except SystemExit as ex:
            argc.append(ex.code)
    check("CLI: 不正な引数は rc=2", argc == [2] * 5, argc)
    a = parse_args([])
    check(
        "CLI: 既定は timeout=20・通信あり",
        a.timeout == 20.0 and not a.offline and not a.json and a.source is None,
        a,
    )
    # --- B: 確認日の経過（通信しない） ---
    D = datetime.date

    def st(conf, now, months=STALE_MONTHS):
        return stale_info(conf, now, months)

    check(
        "B: 6か月ちょうど（期限の当日）は古くない（既定は6か月）",
        STALE_MONTHS == 6
        and real.get("stale_after_months") == 6
        and not st("2026-04-12", D(2026, 10, 12))["stale"]
        and st("2026-04-12", D(2026, 10, 12))["due_on"] == "2026-10-12"
        and st("2026-04-12", D(2026, 10, 12))["months"] == 6,
    )
    check(
        "B: 期限の1日前は古くない・1日後は古い（超過1日）",
        not st("2026-04-12", D(2026, 10, 11))["stale"]
        and st("2026-04-12", D(2026, 10, 13))["stale"]
        and st("2026-04-12", D(2026, 10, 13))["overdue_days"] == 1,
    )
    x = st("2026-08-31", D(2027, 2, 28))
    y = st("2026-08-31", D(2027, 3, 1))
    check(
        "B: 月末の丸め（8/31+6か月＝翌2/28。2/28は古くない・3/1は古い）",
        x["due_on"] == "2027-02-28" and not x["stale"] and y["stale"],
        (x, y),
    )
    check(
        "B: 月末の丸め（うるう年は2/29。1/31+1か月、8/31+6か月、12/31+2か月）",
        add_months(D(2027, 11, 30), 3) == D(2028, 2, 29)
        and add_months(D(2028, 1, 31), 1) == D(2028, 2, 29)
        and add_months(D(2027, 1, 31), 1) == D(2027, 2, 28)
        and add_months(D(2026, 8, 31), 6) == D(2027, 2, 28)
        and add_months(D(2026, 12, 31), 2) == D(2027, 2, 28),
    )
    check(
        "B: うるう日(2/29)起点（+3か月＝5/29。+12か月＝翌年2/28。+48か月＝2/29）と年またぎ",
        add_months(D(2028, 2, 29), 3) == D(2028, 5, 29)
        and add_months(D(2028, 2, 29), 12) == D(2029, 2, 28)
        and add_months(D(2028, 2, 29), 48) == D(2032, 2, 29)
        and add_months(D(2026, 11, 15), 3) == D(2027, 2, 15)
        and add_months(D(2026, 10, 12), 24) == D(2028, 10, 12),
    )
    check(
        "B: 12月の繰り上がり（9/30+3か月＝12/30、10/31+2か月＝12/31、12/1+1か月＝翌1/1）",
        add_months(D(2026, 9, 30), 3) == D(2026, 12, 30)
        and add_months(D(2026, 10, 31), 2) == D(2026, 12, 31)
        and add_months(D(2026, 12, 1), 1) == D(2027, 1, 1),
    )
    f = st("2026-10-20", D(2026, 10, 12))
    check(
        "B: 確認日が未来は state=future で古いに数える（経過は負）",
        f["state"] == "future" and f["stale"] and f["elapsed_days"] == -8,
        f,
    )
    check(
        "B: 経過日数（2026-09-02 → 2026-10-12 は40日）",
        st("2026-09-02", D(2026, 10, 12))["elapsed_days"] == 40,
    )
    check(
        "B: N か月の上書き（1か月なら40日経過は古い、6か月なら古くない）",
        st("2026-09-02", D(2026, 10, 12), 1)["stale"]
        and not st("2026-09-02", D(2026, 10, 12), 6)["stale"],
    )

    def stale_doc(months=None, conf="2026-03-01"):
        d = copy.deepcopy(real)
        for k in d["sources"]:
            d["sources"][k]["confirmed_on"] = conf
        if months is None:
            d.pop("stale_after_months", None)
        else:
            d["stale_after_months"] = months
        return d

    # 確認日 2026-03-01 は、2026-10-12 には6か月（9/1）を過ぎている
    rc, out, err, g = cli(["--offline", "--today", "2026-10-12"], doc=stale_doc())
    check(
        "B: --offline でも評価する（全て古い→ rc=11・警告行・通信なし）",
        rc == 11
        and out.count("[警告] 確認日が古い") == 4
        and "確認日が古い4件" in out
        and not g.calls,
        (rc, out),
    )
    rc, out, err, g = cli(["--offline", "--today", "2026-09-01"], doc=stale_doc())
    check(
        "B: --offline で期限の当日は警告なし（rc=0）",
        rc == 0 and "[警告]" not in out and "確認日が古い0件" in out,
        (rc, out),
    )
    all_fail = {k: FetchError("HTTP 503", retry=False) for k in (au, cu, iu, ku)}
    rc, out, err, g = cli(["--today", "2026-10-12"], all_fail, doc=stale_doc())
    check(
        "B: 取得が全て確認できずでも評価する（rc=11。確認できずは警告にしない）",
        rc == 11
        and out.count("[確認できず]") == 4
        and out.count("[警告] 確認日が古い") == 4,
        (rc, out),
    )
    rc, out, err, g = cli(["--today", "2026-10-12"], all_fail)
    check(
        "B: 取得が確認できずで確認日も新しければ rc=0",
        rc == 0 and "確認日が古い0件" in out,
        (rc, out),
    )
    dd = stale_doc()
    rc, out, err, g = cli(
        ["--today", "2026-10-12"],
        {**ok_table, cu: arch(2025, 2026), tpl.format(year=2026): table(old_rank)},
        doc=dd,
    )
    check(
        "B: 差ありと古いが同時なら rc=10（Aが優先。両方表示）",
        rc == 10 and "[差あり] CWE" in out and "[警告] 確認日が古い" in out,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12", "--stale-months", "12"], doc=stale_doc()
    )
    check("B: --stale-months で上書き（12か月なら古くない）", rc == 0, (rc, out))
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12", "--stale-months", "3"],
        doc=stale_doc(conf="2026-06-01"),
    )
    check(
        "B: --stale-months 3 なら確認日 2026-06-01 は古い（既定の6か月では古くない）",
        rc == 11 and "3か月" in out,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12", "--stale-months", "1"],
        doc=stale_doc(months=12),
    )
    check(
        "B: --stale-months は VERSIONS.json の stale_after_months より優先",
        rc == 11 and "1か月" in out,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12"], doc=stale_doc(months=12)
    )
    check(
        "B: VERSIONS.json の stale_after_months が既定（12か月なら古くない）",
        rc == 0,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12"], doc=stale_doc(months=None)
    )
    check(
        "B: stale_after_months が無ければ6か月（確認日 2026-03-01 は古い）",
        rc == 11 and "6か月" in out,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12"],
        doc=stale_doc(months=None, conf="2026-06-01"),
    )
    check(
        "B: stale_after_months が無ければ6か月（確認日 2026-06-01 は古くない）",
        rc == 0 and "6か月の期限 2026-12-01" in out,
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--offline", "--json", "--today", "2026-10-12"], doc=stale_doc()
    )
    try:
        dj = json.loads(out)
    except ValueError:
        dj = {}
    r0 = (dj.get("results") or [{}])[0]
    check(
        "B: --json に stale（原典ごと）・warn_stale・stale_after_months が出る",
        rc == 11
        and dj.get("warn_stale") is True
        and dj.get("warn_diff") is False
        and dj.get("stale_after_months") == 6
        and dj["summary"]["stale"] == 4
        and r0.get("stale", {}).get("state") == "stale"
        and r0["stale"]["elapsed_days"] == 225
        and r0["stale"]["due_on"] == "2026-09-01"
        and r0["stale"]["overdue_days"] == 41,
        (rc, out[:300]),
    )
    rc, out, err, g = cli(
        ["--offline", "--today", "2026-10-12"], doc=stale_doc(conf="2026-10-20")
    )
    check(
        "B: 未来の確認日は警告つき（rc=11・入力不正にしない）",
        rc == 11 and "確認日が未来" in out,
        (rc, out),
    )
    d3 = stale_doc()
    d3["sources"]["asvs"]["confirmed_on"] = "2026-9-2"
    rc, out, err, g = cli(["--offline"], doc=d3)
    check(
        "B: 確認日の形式不正は VERSIONS.json の不正（rc=2）",
        rc == 2 and "confirmed_on" in err,
        (rc, err),
    )
    d3["sources"]["asvs"]["confirmed_on"] = "2026-02-30"
    rc, out, err, g = cli(["--offline"], doc=d3)
    check("B: 実在しない確認日も rc=2", rc == 2, (rc, err))
    for bad_m in (0, -1, 121, "3", True, 2.5):
        rc, out, err, g = cli(["--offline"], doc=stale_doc(months=bad_m))
        check(
            f"B: stale_after_months={bad_m!r} は rc=2",
            rc == 2 and "stale_after_months" in err,
            (rc, err),
        )
    rc, out, err, g = cli(
        ["--offline", "--brief", "--today", "2026-10-12"], doc=stale_doc()
    )
    lines = out.strip().split("\n")
    check(
        "B: --brief は警告を1件1行で出す（4行）",
        rc == 11
        and len(lines) == 4
        and all("確認日が古い" in x for x in lines)
        and "[確認せず]" not in out,
        (rc, out),
    )
    rc, out, err, g = cli(["--offline", "--brief", "--today", "2026-10-12"])
    check(
        "B: --brief は警告が無ければ何も出さない（rc=0）",
        rc == 0 and out == "",
        (rc, out),
    )
    rc, out, err, g = cli(
        ["--brief", "--today", "2026-10-12"],
        {**ok_table, ku: listing(sheets + ["New_Cheat_Sheet"])},
    )
    check(
        "B: --brief に差ありも1行で出る",
        rc == 10 and out.count("原典に差あり") == 1,
        (rc, out),
    )
    argc = []
    for argv in (
        ["--stale-months", "0"],
        ["--stale-months", "x"],
        ["--stale-months", "121"],
        ["--today", "2026-13-01"],
        ["--today", "yesterday"],
        ["--json", "--brief"],
    ):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(argv)
            argc.append(0)
        except SystemExit as ex:
            argc.append(ex.code)
    check(
        "B: 不正な --stale-months・--today・--json と --brief の併用は rc=2",
        argc == [2] * 6,
        argc,
    )
    rc, out, err, g = cli(["--offline"], inject_today=False)
    check(
        "B: --today を省くと実行日（実際の日付）で評価する",
        out.startswith(f"原典の最新版確認（{datetime.date.today().isoformat()}"),
        (rc, out[:60]),
    )

    # --- 低6: 外部テキストの無害化 ---
    evil = "a\x85b\u202ec\u200bd\u2066e\ufeffg\x1b[31m\n\u2069"
    check(
        "無害化: C1制御・方向制御・ゼロ幅・BOM・ESC・改行を空白にする",
        clean(evil) == "a b c d e g [31m"
        and not UNSAFE_RE.search(clean(evil))
        and clean("\u200f\u200e") == "",
        repr(clean(evil)),
    )
    bad_rel = rel(
        "v5.1.0_release", name="\u202eevil\x85", body="x\u200by\u2066z\x9b[0m"
    )
    r, _ = runone("asvs", {au: js([bad_rel, *base_rel])})
    txt = render(
        run(real, fake({au: js([bad_rel, *base_rel])}), False, ["asvs"], today)
    )
    check(
        "無害化: リリースの名前・本文の不可視文字は出力に残らない",
        r["status"] == "diff"
        and not UNSAFE_RE.search(
            r["details"]["release_name"] + r["details"]["notes_excerpt"]
        )
        and not re.search("[\u202e\u200b\u2066\x85\x9b]", txt),
        r["details"],
    )
    odd = [
        {"name": "Evil\u202e_Cheat_Sheet.md", "type": "file"},
        {"name": "A B_Cheat_Sheet.md", "type": "file"},
        {"name": "x\x1b[0m_Cheat_Sheet.md", "type": "file"},
        {"name": "日本語_Cheat_Sheet.md", "type": "file"},
        {"name": "Good-Name.v2_Cheat_Sheet.md", "type": "file"},
    ]
    r, _ = runone(
        "owasp_cheatsheets",
        {ku: js([{"name": x + ".md", "type": "file"} for x in sheets] + odd)},
    )
    check(
        "無害化: シート名は [A-Za-z0-9_.-]+ に合うものだけ採用する（他は無視）",
        r["status"] == "diff" and r["details"]["added"] == ["Good-Name.v2_Cheat_Sheet"],
        r["details"],
    )

    # --- 低7: CWEの順位表の解釈 ---
    def table_r(pairs):
        rows = "".join(
            f'<tr><td style="x"><b>{rk}</b></td>\n'
            f'<td><a href="/d/{c[4:]}.html">{c}</a></td></tr>'
            for rk, c in pairs
        )
        return f"<table>{rows}</table>".encode()

    def cwe_diff(tbl):
        r, _ = runone("cwe_top25", {cu: arch(2025, 2026), tpl.format(year=2026): tbl})
        return r

    two = list(enumerate(old_rank, 1))
    r = cwe_diff(table_r(two + [(26, "CWE-5000"), (27, "CWE-5001")]))
    check(
        "CWE順位表: 26件以上は順位1〜25だけ採用（26位以降を追加にしない）",
        r["status"] == "diff"
        and not any(c.startswith("追加") for c in r["changes"])
        and any("同じ" in c for c in r["changes"]),
        r["changes"],
    )
    for name, pairs in (
        ("順位が重複", two[:3] + [(3, "CWE-5000")] + two[4:]),
        ("順位が欠落（24件）", two[:24]),
        ("CWE番号が重複", two[:24] + [(25, old_rank[0])]),
        ("順位が欠落して26位が混ざる", two[:24] + [(26, "CWE-5000")]),
    ):
        r = cwe_diff(table_r(pairs))
        check(
            f"CWE順位表: {name}は偽の追加・除外を出さず「確認できず（順位表を解釈できない）」",
            r["status"] == "diff"
            and any(
                "順位表は確認できず（順位表を解釈できない" in c for c in r["changes"]
            )
            and not any(
                c.startswith(("追加:", "除外:", "順位変動:")) for c in r["changes"]
            ),
            r["changes"],
        )

    # --- 低7: IPAに新しい版の言及があれば「要確認」（差ありにはしない） ---
    r, _ = runone(
        "ipa",
        {
            iu: ipa("2021年3月31日改訂第7版第4刷公開").replace(
                b"</body>", "<p>次の改訂第8版を準備中</p></body>".encode()
            )
        },
    )
    check(
        "IPA: 日本語版より新しい「第N版」の言及は要確認を添える（状態は一致のまま）",
        r["status"] == "same" and r["hints"] and "改訂第8版" in r["hints"][0],
        r,
    )
    txt = render(
        run(
            real,
            fake(
                {
                    iu: ipa("2021年3月31日改訂第7版第4刷公開").replace(
                        b"</body>", "<p>改訂第8版</p></body>".encode()
                    )
                }
            ),
            False,
            ["ipa"],
            today,
        )
    )
    check(
        "IPA: 要確認は出力に「要確認:」として出る",
        "要確認: ページに改訂第8版" in txt,
        txt,
    )
    r, _ = runone("ipa", {iu: ipa("2021年3月31日改訂第7版第4刷公開")})
    check("IPA: 古い版の言及だけなら要確認は付かない", r["hints"] == [], r["hints"])

    # --- 低9: 確認日の根拠 ---
    out_ = run(real, fake({}), True, None, today)
    txt = render(out_)
    br = brief(run(real, fake({}), True, None, datetime.date(2030, 1, 1)))
    jr = {x["key"]: x for x in out_["results"]}
    check(
        "確認日の根拠: introduced には「（導入日。人の確認ではない）」を付け、human には付けない",
        "最終確認日" not in txt.split("[確認せず] IPA")[0].split("OWASP ASVS")[0]
        and txt.count(INTRODUCED) == 2
        and "確認日 2026-09-02。" in txt
        and jr["ipa"]["confirmed_basis"] == "introduced"
        and jr["ipa"]["stale"]["confirmed_basis"] == "introduced"
        and jr["asvs"]["confirmed_basis"] == "human",
        txt,
    )
    check(
        "確認日の根拠: --brief（確認日が古い）にも導入日の注記が出る（humanには出ない）",
        br.count(INTRODUCED) == 2 and "ASVS: 確認日が古い（確認日 2026-09-02。" in br,
        br,
    )
    rc, out, err, g = cli(["--offline", "--json", "--today", "2026-10-12"])
    dj = json.loads(out)
    check(
        "確認日の根拠: --json に confirmed_basis が出る",
        [x["confirmed_basis"] for x in dj["results"]]
        == ["human", "human", "introduced", "introduced"],
        out[:200],
    )

    # --- 中3: 実行全体の締め切り ---
    class Clock:
        t = 0.0

        def __call__(self):
            return self.t

    def dl_run(argv, per_call, table, doc=None):
        clk, seen = Clock(), []

        def raw(url, timeout):
            seen.append((url, timeout))
            clk.t += per_call
            v = table.get(url)
            if v is None:
                raise FetchError("HTTP 404", retry=False)
            if isinstance(v, Exception):
                raise v
            return v

        rc, out, err, g = cli(argv, doc=doc, clock=clk, raw=raw)
        return rc, out, seen

    rc, out, seen = dl_run(["--today", "2026-10-12"], 50, ok_table)
    check(
        "締め切り(90秒): 超えたら残りの原典は「確認できず（全体の時間切れ）」・通信しない",
        rc == 0
        and len(seen) == 2
        and out.count("[一致]") == 2
        and out.count("[確認できず]") == 2
        and out.count("全体の時間切れ") == 2,
        (rc, out, seen),
    )
    rc, out, seen = dl_run(["--today", "2026-10-12"], 50, ok_table, doc=stale_doc())
    check(
        "締め切り: 時間切れでも確認日の経過(B)は全て評価する（rc=11）",
        rc == 11
        and out.count("[警告] 確認日が古い") == 4
        and out.count("全体の時間切れ") == 2,
        (rc, out),
    )
    rc, out, seen = dl_run(["--deadline", "30", "--today", "2026-10-12"], 25, ok_table)
    check(
        "締め切り: 個別の timeout は残り時間に切り詰める（20秒→残り5秒）",
        [t for _, t in seen] == [20.0, 5.0] and out.count("全体の時間切れ") == 2,
        seen,
    )
    rc, out, seen = dl_run(["--deadline", "5", "--timeout", "20"], 1, ok_table)
    check(
        "締め切り: 間に合うなら全て取得し、timeout は残り時間（5・4・3・2秒）に切り詰める",
        [t for _, t in seen] == [5.0, 4.0, 3.0, 2.0] and "全体の時間切れ" not in out,
        seen,
    )
    rc, out, seen = dl_run(["--today", "2026-10-12"], 1, ok_table)
    check(
        "締め切り: 既定は90秒（4件で4秒なら時間切れなし。timeoutは20秒のまま）",
        len(seen) == 4
        and {t for _, t in seen} == {20.0}
        and "全体の時間切れ" not in out,
        seen,
    )
    rc, out, seen = dl_run(["--deadline", "1", "--today", "2026-10-12"], 5, ok_table)
    check(
        "締め切り: 最初の取得で超えたら残り3件は通信しない",
        len(seen) == 1 and out.count("全体の時間切れ") == 3,
        (seen, out),
    )
    argc = []
    for argv in (
        ["--deadline", "0"],
        ["--deadline", "nan"],
        ["--deadline", "-5"],
        ["--deadline", "inf"],
    ):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(argv)
            argc.append(0)
        except SystemExit as ex:
            argc.append(ex.code)
    check("締め切り: 不正な --deadline は rc=2", argc == [2] * 4, argc)
    check("締め切り: 既定は90秒", parse_args([]).deadline == 90.0 and DEADLINE < 120)

    # 想定外の例外（コードの前提が崩れた応答）でも Traceback にしない
    r, _ = runone("asvs", {au: js([{"tag_name": 5, "draft": False}, "x", None])})
    check(
        "想定外の要素だけの応答は確認できず（Tracebackにしない）",
        r["status"] == "unknown",
        r,
    )
    r, _ = runone("asvs", {au: ValueError("boom")})
    check(
        "想定外の例外は確認できず（種別を出す）",
        r["status"] == "unknown" and "ValueError" in r["reason"],
        r,
    )
    # 外部のテキストの無害化
    r, _ = runone(
        "asvs", {au: js([rel("v5.1.0_release", body="a\x1b[31m\n\n" + "x" * 2000)])}
    )
    ex = r["details"]["notes_excerpt"]
    check(
        "リリースノートの抜粋は1行・制御文字なし・長さ制限",
        "\n" not in ex and "\x1b" not in ex and len(ex) <= EXCERPT,
        len(ex),
    )
    # 同梱の VERSIONS.json: 検証を通ること（冒頭）と、--offline が rc 0 か 11 になることだけを確かめる
    rc, out, err, g = cli(["--offline"], versions=real_path)
    check(
        "同梱の VERSIONS.json で --offline が rc 0 か 11（通信しない）",
        rc in (0, 11) and "[確認せず]" in out and not g.calls,
        (rc, out[:200], err[:200]),
    )
    print("SELF-TEST", "OK" if not fails else f"NG({fails})")
    return 1 if fails else 0


def _st_entry(main_globals, *args, **kwargs):
    """本体のモジュールの名前（globals()）を写し、self_test を実行して戻り値を返す。"""
    global _MAIN_FILE, _MAIN_GLOBALS
    g = globals()
    for k, v in main_globals.items():
        if not (k.startswith("__") and k.endswith("__")) and k not in g:
            g[k] = v
    _MAIN_FILE = main_globals["__file__"]
    _MAIN_GLOBALS = main_globals
    return self_test(*args, **kwargs)
