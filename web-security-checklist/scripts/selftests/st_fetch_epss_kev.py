"""fetch_epss_kev.py の自己検査（--self-test）の本体。本体から分けた（読込を減らすため。P6）。
単独では実行しない。`python3 scripts/fetch_epss_kev.py --self-test` が呼ぶ。
本体のモジュールの名前（関数・定数）をこのモジュールの名前空間に写してから、元のコードをそのまま実行する。"""
from __future__ import annotations

import argparse
import datetime
import decimal
import hashlib
import http.client
import json
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_MAIN_FILE = None  # 本体のファイルのパス（_st_entry が入れる）
_MAIN_GLOBALS = None  # 本体の globals()。本体の定数を一時的に変える検査はここを書き換える


def self_test() -> int:
    import contextlib
    import io
    import types

    fails = 0

    def check(name, ok, detail=""):
        nonlocal fails
        fails += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name}{'' if ok else ': ' + str(detail)}")

    def js(o):
        return json.dumps(o).encode()

    kev_doc = {
        "catalogVersion": "2026.10.08",
        "dateReleased": "2026-10-08T15:00:00.000Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "x" * 250,
            }
        ],
    }
    base = {
        f"{OSV_API}GHSA-aaaa-bbbb-cccc": js(
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2021-44228"]}
        ),
        f"{OSV_API}GHSA-dddd-eeee-ffff": js(
            {"id": "GHSA-dddd-eeee-ffff", "aliases": ["CVE-2099-0001"]}
        ),
        f"{OSV_API}PYSEC-2020-1": js(
            {"id": "PYSEC-2020-1", "aliases": ["GHSA-zzzz-yyyy-xxxx"]}
        ),
        KEV_URL: js(kev_doc),
    }

    def queried(url):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cve"][0].split(
            ","
        )

    def epss_resp(url):
        rows = [
            {
                "cve": c,
                "epss": "0.034250000",
                "percentile": "0.885880000",
                "date": "2026-10-08",
            }
            for c in queried(url)
            if c != "CVE-2099-0001"
        ]
        return js({"status": "OK", "data": rows})

    def fake(over=None, log=None):
        def get(url):
            if log is not None:
                log.append(url)
            r = (over or {}).get(url, base.get(url))
            if url.startswith(EPSS_API + "?") and r is None:
                r = (over or {}).get("EPSS", epss_resp)
            if callable(r):
                return r(url)
            if isinstance(r, Exception):
                raise r
            if r is None:
                raise FetchError("HTTP 404", retry=False)
            return r

        return get

    def net(over=None, log=None):  # http_get・再試行を通す（opener だけ差し替える）
        f = fake(over, log)
        return with_retry(
            lambda u: http_get(u, 1, None, lambda req, t, ctx: f(req.full_url)),
            lambda s: None,
        )

    def run_main(ids, get, out=None, kev_cache=None, text=None, status=False):
        with tempfile.TemporaryDirectory() as td:
            src = None
            if text is not None:
                src = os.path.join(td, "sca.txt")
                with open(src, "w", encoding="utf-8") as f:
                    f.write(text)
            a = argparse.Namespace(
                from_text=src,
                id=ids,
                out=out or os.path.join(td, "o.json"),
                kev_cache=kev_cache,
                timeout=1.0,
                status_line=status,
            )
            buf, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
                rc = main(a, get)
            doc = None
            if rc == 0 and os.path.exists(a.out):
                with open(a.out, encoding="utf-8") as f:
                    doc = json.load(f)
            return rc, doc, buf.getvalue() + err.getvalue()

    now = "2026-10-09T00:00:00Z"
    # 正常: GHSA→CVE→EPSS→KEV掲載/非掲載、no_cve、EPSS not_found、CVE直接（OSVを引かない）
    log: list[str] = []
    d = build(
        ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "PYSEC-2020-1", "CVE-2023-0001"],
        fake(log=log),
        now=now,
    )
    e = {x["id"]: x for x in d["entries"]}
    it = e["GHSA-aaaa-bbbb-cccc"]["items"][0]
    check(
        "正常 GHSA→CVE→EPSS→KEV掲載",
        it["cve"] == "CVE-2021-44228"
        and it["epss"] == 0.03425
        and it["percentile"] == 0.88588
        and it["epss_date"] == "2026-10-08"
        and it["epss_error"] is None
        and it["kev"] is True
        and it["kev_ransomware"] == "Known"
        and len(it["kev_required_action"]) == ACTION_MAX
        and it["urls"]["advisory"]
        == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
        and it["urls"]["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        it,
    )
    it = e["CVE-2023-0001"]["items"][0]
    check(
        "CVE直接・KEV非掲載・OSVを引かない",
        it["kev"] is False
        and it["kev_date_added"] is None
        and it["urls"]["advisory"] == "https://osv.dev/vulnerability/CVE-2023-0001"
        and not any(u.startswith(OSV_API + "CVE") for u in log),
        (it, log),
    )
    it = e["GHSA-dddd-eeee-ffff"]["items"][0]
    check(
        "EPSS not_found",
        it["epss_status"] == "not_found"
        and it["epss"] is None
        and it["epss_error"] is None
        and it["kev"] is False,
        it,
    )
    check(
        "no_cve",
        e["PYSEC-2020-1"]["status"] == "no_cve" and e["PYSEC-2020-1"]["items"] == [],
        e["PYSEC-2020-1"],
    )
    check(
        "sources（KEV版・sha256・score_date）",
        d["sources"]["kev"]["catalog_version"] == "2026.10.08"
        and d["sources"]["kev"]["sha256"] == hashlib.sha256(js(kev_doc)).hexdigest()
        and d["sources"]["epss"]["score_date"] == "2026-10-08"
        and sum(u == KEV_URL for u in log) == 1,
        d["sources"],
    )
    check("出力JSONのスキーマ（正常）", validate(d) == [], validate(d))
    # OSV失敗（通信失敗・不正なJSON）
    d2 = build(
        ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"],
        fake(
            {
                OSV_API + "GHSA-aaaa-bbbb-cccc": FetchError("タイムアウト"),
                OSV_API + "GHSA-dddd-eeee-ffff": b"<html>",
            }
        ),
        now=now,
    )
    e2 = {x["id"]: x for x in d2["entries"]}
    check(
        "OSV失敗",
        e2["GHSA-aaaa-bbbb-cccc"]["status"] == "error"
        and "タイムアウト" in e2["GHSA-aaaa-bbbb-cccc"]["error"],
        e2,
    )
    check(
        "不正なJSON応答（OSV）",
        e2["GHSA-dddd-eeee-ffff"]["status"] == "error"
        and "不正なJSON" in e2["GHSA-dddd-eeee-ffff"]["error"],
        e2,
    )
    check(
        "全IDがOSV失敗ならKEVを取得しない",
        d2["sources"]["kev"]["catalog_version"] is None and validate(d2) == [],
    )
    # EPSS失敗（通信失敗・不正なJSON・data無し）
    for name, r in (
        ("通信", FetchError("HTTP 503")),
        ("不正なJSON", b"{"),
        ("dataが無い", js({"status": "OK"})),
    ):
        d3 = build(["CVE-2021-44228"], fake({"EPSS": r}), now=now)
        it = d3["entries"][0]["items"][0]
        check(
            f"EPSS失敗（{name}）",
            it["epss"] is None
            and it["epss_status"] == "error"
            and it["epss_error"]
            and it["kev"] is True
            and validate(d3) == []
            and "EPSS取得失敗" in summary(d3, "o"),
            it,
        )
    # KEV取得失敗・不正なKEV
    for name, r in (
        ("通信", FetchError("接続失敗 (x)")),
        ("不正なJSON", b"\xff\xfe"),
        ("形が違う", js([])),
    ):
        d4 = build(["CVE-2021-44228"], fake({KEV_URL: r}), now=now)
        it = d4["entries"][0]["items"][0]
        check(
            f"KEV取得失敗（{name}）",
            it["kev"] is None
            and d4["sources"]["kev"]["error"]
            and it["epss_status"] == "ok"
            and validate(d4) == [],
            (it, d4["sources"]["kev"]),
        )
    # HTTP応答の異常（IncompleteRead・BadStatusLine）: 他のIDは続き、rc=0
    log = []
    rc, doc, _ = run_main(
        ["GHSA-aaaa-bbbb-cccc", "CVE-2023-0001"],
        net({OSV_API + "GHSA-aaaa-bbbb-cccc": http.client.IncompleteRead(b"x")}, log),
    )
    ent = {x["id"]: x for x in (doc or {}).get("entries", [])}
    check(
        "IncompleteRead（OSV）→該当IDだけ error・再試行・rc=0",
        rc == 0
        and "IncompleteRead" in ent["GHSA-aaaa-bbbb-cccc"]["error"]
        and ent["CVE-2023-0001"]["items"][0]["epss_status"] == "ok"
        and log.count(OSV_API + "GHSA-aaaa-bbbb-cccc") == RETRIES + 1,
        (rc, ent, log),
    )
    rc, doc, out = run_main(
        ["CVE-2021-44228"], net({"EPSS": http.client.BadStatusLine("x")})
    )
    it = doc["entries"][0]["items"][0] if doc else {}
    check(
        "BadStatusLine（EPSS）→EPSSだけ error・KEVは続く・rc=0",
        rc == 0
        and it.get("epss_status") == "error"
        and "BadStatusLine" in it.get("epss_error", "")
        and it.get("kev") is True
        and "EPSS取得失敗" in out,
        (rc, it, out),
    )
    # 外部の値の型・範囲（NaN・範囲外・不正な型・日付）と、1行だけ壊れたEPSS応答
    bad_rows = {
        "CVE-2024-00001": {"epss": "NaN", "percentile": "0.5"},
        "CVE-2024-00002": {"epss": "1.5", "percentile": "0.5"},
        "CVE-2024-00003": {"epss": "0.1", "percentile": [1]},
        "CVE-2024-00004": {"epss": float("nan"), "percentile": 0.5},
        "CVE-2024-00005": {"epss": True, "percentile": 0.5},
        "CVE-2024-00006": {"percentile": "0.5"},
        "CVE-2024-00007": {"epss": "０.５", "percentile": "0.5"},
        "CVE-2024-00010": {"epss": 10**400, "percentile": "0.5"},
        "CVE-2024-00011": {"epss": "1" + "0" * 400, "percentile": "0.5"},
    }

    def epss_bad(url):
        rows = [dict(v, cve=c, date="2026-10-08") for c, v in bad_rows.items()]
        rows.append(
            {
                "cve": "CVE-2024-00008",
                "epss": "0.2",
                "percentile": "0.9",
                "date": "2026/10/08",
            }
        )
        rows.append(
            {"cve": "CVE-2024-00009", "epss": 0, "percentile": 1, "date": "2026-10-08"}
        )
        rows.append("broken")
        return json.dumps({"data": rows}).encode()

    kev_bad = dict(
        kev_doc,
        catalogVersion=5,
        vulnerabilities=[
            {
                "cveID": "CVE-2024-00008",
                "dateAdded": 20211210,
                "dueDate": "2021-12-24",
                "requiredAction": ["x"],
            }
        ],
    )
    d8 = build(
        sorted(bad_rows) + ["CVE-2024-00008", "CVE-2024-00009"],
        fake({"EPSS": epss_bad, KEV_URL: js(kev_bad)}),
        now=now,
    )
    its = {x["id"]: x["items"][0] for x in d8["entries"]}
    bad_ok = all(
        its[c]["epss_status"] == "error"
        and its[c]["epss"] is None
        and its[c]["epss_error"]
        for c in bad_rows
    )
    i8, i9 = its["CVE-2024-00008"], its["CVE-2024-00009"]
    check(
        "NaN/範囲外/不正な型のEPSSの行はそのCVEだけ error",
        bad_ok,
        {c: its[c]["epss_error"] for c in bad_rows},
    )
    check(
        "1行だけ壊れたEPSS応答で他の行は ok（不正な日付は null）",
        i8["epss_status"] == "ok"
        and i8["epss_date"] is None
        and i9["epss"] == 0.0
        and i9["percentile"] == 1.0,
        (i8, i9),
    )
    check(
        "KEVの不正な型は null（catalog_version・日付・requiredAction）",
        d8["sources"]["kev"]["catalog_version"] is None
        and i8["kev"] is True
        and i8["kev_date_added"] is None
        and i8["kev_due_date"] == "2021-12-24"
        and i8["kev_required_action"] is None
        and validate(d8) == []
        and json.dumps(d8, allow_nan=False) != "",
        i8,
    )
    # KEVのキャッシュ保存
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "kev.json")
        build(["CVE-2021-44228"], fake(), kev_cache=p, now=now)
        with open(p, "rb") as fb:
            check("--kev-cache に取得内容を残す", fb.read() == js(kev_doc))
    # 書き込み先は通信の前に確かめる
    log = []
    rc, _, _ = run_main(
        ["CVE-2021-44228"], fake(log=log), out="/nonexistent-dir/o.json"
    )
    check("--out に書けない→rc=2・通信なし", rc == 2 and log == [], (rc, log))
    with tempfile.TemporaryDirectory() as td:
        rc, _, _ = run_main(["CVE-2021-44228"], fake(log=log), kev_cache=td)
    check("--kev-cache に書けない→rc=2・通信なし", rc == 2 and log == [], (rc, log))
    # バッチ分割（51件 → 50件+1件）
    log = []
    many = [f"CVE-2024-{n:05d}" for n in range(51)]
    d5 = build(many, fake(log=log), now=now)
    q = [u for u in log if u.startswith(EPSS_API)]
    check(
        "EPSSのバッチ分割（51件）",
        [len(queried(u)) for u in q] == [50, 1]
        and all(i["epss_status"] == "ok" for x in d5["entries"] for i in x["items"]),
        q,
    )
    # ID抽出（複数形式・重複・境界）
    text = (
        "lodash  GHSA-jf85-cpcp-j695 https://github.com/advisories/"
        "GHSA-jf85-cpcp-j695\n"
        "CVE-2021-44228, CVE-2021-44228 PYSEC-2021-19 GO-2022-0969 RUSTSEC-2021-0078 "
        "OSV-2020-111\n"
        "XCVE-2020-1111 CVE-2020-12 GHSA-AAAA-bbbb-cccc"
    )
    got = extract_ids(text)
    want = [
        "GHSA-jf85-cpcp-j695",
        "CVE-2021-44228",
        "PYSEC-2021-19",
        "GO-2022-0969",
        "RUSTSEC-2021-0078",
        "OSV-2020-111",
        "GHSA-aaaa-bbbb-cccc",
    ]
    check("ID抽出（複数形式・重複・境界）", got == want, got)
    # IDの前後の境界（日本語・é は境界、全角英数・前の - は語の一部）
    bounds: tuple[tuple[str, list[str]], ...] = (
        ("脆弱性CVE-2021-44228が見つかった", ["CVE-2021-44228"]),
        ("CVE-2021-44228の修正", ["CVE-2021-44228"]),
        ("CVE-2021-44228é", ["CVE-2021-44228"]),
        ("éCVE-2021-44228", ["CVE-2021-44228"]),
        ("ａCVE-2021-44228", []),
        ("CVE-2021-4422８", []),
        ("CVE-2021-44228ｂ", []),
        ("-CVE-2021-44228", []),
        ("CVE-2021-44228-", ["CVE-2021-44228"]),
        ("CVE-2021-44228", ["CVE-2021-44228"]),
        ("x\nCVE-2021-44228\n", ["CVE-2021-44228"]),
        (
            "（GHSA-jf85-cpcp-j695）、PYSEC-2021-19。",
            ["GHSA-jf85-cpcp-j695", "PYSEC-2021-19"],
        ),
    )
    for t, w in bounds:
        check(f"ID境界: {t!r}", extract_ids(t) == w, extract_ids(t))
    # ID正規化（--id・--from-text とも正規化後に検証・重複除去）
    ids, bad = collect_ids(
        "cve-2021-44228 ghsa-JF85-CPCP-J695 pysec-2021-19 Go-2022-0969 "
        "rustsec-2021-0078 osv-2020-111"
        " GO-2022-0969 OSV-2020-111",
        [
            "CVE-2021-44228",
            "Cve-2021-44228",
            " GHSA-jf85-cpcp-j695",
            "rustsec-2021-0078",
            "go-2022-0969",
            "Osv-1-2",
        ],
    )
    check(
        "ID正規化（大文字・GHSA本体は小文字・重複除去・GO/OSVは大文字のみ）",
        ids
        == [
            "CVE-2021-44228",
            "GHSA-jf85-cpcp-j695",
            "PYSEC-2021-19",
            "RUSTSEC-2021-0078",
            "GO-2022-0969",
            "OSV-2020-111",
        ]
        and bad == ["go-2022-0969", "Osv-1-2"],
        (ids, bad),
    )
    rc, doc, _ = run_main(["cve-2021-44228"], fake())
    check(
        "小文字の --id を受理し出力の id は正規化後",
        rc == 0 and doc["entries"][0]["id"] == "CVE-2021-44228",
        doc,
    )
    # 全角数字のID（--id は rc=2、--from-text は無視、正常なCVEのバッチに影響しない）
    rc, _, _ = run_main(["CVE-２０２１-44228"], fake())
    check("全角数字の --id は rc=2", rc == 2, rc)
    log = []
    rc, doc, _ = run_main(
        [],
        fake(log=log),
        text="CVE-２０２１-44228 CVE-2021-4422８ CVE-2021-44228 ｃｖｅ-2021-1234",
    )
    check(
        "全角を含むIDは --from-text で無視・正常なCVEは ok",
        rc == 0
        and [x["id"] for x in doc["entries"]] == ["CVE-2021-44228"]
        and doc["entries"][0]["items"][0]["epss_status"] == "ok",
        (doc, log),
    )
    log = []
    d9 = build(["CVE-２０２１-44228", "CVE-2021-44228"], fake(log=log), now=now)
    check(
        "不正なIDは error（通信しない）・同じ処理の正常なCVEは影響なし",
        d9["entries"][0]["status"] == "error"
        and d9["entries"][1]["items"][0]["epss_status"] == "ok"
        and all(u.isascii() for u in log)
        and validate(d9) == [],
        (d9["entries"], log),
    )
    check(
        "epss_url はCVEをエンコードする",
        epss_url(["CVE-1/2", "CVE-2021-44228"]).endswith(
            "cve=CVE-1%2F2,CVE-2021-44228"
        ),
    )
    log = []
    d6 = build([], fake(log=log), now=now)
    check(
        "IDなし（entries空・通信なし）",
        d6["entries"] == [] and log == [] and validate(d6) == [],
        log,
    )
    # 再試行（2回失敗→3回目成功、429は再試行、4xxは再試行しない）
    calls = []

    def flaky(url):
        calls.append(url)
        if len(calls) < 3:
            raise FetchError("HTTP 503")
        return b"ok"

    waits: list[int] = []
    check(
        "再試行（最大2回・待ち時間あり）",
        with_retry(flaky, waits.append)("https://x") == b"ok" and waits == [1, 2],
    )
    calls.clear()

    def busy(req, timeout, ctx):
        calls.append(req.full_url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(
                req.full_url, 429, "Too Many Requests", {}, None
            )
        return b"ok"

    waits = []
    r = with_retry(lambda u: http_get(u, 1, None, busy), waits.append)("https://x")
    check("429は再試行する", r == b"ok" and waits == [1, 2] and len(calls) == 3, calls)
    calls.clear()

    def nf(url):
        calls.append(url)
        raise FetchError("HTTP 404", retry=False)

    try:
        with_retry(nf, lambda s: None)("https://x")
        ok = False
    except FetchError:
        ok = len(calls) == 1
    check("4xxは再試行しない", ok, calls)
    try:
        http_get("http://example.invalid/", 1)
        ok = False
    except FetchError as ex:
        ok = "HTTPS以外" in str(ex)
    check("HTTPS以外のURLを拒否", ok)
    h = HttpsOnlyRedirect()
    req = urllib.request.Request("https://api.osv.dev/v1/vulns/X")
    try:
        h.redirect_request(req, None, 302, "Found", {}, "http://api.osv.dev/v1/vulns/X")
        ok = False
    except FetchError as ex:
        ok = "リダイレクトを拒否" in str(ex) and not ex.retry
    ok2 = (
        h.redirect_request(
            req, None, 302, "Found", {}, "https://api.osv.dev/v1/vulns/Y"
        )
        is not None
    )
    check("HTTPS以外へのリダイレクトを拒否（HTTPSは通す）", ok and ok2)
    saved = MAX_BYTES
    _MAIN_GLOBALS["MAX_BYTES"] = 10
    try:
        http_get("https://x", 1, None, lambda req, t, ctx: b"x" * 11)
        ok = False
    except FetchError as ex:
        ok = "超える" in str(ex) and not ex.retry
    finally:
        _MAIN_GLOBALS["MAX_BYTES"] = saved
    check("MAX_BYTES超過は error（再試行しない）", ok)
    # --timeout は正の有限の数のみ
    for v in ("inf", "nan", "0", "-1"):
        code: int | str | None
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(
                    ["--id", "CVE-2021-44228", "--out", "o.json", "--timeout", v]
                )
            code = 0
        except SystemExit as ex:
            code = ex.code
        check(f"--timeout {v} は rc=2", code == 2, code)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            parse_args(["--id", "CVE-2021-44228", "--out", "o.json", "--kev-cache", ""])
        code = 0
    except SystemExit as ex:
        code = ex.code
    check("--kev-cache が空は rc=2", code == 2, code)
    for opt, v in (
        ("--max-seconds", "0"),
        ("--max-seconds", "inf"),
        ("--max-ids", "0"),
    ):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(["--id", "CVE-2021-44228", "--out", "o.json", opt, v])
            code = 0
        except SystemExit as ex:
            code = ex.code
        check(f"{opt} {v} は rc=2", code == 2, code)
    a0 = parse_args(["--id", "CVE-2021-44228", "--out", "o.json"])
    check(
        "--max-seconds・--max-ids の既定（120・200）",
        (a0.max_seconds, a0.max_ids) == (MAX_SECONDS, MAX_IDS),
    )
    ok = True
    for big in (10**400, "1" + "0" * 400, "1e400"):
        try:
            unit(big)
            ok = False
        except ValueError:
            pass
    check("unit: 巨大な整数・桁あふれは ValueError（OverflowErrorにしない）", ok)
    # 要約から制御文字を除く
    d10 = build(
        ["GHSA-aaaa-bbbb-cccc"],
        fake({OSV_API + "GHSA-aaaa-bbbb-cccc": FetchError("x\x1b[2J\u202ey\n")}),
        now=now,
    )
    s10 = summary(d10, "o")
    check(
        "要約から制御文字を除く",
        "\x1b" not in s10 and "\u202e" not in s10 and "x[2Jy" in s10,
        repr(s10),
    )
    # CA証明書の切り替え（既定の文脈で検証失敗→既定のCAファイル等が存在しなければ既知のバンドルで1回だけ再試行）

    def tls_case(have, default_ca=None):
        opened = []

        def opener(req, timeout, ctx):
            opened.append(ctx)
            if ctx is None:
                raise urllib.error.URLError(
                    ssl.SSLCertVerificationError(1, "certificate verify failed")
                )
            return b"ok"

        t = Tls(
            exists=lambda x: x in have,
            paths=lambda: types.SimpleNamespace(cafile=default_ca, capath=None),
            make_ctx=lambda c: ("ctx", c),
        )
        try:
            r = http_get("https://x", 1, t, opener)
        except FetchError as ex:
            r = ex
        return t, r, opened

    t, r, opened = tls_case(
        {"/private/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"}
    )
    r2 = http_get(
        "https://x", 1, t, lambda req, timeout, ctx: opened.append(ctx) or b"ok2"
    )
    d7 = build(["CVE-2021-44228"], fake(), now=now, tls=t)
    check(
        "CA: 既定で検証失敗→バンドルで成功（以後もバンドル・tls_caと要約に記録）",
        r == b"ok"
        and r2 == b"ok2"
        and t.cafile == "/private/etc/ssl/cert.pem"
        and opened == [None, ("ctx", t.cafile), ("ctx", t.cafile)]
        and d7["sources"]["tls_ca"] == t.cafile
        and validate(d7) == []
        and f"CA証明書: {t.cafile}" in summary(d7, "o"),
        (r, opened, t.cafile),
    )
    t, r, opened = tls_case(set())
    check(
        "CA: バンドルが無い→従来のエラー（設定を促す）",
        isinstance(r, FetchError)
        and "Install Certificates" in str(r)
        and t.cafile is None
        and opened == [None],
        (r, opened),
    )
    t, r, opened = tls_case(
        {"/etc/ssl/cert.pem", "/py/cert.pem"}, default_ca="/py/cert.pem"
    )
    check(
        "CA: 既定のCAファイルが存在すれば切り替えない",
        isinstance(r, FetchError) and t.cafile is None and opened == [None],
        r,
    )
    t, r, opened = tls_case(
        {"/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt"}
    )
    check(
        "CA: 既知のパスの順に最初に存在するものを使う",
        r == b"ok" and t.cafile == "/etc/ssl/certs/ca-certificates.crt",
        t.cafile,
    )
    with open(os.path.abspath(_MAIN_FILE), encoding="utf-8") as f:
        src = f.read()
    banned = (
        "CERT_" + "NONE",
        "check_hostname" + r"\s*=\s*False",
        "_create_" + "unverified_context",
    )
    hit = [b for b in banned if re.search(b, src)]
    check(
        "CA: 証明書の検証を無効にしていない（無効化の設定がコードに無い）",
        hit == [],
        hit,
    )
    # スキーマ検査の破壊ケース
    breaks = {
        "epssが文字列": lambda x: x["entries"][0]["items"][0].update(epss="0.03425"),
        "epssがNaN": lambda x: x["entries"][0]["items"][0].update(epss=float("nan")),
        "epssが範囲外": lambda x: x["entries"][0]["items"][0].update(epss=1.5),
        "epss_errorとepss_statusが不整合": lambda x: x["entries"][0]["items"][0].update(
            epss_error="x"
        ),
        "epss_error欠落（status=error）": lambda x: x["entries"][0]["items"][0].update(
            epss=None, percentile=None, epss_status="error", epss_error=None
        ),
        "kev_date_addedの形式": lambda x: x["entries"][0]["items"][0].update(
            kev_date_added="2021/12/10"
        ),
        "kevが文字列": lambda x: x["entries"][0]["items"][0].update(kev="yes"),
        "statusが不正": lambda x: x["entries"][0].update(status="unknown"),
        "errorとstatusが不整合": lambda x: x["entries"][0].update(status="error"),
        "itemsとcvesが不一致": lambda x: x["entries"][0].update(cves=["CVE-2000-0001"]),
        "attribution欠落": lambda x: x["sources"]["epss"].pop("attribution"),
        "sources.kev.sha256欠落": lambda x: x["sources"]["kev"].pop("sha256"),
        "catalog_versionが数値": lambda x: x["sources"]["kev"].update(
            catalog_version=5
        ),
        "retrieved_atが不正": lambda x: x.update(retrieved_at="2026-10-09 00:00"),
        "tls_ca欠落": lambda x: x["sources"].pop("tls_ca"),
        "urlsがhttp": lambda x: x["entries"][0]["items"][0]["urls"].update(
            nvd="http://nvd.nist.gov/"
        ),
    }
    for name, brk in breaks.items():
        x = json.loads(json.dumps(d))
        brk(x)
        check(f"スキーマ破壊: {name}", validate(x) != [], name)
    s = summary(d, "out.json")
    check(
        "要約（1行1ID・末尾）",
        len(s.splitlines()) == 1 + 4 + 1
        and "0.03425/0.88588/2026-10-08" in s
        and "KEV版: 2026.10.08" in s,
        s,
    )
    check(
        "要約にスキーマ違反を WARN で出す",
        "WARN: 出力JSONの検査: x" in summary(d, "o", ["x"]),
    )
    # --status-line（run_sca_scan.sh の末尾の1行）
    cert = FetchError("証明書を検証できない（x）", retry=False, cert=True)

    def one(over):  # CVE 1件（KEV掲載）を over の失敗で作る
        return build(["CVE-2021-44228"], fake(over), now=now)

    cases = (
        (
            "取得済み（not_found・no_cve は失敗に数えない）",
            d,
            "取得済み（CVE 3件、KEV掲載 1件）",
        ),
        ("ID 0件", build([], fake(), now=now), "スキャン出力に脆弱性IDなし"),
        (
            "CVEなしの勧告だけ",
            build(["PYSEC-2020-1"], fake(), now=now),
            "対象のCVEなし（CVEなしの勧告1件は対象外）",
        ),
        ("全IDがOSV失敗", d2, "未取得（理由: OSV: タイムアウト）"),
        (
            "EPSSだけ失敗",
            one({"EPSS": FetchError("HTTP 503")}),
            "一部未取得（理由: EPSS: HTTP 503）",
        ),
        (
            "EPSS・KEVとも失敗",
            one({"EPSS": FetchError("HTTP 503"), KEV_URL: FetchError("x")}),
            "未取得（理由: EPSS: HTTP 503）",
        ),
        (
            "証明書の検証失敗",
            one({"EPSS": cert, KEV_URL: cert}),
            "未取得（理由: CA証明書）",
        ),
        (
            "KEVだけ証明書の検証失敗",
            one({KEV_URL: cert}),
            "一部未取得（理由: CA証明書）",
        ),
    )
    for name, doc_, want_line in cases:
        line = status_line(doc_)
        check(f"状況行: {name}", line == "EPSS/KEV: " + want_line, line)
    rc, _, out = run_main(["CVE-2021-44228"], fake(), status=True)
    check(
        "状況行: --status-line で要約の後の最終行に出す",
        rc == 0 and out.splitlines()[-1].startswith("EPSS/KEV: 取得済み"),
        out,
    )
    rc, _, out = run_main(["CVE-2021-44228"], fake())
    check(
        "状況行: --status-line なしでは出さない",
        rc == 0 and "EPSS/KEV:" not in out,
        out,
    )
    # 打ち切り（Guard）: 同じホストへの接続レベルの失敗の連続・時間切れ（時刻は差し替え）
    refused = FetchError("接続失敗 ([Errno 61] Connection refused)", conn=True)

    def guarded(over, clock=None, tick=0.0, max_seconds=MAX_SECONDS, calls=None):
        t = [0.0]

        def raw(url, timeout):
            if calls is not None:
                calls.append((url, timeout))
            t[0] += tick
            return fake(over)(url)

        g = Guard(raw, 10.0, max_seconds, clock or (lambda: t[0]))
        return with_retry(g, lambda s: None), g

    def conn_of(exc):
        def opener(req, t, ctx):
            raise exc

        try:
            get_once("https://api.osv.dev/v1/vulns/x", 1, None, opener)
        except FetchError as e:
            return e.conn
        return None

    kinds = {
        "接続拒否": (
            urllib.error.URLError(ConnectionRefusedError(61, "refused")),
            True,
        ),
        "名前解決失敗": (urllib.error.URLError(socket.gaierror(8, "nodename")), True),
        "タイムアウト": (urllib.error.URLError(socket.timeout("t")), True),
        "OSError": (OSError("x"), True),
        "HTTP 503": (
            urllib.error.HTTPError(
                "https://x", 503, "x", http.client.HTTPMessage(), None
            ),
            False,
        ),
        "証明書": (urllib.error.URLError(ssl.SSLCertVerificationError("x")), False),
    }
    conns = {k: conn_of(v[0]) for k, v in kinds.items()}
    check(
        "接続レベルの失敗だけを conn にする",
        all(conns[k] is v[1] for k, v in kinds.items()),
        conns,
    )
    ghsa = ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "PYSEC-2020-1"]
    calls = []
    get, _ = guarded({OSV_API + x: refused for x in ghsa}, calls=calls)
    d11 = build(ghsa + ["CVE-2021-44228"], get, now=now)
    e11 = {x["id"]: x for x in d11["entries"]}
    osv_calls = [u for u, _ in calls if u.startswith(OSV_API)]
    check(
        "打ち切り: 同じホストへの接続失敗が3回続いたら残りを同じ理由の error（再試行も止める）",
        len(osv_calls) == CONN_FAILS
        and all(
            e11[x]["status"] == "error" and "Connection refused" in e11[x]["error"]
            for x in ghsa
        )
        and all("打ち切り" in e11[x]["error"] for x in ghsa)
        and validate(d11) == [],
        (osv_calls, e11),
    )
    it = e11["CVE-2021-44228"]["items"][0]
    check(
        "打ち切り: 他のホスト（EPSS・KEV）は続く",
        it["epss_status"] == "ok"
        and it["kev"] is True
        and status_line(d11).startswith("EPSS/KEV: 一部未取得"),
        (it, status_line(d11)),
    )
    seq = [
        refused,
        refused,
        FetchError("HTTP 503"),
        refused,
        js({"id": "GHSA-dddd-eeee-ffff", "aliases": []}),
    ]

    def flaky_seq(url):
        r = seq.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    get, g = guarded(
        {
            OSV_API + "GHSA-aaaa-bbbb-cccc": flaky_seq,
            OSV_API + "GHSA-dddd-eeee-ffff": flaky_seq,
        }
    )
    d12 = build(["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"], get, now=now)
    check(
        "打ち切り: HTTPの応答で数え直す（接続失敗が続いていなければ打ち切らない）",
        g.cut == {}
        and d12["entries"][0]["error"] == "OSV: HTTP 503"
        and d12["entries"][1]["status"] == "no_cve"
        and seq == [],
        (g.cut, d12["entries"], seq),
    )
    get, g = guarded({OSV_API + x: FetchError("HTTP 503") for x in ghsa})
    d13 = build(ghsa, get, now=now)
    check(
        "打ち切り: 接続レベルでない失敗（HTTP 503）は数えない",
        g.cut == {} and all(e["error"] == "OSV: HTTP 503" for e in d13["entries"]),
        d13["entries"],
    )
    get, g = guarded({OSV_API + x: cert for x in ghsa})
    build(ghsa, get, now=now)
    check(
        "打ち切り: 証明書の検証失敗は数えない（既存の扱いのまま）", g.cut == {}, g.cut
    )
    calls = []
    get, _ = guarded({}, tick=50.0, max_seconds=100.0, calls=calls)
    d14 = build(
        ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "PYSEC-2020-1", "CVE-2023-0001"],
        get,
        now=now,
    )
    e14 = {x["id"]: x for x in d14["entries"]}
    it = e14["CVE-2023-0001"]["items"][0]
    check(
        "時間切れ: 上限を過ぎたら残りを「時間切れ」の error にし、出力は作る",
        e14["GHSA-aaaa-bbbb-cccc"]["status"] == "ok"
        and e14["GHSA-dddd-eeee-ffff"]["status"] == "ok"
        and e14["PYSEC-2020-1"]["status"] == "error"
        and "時間切れ" in e14["PYSEC-2020-1"]["error"]
        and "時間切れ" in it["epss_error"]
        and "時間切れ" in d14["sources"]["kev"]["error"]
        and len(calls) == 2
        and validate(d14) == []
        and "時間切れ" in status_line(d14),
        (calls, e14, d14["sources"]["kev"]),
    )
    check(
        "時間切れ: 各回のタイムアウトは残り時間以下",
        [t for _, t in calls] == [10.0, 10.0],
        calls,
    )
    calls = []
    get, _ = guarded({}, tick=115.0, calls=calls)
    build(["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"], get, now=now)
    check(
        "時間切れ: 残りが少なければタイムアウトを縮める",
        [t for _, t in calls] == [10.0, 5.0],
        calls,
    )
    # 件数上限
    ids5 = [
        "CVE-2021-0001",
        "CVE-2021-0002",
        "CVE-2021-0003",
        "CVE-2021-0004",
        "CVE-2021-0005",
        "CVE-2021-0006",
    ]
    log = []
    d15 = build(ids5, fake(log=log), now=now, max_ids=2)
    lim = d15["sources"]["id_limit"]
    check(
        "件数上限: 超過分は処理せず sources.id_limit と要約に記録",
        [e["id"] for e in d15["entries"]] == ids5[:2]
        and lim
        == {
            "max_ids": 2,
            "excluded": 4,
            "excluded_ids": ids5[2:],
            "note": "件数上限により除外: 4件",
        }
        and not any("CVE-2021-0003" in u for u in log)
        and "件数上限により除外: 4件（--max-ids 2。CVE-2021-0003" in summary(d15, "o")
        and validate(d15) == [],
        (lim, summary(d15, "o")),
    )
    check(
        "件数上限: 状況行は一部未取得",
        status_line(d15) == "EPSS/KEV: 一部未取得（理由: 件数上限により除外: 4件）",
        status_line(d15),
    )
    check(
        "件数上限: 未指定・上限内では記録が空で要約に出さない",
        d["sources"]["id_limit"]
        == {"max_ids": MAX_IDS, "excluded": 0, "excluded_ids": [], "note": None}
        and "件数上限" not in summary(d, "o"),
        d["sources"]["id_limit"],
    )
    for name, brk in (
        ("id_limit欠落", lambda x: x["sources"].pop("id_limit")),
        (
            "excludedと一覧が不一致",
            lambda x: x["sources"]["id_limit"].update(excluded=1),
        ),
        ("noteが除外0件で文字列", lambda x: x["sources"]["id_limit"].update(note="x")),
    ):
        x = json.loads(json.dumps(d))
        brk(x)
        check(f"スキーマ破壊: {name}", validate(x) != [], name)
    # --check-report: 模擬報告書（report_template.md の8節・5節の表記）とJSONの照合
    dr = build(
        [
            "GHSA-aaaa-bbbb-cccc",
            "GHSA-dddd-eeee-ffff",
            "PYSEC-2020-1",
            "CVE-2023-0001",
            "GHSA-1111-2222-3333",
        ],
        fake(),
        now=now,
    )

    def links(vid, cve=None):
        if cve is None:
            return f"[勧告]({advisory_url(vid)})"
        return (
            f"[EPSS]({EPSS_API}?cve={cve}) [KEV]({KEV_URL}) [NVD](https://nvd.nist.gov/"
            f"vuln/detail/{cve})"
            f" [勧告]({advisory_url(vid)})"
        )

    rep = "\n".join(
        [
            "# セキュリティ監査報告書",
            "## 5. 指摘詳細（重大度順）",
            "### 5.1 [High] 依存ライブラリの既知脆弱性",
            "| 項目 | 内容 |",
            "| --- | --- |",
            "| ファイル | `package.json:1` |",
            (
                "| 悪用状況（EPSS/KEV） | 対象: GHSA-aaaa-bbbb-cccc、GHSA-dddd-eeee-ffff。最大EPSS "
                "0.03425（CVE-2021-44228）、"
                "KEV掲載 1件（CVE-2021-44228）。詳細は8節 |"
            ),
            "```markdown",
            "## 8. コード中の見出し（数えない）",
            "~~~",
            "| 悪用状況（EPSS/KEV） | 対象: PYSEC-2020-1。最大EPSS 該当なし、KEV掲載 0件。詳細は8節 |",
            "```",
            "### 5.2 [Medium] CVEを直接持つ指摘",
            (
                "| 悪用状況（EPSS/KEV） | 対象: CVE-2023-0001。最大EPSS 0.034（CVE-2023-0001）、"
                "KEV掲載 0件。"
                "詳細は8節 |"
            ),
            "### 5.3 [Low] OSVで失敗した勧告",
            (
                "| 悪用状況（EPSS/KEV） | 対象: GHSA-1111-2222-3333。最大EPSS 未取得（OSV: HTTP 404）、"
                "KEV掲載 未取得（同上）。詳細は8節 |"
            ),
            "## 6. リスク分析",
            "## 8. SCA（依存関係脆弱性）スキャン結果",
            "npm audit: GHSA-aaaa-bbbb-cccc（CVE-2021-44228）ほか",
            "~~~text",
            "**EPSS・KEV（悪用状況）**: 取得済み",
            "取得日時: x、KEVカタログ版: x、EPSSの基準日: x。",
            "```",
            "~~~",
            "**EPSS・KEV（悪用状況）**: 一部未取得（理由: OSV: HTTP 404）",
            "",
            "| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |",
            "| --- | --- | --- | --- | --- | --- |",
            "| GHSA-aaaa-bbbb-cccc | CVE-2021-44228 | 0.03425 | 0.88588 | "
            "掲載（2021-12-10登録） | "
            + links("GHSA-aaaa-bbbb-cccc", "CVE-2021-44228")
            + " |",
            "| GHSA-dddd-eeee-ffff | CVE-2099-0001 | 該当なし | 該当なし | 非掲載 | "
            + links("GHSA-dddd-eeee-ffff", "CVE-2099-0001")
            + " |",
            "| PYSEC-2020-1 | CVEなし（対象外） | ― | ― | ― | "
            + links("PYSEC-2020-1")
            + " |",
            "| CVE-2023-0001 | CVE-2023-0001 | 0.034 | 0.886 | 非掲載 | "
            + links("CVE-2023-0001", "CVE-2023-0001")
            + " |",
            "| GHSA-1111-2222-3333 | 不明（OSV: HTTP 404 \\| x） | 未取得（同上） | 未取得（同上） | "
            "未取得（同上） | " + links("GHSA-1111-2222-3333") + " |",
            (
                "<!-- 例: | GHSA-xxxx-xxxx-xxxx | CVE-2024-0001 | 0.12345 | 0.98765 | "
                "掲載（2026-01-15登録） | -->"
            ),
            "",
            (
                "取得日時: 2026-10-09T00:00:00Z、KEVカタログ版: 2026.10.08、EPSSの基準日: 2026-10-08。"
                "EPSS data from FIRST (https://www.first.org/epss/)"
            ),
            "## 9. 自己レビュー（見落とし確認）",
            "CVE-2000-0001 は SCA 外の参考情報",
        ]
    )
    ng, warn = check_report_text(rep, dr)
    check(
        "報告書照合: 正常（丸め・no_cve・error・コメントとコードフェンス内の行を除外）",
        ng == [] and warn == [],
        (ng, warn),
    )
    a_rep = (
        "GHSA-aaaa-bbbb-cccc | CVE-2021-44228 | 0.03425 | 0.88588 | "
        "掲載（2021-12-10登録）"
    )
    row5 = "最大EPSS 0.03425（CVE-2021-44228）、KEV掲載 1件（CVE-2021-44228）"
    rbreaks = (
        ("値の改ざん（EPSS）", a_rep, a_rep.replace("0.03425", "0.04425"), "EPSS"),
        (
            "値の改ざん（丸めが小数第2位）",
            "| 0.034 | 0.886 |",
            "| 0.03 | 0.886 |",
            "EPSS",
        ),
        (
            "値の改ざん（パーセンタイル）",
            a_rep,
            a_rep.replace("0.88588", "0.8"),
            "パーセンタイル",
        ),
        ("値の改ざん（KEV登録日）", "2021-12-10登録", "2021-12-11登録", "KEV"),
        (
            "値の改ざん（KEV非掲載→掲載）",
            "| 0.886 | 非掲載 |",
            "| 0.886 | 掲載（登録日不明） |",
            "KEV",
        ),
        (
            "URL欠落（NVD）",
            " [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)",
            "",
            "根拠URL",
        ),
        (
            "URL欠落（no_cveの勧告）",
            "[勧告](https://osv.dev/vulnerability/PYSEC-2020-1)",
            "",
            "根拠URL",
        ),
        ("取得日欠落", "取得日時: 2026-10-09T00:00:00Z、", "", "取得日時"),
        (
            "取得日時の不一致",
            "2026-10-09T00:00:00Z",
            "2026-10-08T00:00:00Z",
            "取得日時",
        ),
        (
            "KEVカタログ版の不一致",
            "KEVカタログ版: 2026.10.08",
            "KEVカタログ版: 2026.10.01",
            "KEVカタログ版",
        ),
        ("EPSS基準日の欠落", "、EPSSの基準日: 2026-10-08", "", "取得日時の行の形"),
        (
            "出典表記欠落",
            "EPSS data from FIRST (https://www.first.org/epss/)",
            "",
            "出典表記",
        ),
        (
            "no_cveの誤記（不明と書く）",
            "| CVEなし（対象外） |",
            "| 不明（OSV: x） |",
            "JSONと合わない",
        ),
        (
            "no_cveの誤記（値の列に未取得）",
            "| CVEなし（対象外） | ― |",
            "| CVEなし（対象外） | 未取得（x） |",
            "―",
        ),
        (
            "未取得の誤記（値があるのに未取得）",
            "| 0.034 | 0.886 |",
            "| 未取得（x） | 0.886 |",
            "未取得",
        ),
        (
            "未取得の誤記（理由なし）",
            "未取得（同上） | 未取得（同上） | 未取得（同上）",
            "未取得 | 未取得（同上） | 未取得（同上）",
            "未取得",
        ),
        (
            "値が無いのに数値（error）",
            "未取得（同上） | 未取得（同上） | 未取得（同上）",
            "0.1 | 未取得（同上） | 未取得（同上）",
            "未取得",
        ),
        (
            "値が無いのに数値（not_found）",
            "| 該当なし | 該当なし | 非掲載 |",
            "| 0.0 | 該当なし | 非掲載 |",
            "該当なし",
        ),
        (
            "errorを未取得と書かない（CVE列）",
            "| 不明（OSV: HTTP 404 \\| x） |",
            "| CVEなし（対象外） |",
            "JSONと合わない",
        ),
        (
            "最大EPSSの不一致",
            row5,
            row5.replace("最大EPSS 0.03425", "最大EPSS 0.01"),
            "最大EPSS",
        ),
        (
            "最大EPSSのCVEの不一致",
            row5,
            row5.replace("0.03425（CVE-2021-44228）", "0.03425（CVE-2099-0001）"),
            "最大EPSSのCVE",
        ),
        (
            "KEV掲載件数の不一致",
            row5,
            row5.replace("KEV掲載 1件", "KEV掲載 2件"),
            "KEV掲載",
        ),
        (
            "値があるのに最大EPSS未取得",
            "最大EPSS 0.034（CVE-2023-0001）",
            "最大EPSS 未取得（x）",
            "最大EPSS",
        ),
        (
            "値が無いのに最大EPSSが数値",
            "最大EPSS 未取得（OSV: HTTP 404）",
            "最大EPSS 0.1（CVE-2023-0001）",
            "最大EPSS",
        ),
        (
            "CVEの無い指摘に行",
            "## 6. リスク分析",
            (
                "### 5.4 [Low] x\n| 悪用状況（EPSS/KEV） | 対象: PYSEC-2020-1。最大EPSS 該当なし、"
                "KEV掲載 0件。"
                "詳細は8節 |\n## 6."
            ),
            "CVEの無い指摘",
        ),
        (
            "対象がJSONに無い",
            "対象: CVE-2023-0001。",
            "対象: CVE-2023-0001、GHSA-9999-9999-9999。",
            "JSONに無い",
        ),
        (
            "表の行の欠落",
            "| CVE-2023-0001 | CVE-2023-0001 |",
            "| GHSA-9999-9999-9999 | CVE-2023-0001 |",
            "表に無い",
        ),
        (
            "状況行の欠落",
            "**EPSS・KEV（悪用状況）**: 一部",
            "EPSS/KEV: 一部",
            "1個であるべき",
        ),
        (
            "状況行がJSONと不一致",
            "一部未取得（理由: OSV: HTTP 404）",
            "取得済み（CVE 3件、KEV掲載 1件）",
            "状況",
        ),
        (
            "状況行の理由が空",
            "一部未取得（理由: OSV: HTTP 404）",
            "一部未取得（理由: ）",
            "理由が無い",
        ),
        (
            "KEV掲載の括弧の欠落（全件を挙げる）",
            row5,
            row5.replace("1件（CVE-2021-44228）", "1件"),
            "括弧内",
        ),
        (
            "取得日時の行が2つ（2つ目の誤り）",
            "## 9. 自己レビュー",
            (
                "取得日時: 2026-10-09T00:00:00Z、KEVカタログ版: 2026.10.01、EPSSの基準日: 2026-10-08。"
                "\n## 9. 自己レビュー"
            ),
            "2個",
        ),
        (
            "全角コロン（対象）",
            "対象: CVE-2023-0001。",
            "対象：CVE-2023-0001。",
            "表記の揺れ",
        ),
        (
            "全角コロン（取得日時の行）",
            "KEVカタログ版: 2026.10.08",
            "KEVカタログ版：2026.10.08",
            "表記の揺れ",
        ),
        (
            "「詳細は8節を参照」の行のKEV件数",
            "0001）、KEV掲載 0件。詳細は8節",
            "0001）、KEV掲載 2件。詳細は8節を参照",
            "「2件」",
        ),
    )
    for name, old, new, word in rbreaks:
        ng, _ = check_report_text(rep.replace(old, new, 1), dr)
        check(
            f"報告書照合の破壊: {name}",
            old in rep and ng != [] and any(word in x for x in ng),
            ng,
        )
    ng, warn = check_report_text(
        rep.replace("npm audit: GHSA-aaaa-bbbb-cccc", "npm audit: GHSA-zzzz-zzzz-zzzz"),
        dr,
    )
    check(
        "報告書照合: 8節のIDがJSONに無ければWARN（NGにしない）",
        ng == [] and len(warn) == 1 and "GHSA-zzzz" in warn[0],
        (ng, warn),
    )
    alias = rep.replace(
        "対象: GHSA-aaaa-bbbb-cccc、", "対象: GHSA-aaaa-bbbb-cccc（CVE-2021-44228）、"
    )
    ng, warn = check_report_text(alias, dr)
    check(
        "報告書照合: 対象に勧告のCVEを併記してもよい",
        ng == [] and warn == [],
        (ng, warn),
    )
    ng, warn = check_report_text(
        rep.replace(
            "0001）、KEV掲載 0件。詳細は8節 |", "0001）、KEV掲載 0件。詳細は8節を参照 |"
        ),
        dr,
    )
    check(
        "報告書照合: 「詳細は8節を参照」でもよい", ng == [] and warn == [], (ng, warn)
    )
    lack = rep.replace(
        "### 5.2 [Medium] CVEを直接持つ指摘",
        "### 5.2 [Medium] CVEを直接持つ指摘\n関連: GHSA-dddd-eeee-ffff",
    )
    ng, warn = check_report_text(lack, dr)
    check(
        "報告書照合: 同じ指摘に現れるJSONのIDが対象に無ければWARN（列挙漏れ）",
        ng == []
        and len(warn) == 1
        and "列挙漏れ" in warn[0]
        and "GHSA-dddd-eeee-ffff" in warn[0],
        (ng, warn),
    )
    # 理由の中の「。」（CA証明書の失敗）: 括弧の外の最初の「。」で切る（取得日時の行・5節の行・状況行）
    why_ca = (
        "OSV: 証明書を検証できない（PythonのCA証明書の設定を確認。macOSのpython.org版なら「Install "
        "Certificates.command」を実行）"
    )
    cert_full = FetchError(why_ca[5:] + " (x)", retry=False, cert=True)
    dca = build(
        ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"],
        fake({OSV_API + x: cert_full for x in ghsa}),
        now=now,
    )
    rep_ca = (
        "## 5. 指摘詳細\n### 5.1 [High] x\n"
        f"| 悪用状況（EPSS/KEV） | 対象: GHSA-aaaa-bbbb-cccc。最大EPSS 未取得（{why_ca}）、KEV掲載 "
        f"未取得（{why_ca}）。詳細は8節 |\n"
        f"## 8. SCA\n**EPSS・KEV（悪用状況）**: 未取得（理由: {why_ca}）\n"
        "| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |\n|---|---|---|---|"
        "---|---|\n"
        + "".join(
            f"| {v} | 不明（{why_ca}） | 未取得（同上） | 未取得（同上） | 未取得（同上） | {links(v)} |\n"
            for v in ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff")
        )
        + f"取得日時: {now}、KEVカタログ版: 未取得（{why_ca}）、EPSSの基準日: 未取得（{why_ca}）。"
        "EPSS data from FIRST (https://www.first.org/epss/)\n"
    )
    ng, warn = check_report_text(rep_ca, dca)
    check(
        "報告書照合: 理由に「。」を含むCA証明書の失敗（取得日時の行・5節の行・状況行）→OK",
        ng == [] and warn == [],
        (ng, warn),
    )
    ng, _ = check_report_text(
        rep_ca.replace(f"KEV掲載 未取得（{why_ca}）", "KEV掲載 0件"), dca
    )
    check(
        "報告書照合: 理由に「。」を含む行でも値の誤りはNG",
        any("KEV掲載「0件」" in x for x in ng),
        ng,
    )
    # 地の文の「取得日時は…」・インラインコード・字下げの ``` は取得日時の行・フェンスとして扱わない
    prose = rep.replace(
        "**EPSS・KEV（悪用状況）**: 一部",
        "取得日時はJSONを参照。\n```x```\n    ```\n**EPSS・KEV（悪用状況）**: 一部",
    )
    ng, warn = check_report_text(prose, dr)
    check(
        "報告書照合: 地の文の取得日時・インラインコード・字下げの```を誤検出しない",
        ng == [] and warn == [],
        (ng, warn),
    )
    ng, _ = check_report_text(
        rep.replace("0001）、KEV掲載 0件。", "0001）、KEV掲載 0 件。"), dr
    )
    check(
        "報告書照合: 「KEV掲載 0 件」（件の前の空白）は形の誤りとして分かるメッセージ",
        any("空白" in x for x in ng),
        ng,
    )
    a2 = parse_args(["--self-test"])
    check(
        "--self-test でも既定値（20・120・200）が入る",
        (a2.timeout, a2.max_seconds, a2.max_ids) == (20.0, MAX_SECONDS, MAX_IDS),
    )
    # 小さい値: 書いた桁で許容差を決める（0.00162 の改ざん・行どうしの入れ替えを見逃さない）
    dr_s = json.loads(json.dumps(dr))
    es_ = {e["id"]: e for e in dr_s["entries"]}
    es_["GHSA-aaaa-bbbb-cccc"]["items"][0]["epss"] = 0.00162
    es_["CVE-2023-0001"]["items"][0]["epss"] = 0.00156
    rep_s = (
        rep.replace("| 0.03425 | 0.88588 |", "| 0.00162 | 0.88588 |")
        .replace("| 0.034 | 0.886 |", "| 0.00156 | 0.886 |")
        .replace("最大EPSS 0.03425（", "最大EPSS 0.00162（")
        .replace("最大EPSS 0.034（", "最大EPSS 0.0016（")
    )
    ng, warn = check_report_text(rep_s, dr_s)
    check(
        "報告書照合: 小さい値の正常（そのまま・書いた桁での丸め）",
        ng == [] and warn == [],
        (ng, warn),
    )
    for name, old, new, word in (
        (
            "小さい値の改ざん（0.00162→0.00201）",
            "| 0.00162 | 0.88588 |",
            "| 0.00201 | 0.88588 |",
            "EPSS",
        ),
        (
            "小さい値の改ざん（0.00162→0.00126）",
            "| 0.00162 | 0.88588 |",
            "| 0.00126 | 0.88588 |",
            "EPSS",
        ),
        (
            "最大EPSSの小さい値の不一致",
            "最大EPSS 0.00162（",
            "最大EPSS 0.00156（",
            "最大EPSS",
        ),
    ):
        ng, _ = check_report_text(rep_s.replace(old, new, 1), dr_s)
        check(
            f"報告書照合の破壊: {name}", old in rep_s and any(word in x for x in ng), ng
        )
    swap = (
        rep_s.replace("| 0.00162 |", "| @ |")
        .replace("| 0.00156 |", "| 0.00162 |")
        .replace("| @ |", "| 0.00156 |")
    )
    ng, _ = check_report_text(swap, dr_s)
    check(
        "報告書照合の破壊: 行どうしの入れ替え（0.00162⇔0.00156）",
        sum("のEPSS" in x for x in ng) == 2,
        ng,
    )
    # 長い入力でも線形に終わる（正規表現の破滅的なバックトラックが無い）
    t0 = time.monotonic()
    long_rep = (
        "## 5. x\n### 5.1 x\n| 悪用状況（EPSS/KEV） | 対象: "
        + "GHSA-aaaa-bbbb-cccc、" * 200
        + "。最大EPSS" * 200
        + "未取得（"
        + " " * 5000
        + "|\n"
        + "<!--" * 5000
        + "\n## 8. SCA\n**EPSS・KEV（悪用状況）**: 一部未取得（理由:"
        + " x" * 5000
        + "\n取得日時: "
        + "、KEVカタログ版: " * 200
        + "、EPSSの基準日: " * 200
        + "未取得（" * 2000
        + "\n"
        + "| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |\n"
        + "| GHSA-aaaa-bbbb-cccc | 不明（"
        + "（" * 5000
        + " | 0."
        + "1" * 5000
        + " | x | x | "
        + "https://" * 2000
        + " |\n"
    )
    check_report_text(long_rep, dr)
    check_report_text(long_rep, None)
    check(
        "報告書照合: 長い入力（200回以上の繰り返し）でも1秒以内",
        time.monotonic() - t0 < 1.0,
        time.monotonic() - t0,
    )
    check(
        "報告書照合: 数値の許容（小数第3位までの丸め・指数表記）",
        num_near("0.123", 0.12345)
        and num_near("9e-05", 0.00009)
        and not num_near("0.12", 0.12345),
    )
    # JSONが無い場合（状況の1行だけ）・IDなし・全IDがOSV失敗
    nojson = (
        "## 8. SCA\nnpm audit: 実施\n**EPSS・KEV（悪用状況）**: 未取得（理由: SCA_EPSS_KEV=0 "
        "で省略）\n## 9. x\n"
    )
    check(
        "報告書照合: JSONなし・未取得の1行だけ→OK",
        check_report_text(nojson, None) == ([], []),
    )
    table_line = "| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |\n"
    for name, txt in (
        ("表がある", nojson.replace("## 9.", table_line + "## 9.")),
        (
            "取得日時の行がある",
            nojson.replace(
                "## 9.", "取得日時: x、KEVカタログ版: x、EPSSの基準日: x。\n## 9."
            ),
        ),
        (
            "5節に数値",
            "## 5. x\n| 悪用状況（EPSS/KEV） | 対象: CVE-2023-0001。最大EPSS 0.1、KEV掲載 0件 |\n"
            + nojson,
        ),
        (
            "状況が取得済み",
            nojson.replace(
                "未取得（理由: SCA_EPSS_KEV=0 で省略）",
                "取得済み（CVE 1件、KEV掲載 0件）",
            ),
        ),
        ("状況行が無い", nojson.replace("**EPSS・KEV（悪用状況）**", "EPSS/KEV")),
        ("8節が無い", nojson.replace("## 8. SCA", "## 7. SCA")),
    ):
        check(
            f"報告書照合: JSONなし・{name}→NG",
            check_report_text(txt, None)[0] != [],
            name,
        )
    empty = (
        "## 8. SCA\n**EPSS・KEV（悪用状況）**: スキャン出力に脆弱性IDなし\n"
        "取得日時: 2026-10-09T00:00:00Z、KEVカタログ版: なし（対象のCVEなし）、EPSSの基準日: なし（対象のCVEなし）。"
        "EPSS data from FIRST (https://www.first.org/epss/)\n"
    )
    check(
        "報告書照合: IDなし（なし（理由））→OK",
        check_report_text(empty, d6) == ([], []),
        check_report_text(empty, d6),
    )
    ng, _ = check_report_text(
        empty.replace(
            "KEVカタログ版: なし（対象のCVEなし）", "KEVカタログ版: 2026.10.08"
        ),
        d6,
    )
    check(
        "報告書照合: JSONでnullのKEVカタログ版に値→NG",
        any("KEVカタログ版" in x for x in ng),
        ng,
    )
    osvf = (
        empty.replace(
            "スキャン出力に脆弱性IDなし", "未取得（理由: OSV: タイムアウト）"
        ).replace("なし（対象のCVEなし）", "未取得（OSV: タイムアウト）")
        + (
            "| 勧告ID | CVE | EPSS（確率） | パーセンタイル | KEV（掲載・登録日） | 根拠URL |\n"
            "|---|---|---|---|---|---|\n"
        )
        + "".join(
            f"| {v} | 不明（OSV: タイムアウト） | 未取得（同上） | 未取得（同上） | 未取得（同上） | {links(v)} |\n"
            for v in ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff")
        )
    )
    ng, warn = check_report_text(osvf, d2)
    check(
        "報告書照合: 全IDがOSV失敗（未取得（理由））→OK",
        ng == [] and warn == [],
        (ng, warn),
    )
    ng, _ = check_report_text(
        osvf.replace(
            "EPSSの基準日: 未取得（OSV: タイムアウト）",
            "EPSSの基準日: なし（対象のCVEなし）",
        ),
        d2,
    )
    check(
        "報告書照合: 取得失敗なのに「なし（理由）」→NG",
        any("EPSSの基準日" in x for x in ng),
        ng,
    )
    # 入出力（ファイル・終了コード・引数）
    with tempfile.TemporaryDirectory() as td:
        rp, jp = os.path.join(td, "r.md"), os.path.join(td, "e.json")
        with open(rp, "w", encoding="utf-8") as f:
            f.write(rep)
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(dr, f)
        codes = []
        for args in (
            (rp, jp),
            (rp, None),
            (os.path.join(td, "none.md"), jp),
            (rp, os.path.join(td, "none.json")),
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                codes.append(check_report(*args))
        bad_doc = dict(dr, schema=2)
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(bad_doc, f)
        sink = io.StringIO()
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            codes.append(check_report(rp, jp))
        # 不正な形のJSON: validate() で検出し、トレースバックを出さず rc=2
        jbreaks = {
            "sourcesが配列": lambda x: x.update(sources=[]),
            "epssが文字列": lambda x: x["sources"].update(epss="x"),
            "urlsが配列": lambda x: x["entries"][0]["items"][0].update(urls=[]),
            "urlsに数値の追加キー": lambda x: x["entries"][0]["items"][0][
                "urls"
            ].update(extra=5, nvd="https://x/"),
            "score_dateキー欠落": lambda x: x["sources"]["epss"].pop("score_date"),
            "kev_date_addedキー欠落": lambda x: x["entries"][0]["items"][0].pop(
                "kev_date_added"
            ),
            "cvesにnull": lambda x: x["entries"][0].update(cves=[None]),
            "kevが1": lambda x: x["entries"][0]["items"][0].update(kev=1),
        }
        jcodes = {}
        for name, brk in jbreaks.items():
            x = json.loads(json.dumps(dr))
            brk(x)
            found: bool | str
            try:
                found = validate(x) != []
            except Exception as ex:  # validate 自体が落ちたら失敗
                found = f"例外 {type(ex).__name__}"
            with open(jp, "w", encoding="utf-8") as fp:
                json.dump(x, fp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                jcodes[name] = (
                    found,
                    check_report(rp, jp),
                    "Traceback" in buf.getvalue(),
                )
        with open(jp, "w", encoding="utf-8") as fp:
            fp.write("[" * 100000 + "]" * 100000)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            jcodes["入れ子が深いJSON"] = (
                True,
                check_report(rp, jp),
                "Traceback" in buf.getvalue(),
            )
    for name, jgot in jcodes.items():
        check(
            f"報告書照合: 不正な形のJSON（{name}）→ validate で検出・rc=2",
            jgot == (True, 2, False),
            jgot,
        )
    check(
        "報告書照合: 終了コード（OK=0・NG=1・読めない=2・JSONの形が不正=2）",
        codes == [0, 1, 2, 2, 2],
        codes,
    )
    a1 = parse_args(["--check-report", "r.md", "--json", "e.json"])
    arg_codes: list[int | str | None] = []
    for argv in (
        ["--json", "e.json"],
        ["--check-report", "r.md", "--out", "o.json"],
        ["--check-report", "r.md", "--status-line"],
        ["--check-report", "r.md", "--timeout", "5"],
        ["--check-report", "r.md", "--max-ids", "3"],
        ["--check-report", "r.md", "--max-seconds", "9"],
        ["--check-report", "r.md", "--kev-cache", "k.json"],
    ):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parse_args(argv)
            arg_codes.append(0)
        except SystemExit as ex:
            arg_codes.append(ex.code)
    check(
        "報告書照合: 引数（--out不要・--json単独と取得の引数の併用は rc=2）",
        a1.check_report == "r.md" and arg_codes == [2] * 7,
        arg_codes,
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
