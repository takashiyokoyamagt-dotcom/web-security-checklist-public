#!/usr/bin/env python3
"""SCA由来の脆弱性IDについて、EPSS（FIRST）とKEV（CISA）の値と根拠URLを取得する（標準ライブラリのみ）。
使い方: fetch_epss_kev.py [--from-text SCA出力.txt] [--id ID ...] --out 結果.json
        [--kev-cache PATH] [--timeout 秒] [--max-seconds 秒] [--max-ids N] [--status-line]
      | --check-report 報告書.md [--json 結果.json] | --self-test
入力: --from-text のテキストから CVE・GHSA・PYSEC・GO・RUSTSEC・OSV の ID を抽出し、--id（繰り返し可）と
合わせて正規化（CVE等は大文字、GHSAの本体は小文字）してから検証し、重複を除く。ID 0件は「IDなし」として
正常終了する（entries は空、通信もしない）。CVE・GHSA・PYSEC・RUSTSEC は大文字小文字を問わず、GO・OSV は
大文字のみ受ける（文中の語を拾わないため）。テキストでは、前が - か、前後がASCII英数字（NFKCで全角を含む）の
ものは除く（漢字・かな・é 等は境界として扱う）。出力の entries[].id は入力ではなく正規化後のID。
ID→CVE: CVE以外は OSV（https://api.osv.dev/v1/vulns/<ID>）の id・aliases から CVE を得る（無ければ no_cve）。
EPSS: https://api.first.org/data/v1/epss?cve=... を最大50件ずつ取得する（応答に無いCVEは not_found）。
KEV: CISAのカタログを1回だけ取得し（--kev-cache に保存。省略時は一時ファイルで終了時に消す）、cveID と照合する。
CVEが1件も無ければKEVは取得せず、sources.kev の catalog_version 等と error は null になる。
entries[].status は OSV で CVE を得られたか（ok/no_cve/error。不正な形式のIDも error）だけを表す。
EPSS・KEVの失敗は items[]（epss_status=error と epss_error、kev=null）と sources.kev.error に出る。
items[].epss_error はEPSSを取得・解釈できなかった理由（epss_status=error のときだけ文字列、他は null）。
sources.tls_ca は証明書の検証に使ったCAバンドルのパス（既定のCAで足りたときは null。Tls を参照）。
外部の値は型・範囲を確かめてから入れる（EPSS・パーセンタイルは0〜1の有限の数値で、外れた行はそのCVEを
error にする。日付は YYYY-MM-DD の文字列、KEVの各項目は文字列のみ。他は null）。
送るのはID（CVE/GHSA等）だけで、対象のコードや内容は送らない。HTTPSのみ・証明書検証あり（既定のCAファイル・
ディレクトリが存在しない環境では既知のシステムCAバンドルに1回だけ切り替え、sources.tls_ca に記録する。Tls を参照）。
User-Agentに web-security-checklist を付ける。各リクエストは最大2回再試行する（1秒・2秒待つ。
HTTP 4xx（429以外）と証明書の検証失敗は再試行しない）。
打ち切り（Guard を参照）: 同じホストへの接続レベルの失敗（接続拒否・タイムアウト・名前解決失敗）が3回続いたら
そのホストへの残りを同じ理由の error にし、開始から --max-seconds（既定120）を過ぎたら残りを「時間切れ」の
error にする。IDは先頭の --max-ids（既定200）件だけを処理し、超過分は sources.id_limit と要約に記録する。
EPSS・KEVは補助情報で、CVSSの重大度は変えない。出力JSON（schema 1）の形は validate() を参照。schemaは1のまま
sources.id_limit を必須とする（T4時点のJSONは validate() を通らない）。書き出す前に
validate() を通し、違反は要約に WARN として出す。
標準出力に1行1IDの要約（ID | CVE | EPSS(確率/パーセンタイル/基準日) | KEV(有/無/未取得) | 状態）を出す。
--status-line は要約の後に取得状況の1行（status_line() を参照。run_sca_scan.sh が使う）を足す。
終了コード 0=完了（通信失敗は該当IDを error にして続行し0） 2=引数エラー（ID形式・入力ファイル・--timeout・
--max-seconds・--max-ids・出力先。--out と --kev-cache の書き込み先は通信の前に確かめる）。
--check-report は通信せず、報告書（assets/templates/report_template.md の表記）の8節の状況行・EPSS・KEVの表（値・根拠URL・
no_cve/errorの行）・取得日時の行・出典表記と、5節の「悪用状況（EPSS/KEV）」行（対象の勧告から計算した最大EPSS・
KEV掲載件数）をJSONと照合する（check_report_text() を参照。数値は書いた桁での丸めを許容。ROUND_PLACES）。8節等に現れる
IDがJSONに無ければWARN（コードフェンス・HTMLコメント内の行は照合にもWARNにも使わない）。--json を省くとJSONが無い場合の検査（状況の1行だけで、表・取得日時の行・数値が無いこと）。
終了コード 0=OK（WARNのみを含む） 1=NG 2=入力エラー（報告書・JSONを読めない、JSONが validate() を通らない）。
--self-test は通信せず、固定データで正常系と失敗系を確かめる。Python 3.9以上で動く。
"""

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

EPSS_API = "https://api.first.org/data/v1/epss"
OSV_API = "https://api.osv.dev/v1/vulns/"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_ATTR = "EPSS data from FIRST (https://www.first.org/epss/)"
UA = "web-security-checklist/fetch_epss_kev (+python-urllib)"
EPSS_BATCH = 50
RETRIES = 2  # 初回に加えた再試行の回数
CONN_FAILS = (
    3  # 同じホストへの接続レベルの失敗がこの回数続いたら、そのホストへの残りを打ち切る
)
MAX_SECONDS = 120.0  # 通信全体の時間上限（--max-seconds の既定）
MAX_IDS = 200  # 処理するIDの件数上限（--max-ids の既定。超過分は処理しない）
MAX_BYTES = 32 * 1024 * 1024  # 応答の上限（KEVカタログは約1.8MB。2026-10-09実測）
ACTION_MAX = 200  # requiredAction の保存字数
ID_PATTERNS = (
    r"CVE-\d{4}-\d{4,}",
    r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}",
    r"PYSEC-\d+-\d+",
    r"GO-\d+-\d+",
    r"RUSTSEC-\d+-\d+",
    r"OSV-\d+-\d+",
)
NOCASE = (
    "CVE-",
    "GHSA-",
    "PYSEC-",
    "RUSTSEC-",
)  # 大文字小文字を問わない接頭辞（GO・OSVは大文字のみ）
# 入力の形（正規化前）。前後の境界は extract_ids で確かめ、正規化してから ID_RE で検証する
ID_FIND = re.compile(
    "|".join(f"(?i:{x})" if x.startswith(NOCASE) else x for x in ID_PATTERNS),
    re.ASCII,
)
ID_RE = re.compile(
    "(?:" + "|".join(ID_PATTERNS) + ")", re.ASCII
)  # 正規化後の形（fullmatch で使う）
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)
DATE_RE = re.compile(r"\d{4}-\d\d-\d\d", re.ASCII)


class FetchError(Exception):
    """通信・HTTPの失敗（理由を日本語で持つ）。retry は再試行してよいか、cert は証明書の検証失敗か、
    conn は接続レベルの失敗（接続拒否・タイムアウト・名前解決失敗等。Guard が数える）か"""

    def __init__(
        self, msg: str, retry: bool = True, cert: bool = False, conn: bool = False
    ):
        super().__init__(msg)
        self.retry = retry
        self.cert = cert
        self.conn = conn


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise FetchError(f"HTTPS以外へのリダイレクトを拒否 ({newurl})", retry=False)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Tls:
    """CA証明書の選択。既定のSSL文脈で証明書の検証に失敗し、かつ既定のCAファイル・ディレクトリ（cafile・capath）が
    存在しないときに限り、既知のシステムCAバンドル（BUNDLES の順に最初に存在するもの）で文脈を作り直す（1回だけ
    試す。検証は無効にしない）。実在する SSL_CERT_FILE は既定の文脈が使うので、ここでは見ない。
    python.org版のPython（Install Certificates.command 未実行）向け。cafile は使ったバンドル（未使用なら None）
    """

    BUNDLES = (
        "/etc/ssl/cert.pem",
        "/private/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    )

    def __init__(
        self, exists=os.path.exists, paths=ssl.get_default_verify_paths, make_ctx=None
    ):
        self.exists, self.paths = exists, paths
        self.make_ctx = make_ctx or (
            lambda cafile: ssl.create_default_context(cafile=cafile)
        )
        self.ctx = None  # None は既定のSSL文脈
        self.cafile = None
        self.tried = False

    def fallback(self) -> bool:
        """バンドルの文脈に切り替えたら True"""
        if self.tried:
            return False
        self.tried = True
        p = self.paths()
        if any(x and self.exists(x) for x in (p.cafile, p.capath)):
            return False  # 既定のCAファイル・ディレクトリがある（バンドルに替えても直らない）
        for c in self.BUNDLES:
            if self.exists(c):
                try:
                    self.ctx = self.make_ctx(c)
                except (OSError, ssl.SSLError):
                    return False
                self.cafile = c
                return True
        return False


def open_url(req, timeout: float, ctx) -> bytes:
    handlers = [HttpsOnlyRedirect] + (
        [urllib.request.HTTPSHandler(context=ctx)] if ctx else []
    )
    with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as r:
        return r.read(MAX_BYTES + 1)


def get_once(url: str, timeout: float, ctx, opener) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/json"}
    )
    try:
        body = opener(req, timeout, ctx)
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code}", retry=e.code == 429 or e.code >= 500)
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise FetchError("タイムアウト", conn=True)
        if isinstance(
            e.reason, ssl.SSLCertVerificationError
        ):  # 一時的でないので再試行しない
            raise FetchError(
                "証明書を検証できない（PythonのCA証明書の設定を確認。macOSのpython.org版なら"
                f"「Install Certificates.command」を実行） ({e.reason})",
                retry=False,
                cert=True,
            )
        raise FetchError(f"接続失敗 ({e.reason})", conn=True)
    except http.client.HTTPException as e:  # IncompleteRead・BadStatusLine 等
        raise FetchError(f"HTTP応答の異常 ({type(e).__name__})")
    except (socket.timeout, TimeoutError):
        raise FetchError("タイムアウト", conn=True)
    except OSError as e:
        raise FetchError(f"接続失敗 ({e})", conn=True)
    if len(body) > MAX_BYTES:
        raise FetchError(f"応答が{MAX_BYTES}Bを超える", retry=False)
    return body


def http_get(
    url: str, timeout: float, tls: Tls | None = None, opener=open_url
) -> bytes:
    """1回のGET（証明書の検証失敗時のCAバンドルへの切り替えを含む）。失敗は FetchError にする"""
    if not url.startswith("https://"):
        raise FetchError(f"HTTPS以外のURL ({url})", retry=False)
    try:
        return get_once(url, timeout, tls.ctx if tls else None, opener)
    except FetchError as e:
        if not (e.cert and tls and tls.fallback()):
            raise
    return get_once(url, timeout, tls.ctx, opener)


def with_retry(get, sleep=time.sleep):
    """get(url) を最大 RETRIES 回再試行する（待ち時間 1秒・2秒）"""

    def wrapped(url: str) -> bytes:
        for n in range(RETRIES + 1):
            try:
                return get(url)
            except FetchError as e:
                if not e.retry or n == RETRIES:
                    raise
            sleep(n + 1)
        raise AssertionError("unreachable")

    return wrapped


class Guard:
    """1回ごとの通信（get(url, timeout)）の打ち切り。同じホストへの接続レベルの失敗（FetchError.conn）が
    CONN_FAILS 回続いたら、そのホストへの残りを同じ理由の error にする（HTTPの応答や成功で数え直す）。
    開始から max_seconds を過ぎたら残りを「時間切れ」の error にする（各回のタイムアウトも残り時間以下にする）。
    どちらも再試行しない。clock は差し替え可能（自己テスト用）"""

    def __init__(
        self,
        get,
        timeout: float,
        max_seconds: float = MAX_SECONDS,
        clock=time.monotonic,
    ):
        self.get, self.timeout, self.max, self.clock = get, timeout, max_seconds, clock
        self.t0 = clock()
        self.fails: dict = {}
        self.cut: dict = {}  # ホスト→打ち切りの理由

    def __call__(self, url: str) -> bytes:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host in self.cut:
            raise FetchError(self.cut[host], retry=False)
        left = self.max - (self.clock() - self.t0)
        if left <= 0:
            raise FetchError(
                f"時間切れ（--max-seconds {self.max:g}秒を超過）", retry=False
            )
        try:
            body = self.get(url, min(self.timeout, left))
        except FetchError as e:
            self.fails[host] = self.fails.get(host, 0) + 1 if e.conn else 0
            if self.fails[host] >= CONN_FAILS:
                self.cut[host] = (
                    f"{e}（{host} への接続失敗が{CONN_FAILS}回続いたため以降を打ち切り）"
                )
                raise FetchError(self.cut[host], retry=False, cert=e.cert)
            raise
        self.fails[host] = 0
        return body


def norm_id(x: str) -> str:
    """CVE・PYSEC・GO・RUSTSEC・OSV は大文字、GHSA は接頭辞を大文字・本体を小文字にする（ASCII以外はそのまま）"""
    x = x.strip()
    if not x.isascii():
        return x
    return "GHSA-" + x[5:].lower() if x.upper().startswith("GHSA-") else x.upper()


def ascii_alnum(ch: str) -> bool:
    """NFKC正規化でASCIIの英数字になる文字（全角英数を含む。漢字・かな・é 等は含まない）"""
    n = unicodedata.normalize("NFKC", ch)
    return n.isascii() and n.isalnum()


def extract_ids(text: str) -> list[str]:
    """テキストからIDを出現順に抽出し、正規化して重複を除く。前が - かASCII英数字、後ろがASCII英数字
    （どちらもNFKCで全角を含む）のものは長い語の一部として除く"""
    out = []
    for m in ID_FIND.finditer(text):
        a, b = m.start(), m.end()
        if (a and (text[a - 1] == "-" or ascii_alnum(text[a - 1]))) or (
            b < len(text) and ascii_alnum(text[b])
        ):
            continue
        out.append(norm_id(m.group(0)))
    return list(dict.fromkeys(out))


def collect_ids(text: str, given: list[str]):
    """(正規化・重複除去したID列, 形式が不正な --id の列)"""
    ids, bad = extract_ids(text), []
    for x in given:
        n = norm_id(x)
        if ID_FIND.fullmatch(x.strip()) and ID_RE.fullmatch(n):
            ids.append(n)
        else:
            bad.append(x)
    return list(dict.fromkeys(ids)), bad


def why(e: Exception) -> str:
    return str(e) if isinstance(e, FetchError) else f"{type(e).__name__}: {e}"


def get_json(get, url: str):
    try:
        return json.loads(get(url).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"不正なJSON応答 ({str(e)[:80]})")


def str_or_none(v):
    return v if isinstance(v, str) else None


def date_or_none(v):
    return v if isinstance(v, str) and DATE_RE.fullmatch(v) else None


def unit(v) -> float:
    """0〜1の有限の数値（ASCIIの数字文字列も可）。それ以外は ValueError"""
    if (
        isinstance(v, bool)
        or not isinstance(v, (int, float, str))
        or (isinstance(v, str) and not v.isascii())
    ):
        raise ValueError(f"数値でない ({type(v).__name__})")
    try:
        x = float(v)
    except OverflowError:  # 巨大な整数
        raise ValueError(f"0〜1の有限の数値でない ({str(v)[:20]}…)")
    if not math.isfinite(x) or not 0 <= x <= 1:
        raise ValueError(f"0〜1の有限の数値でない ({str(v)[:20]})")
    return x


def osv_cves(get, vid: str) -> list[str]:
    d = get_json(get, OSV_API + urllib.parse.quote(vid, safe=""))
    if not isinstance(d, dict) or not isinstance(d.get("id"), str):
        raise ValueError("不正なOSV応答 (idが無い)")
    al = d.get("aliases") or []
    if not isinstance(al, list):
        raise ValueError("不正なOSV応答 (aliasesが配列でない)")
    names = [d["id"]] + [a for a in al if isinstance(a, str)]
    return sorted({a for a in names if CVE_RE.fullmatch(a)})


def epss_url(cves: list[str]) -> str:
    return f"{EPSS_API}?cve={','.join(urllib.parse.quote(c, safe='') for c in cves)}"


def fetch_epss(get, cves: list[str]):
    """{CVE: (epss, percentile, date)} と {CVE: 失敗理由} を返す。50件ずつ問い合わせ、行ごとに値を確かめる"""
    got, err = {}, {}
    for i in range(0, len(cves), EPSS_BATCH):
        part = cves[i : i + EPSS_BATCH]
        try:
            d = get_json(get, epss_url(part))
            rows = d.get("data") if isinstance(d, dict) else None
            if not isinstance(rows, list):
                raise ValueError("不正なEPSS応答 (dataが配列でない)")
        except Exception as e:  # 通信・応答の失敗はこのバッチのCVEを error にして続行
            err.update({c: why(e) for c in part})
            continue
        for r in rows:
            c = r.get("cve") if isinstance(r, dict) else None
            if not isinstance(c, str) or c not in part or c in got:
                continue
            try:
                got[c] = (
                    unit(r.get("epss")),
                    unit(r.get("percentile")),
                    date_or_none(r.get("date")),
                )
                err.pop(c, None)
            except ValueError as e:
                err.setdefault(c, f"不正なEPSSの行 ({e})")
    return got, err


def fetch_kev(get, cache: str | None):
    """(src, {CVE: 掲載行} または None)。src は sources.kev。取得した内容を cache に保存する"""
    src = {
        "url": KEV_URL,
        "catalog_version": None,
        "date_released": None,
        "sha256": None,
        "error": None,
    }
    try:
        raw = get(KEV_URL)
    except Exception as e:  # 通信の失敗は全て記録して続行
        src["error"] = why(e)
        return src, None
    src["sha256"] = hashlib.sha256(raw).hexdigest()
    tmp = None
    try:
        if cache is None:
            fd, tmp = tempfile.mkstemp(prefix="kev-", suffix=".json")
            os.close(fd)
            dest = tmp
        else:
            dest = cache
        with open(dest, "wb") as f:
            f.write(raw)
    except OSError as e:
        print(f"WARN: KEVカタログを保存できない ({e})", file=sys.stderr)
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
    try:
        d = json.loads(raw.decode("utf-8"))
        vs = d.get("vulnerabilities") if isinstance(d, dict) else None
        if not isinstance(vs, list):
            raise ValueError("不正なKEV応答 (vulnerabilitiesが配列でない)")
    except (UnicodeDecodeError, ValueError) as e:
        src["error"] = (
            str(e) if str(e).startswith("不正な") else f"不正なJSON応答 ({str(e)[:80]})"
        )
        return src, None
    src["catalog_version"] = str_or_none(d.get("catalogVersion"))
    src["date_released"] = str_or_none(d.get("dateReleased"))
    return src, {
        v["cveID"]: v
        for v in vs
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    }


def advisory_url(vid: str) -> str:
    return (
        f"https://github.com/advisories/{vid}"
        if vid.startswith("GHSA-")
        else f"https://osv.dev/vulnerability/{vid}"
    )


def item(vid: str, cve: str, epss, epss_err, kev) -> dict:
    e = epss.get(cve)
    k = (None if kev is None else kev.get(cve)) or {}
    act = str_or_none(k.get("requiredAction"))
    return {
        "cve": cve,
        "epss": e[0] if e else None,
        "percentile": e[1] if e else None,
        "epss_date": e[2] if e else None,
        "epss_status": "ok" if e else ("error" if cve in epss_err else "not_found"),
        "epss_error": None if e else epss_err.get(cve),
        "kev": None if kev is None else cve in kev,
        "kev_date_added": date_or_none(k.get("dateAdded")),
        "kev_due_date": date_or_none(k.get("dueDate")),
        "kev_ransomware": str_or_none(k.get("knownRansomwareCampaignUse")),
        "kev_required_action": act[:ACTION_MAX] if act is not None else None,
        "urls": {
            "epss": epss_url([cve]),
            "kev": KEV_URL,
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "advisory": advisory_url(vid),
        },
    }


def build(
    ids: list[str],
    get,
    kev_cache: str | None = None,
    now: str | None = None,
    tls: Tls | None = None,
    max_ids: int = MAX_IDS,
) -> dict:
    """ID列（正規化済み）から出力JSON（dict）を作る。get(url)->bytes は差し替え可能（自己テスト用）。
    先頭の max_ids 件だけを処理し、超過分は sources.id_limit に記録する（entries には入れない）"""
    ids, excluded = ids[:max_ids], ids[max_ids:]
    entries = []
    for vid in ids:
        ent: dict[str, Any] = {
            "id": vid,
            "cves": [],
            "status": "ok",
            "error": None,
            "items": [],
        }
        if not ID_RE.fullmatch(vid):
            ent["status"], ent["error"] = "error", "IDの形式が不正"
        elif CVE_RE.fullmatch(vid):
            ent["cves"] = [vid]
        else:
            try:
                ent["cves"] = osv_cves(get, vid)
            except Exception as e:  # 通信・応答の失敗は該当IDを error にして続行
                ent["status"], ent["error"] = "error", f"OSV: {why(e)}"
            if ent["status"] == "ok" and not ent["cves"]:
                ent["status"] = "no_cve"
        entries.append(ent)
    cves = list(dict.fromkeys(c for ent in entries for c in ent["cves"]))
    epss, epss_err = fetch_epss(get, cves) if cves else ({}, {})
    kev_src = {
        "url": KEV_URL,
        "catalog_version": None,
        "date_released": None,
        "sha256": None,
        "error": None,
    }
    kev = None
    if cves:
        kev_src, kev = fetch_kev(get, kev_cache)
    for ent in entries:
        ent["items"] = [item(ent["id"], c, epss, epss_err, kev) for c in ent["cves"]]
    dates = sorted({v[2] for v in epss.values() if v[2] is not None})
    return {
        "schema": 1,
        "retrieved_at": now
        or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "epss": {
                "api": EPSS_API,
                "score_date": dates[-1] if dates else None,
                "attribution": EPSS_ATTR,
            },
            "kev": kev_src,
            "osv": {"api": OSV_API},
            "tls_ca": tls.cafile if tls else None,
            "id_limit": {
                "max_ids": max_ids,
                "excluded": len(excluded),
                "excluded_ids": excluded,
                "note": f"件数上限により除外: {len(excluded)}件" if excluded else None,
            },
        },
        "entries": entries,
    }


def validate(doc) -> list[str]:
    """出力JSONの形の検査（問題の一覧。空ならOK）"""
    p = []
    opt_s = (str, type(None))

    def is_unit(v):
        return (
            isinstance(v, (int, float))
            and not isinstance(v, bool)
            and math.isfinite(v)
            and 0 <= v <= 1
        )

    def is_date(v):
        return v is None or (isinstance(v, str) and DATE_RE.fullmatch(v) is not None)

    if not isinstance(doc, dict) or doc.get("schema") != 1:
        return ["schemaが1でない"]
    if not isinstance(doc.get("retrieved_at"), str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", doc["retrieved_at"], re.ASCII
    ):
        p.append("retrieved_at がUTC ISO8601でない")

    def obj(
        v, name
    ):  # 辞書でなければ問題に加えて空の辞書を返す（以降の検査で落ちないように）
        if isinstance(v, dict):
            return v
        p.append(f"{name} が辞書でない（無い）")
        return {}

    s = obj(doc.get("sources"), "sources")
    ep = obj(s.get("epss"), "sources.epss")
    if (
        ep.get("attribution") != EPSS_ATTR
        or "api" not in ep
        or "score_date" not in ep
        or not is_date(ep["score_date"])
    ):
        p.append("sources.epss が不正")
    k = obj(s.get("kev"), "sources.kev")
    for key in ("url", "catalog_version", "date_released", "sha256", "error"):
        if not isinstance(k.get(key, 0), opt_s):
            p.append(f"sources.kev.{key} が文字列/nullでない（無い）")
    if "api" not in obj(s.get("osv"), "sources.osv"):
        p.append("sources.osv.api が無い")
    if not isinstance(s.get("tls_ca", 0), opt_s):
        p.append("sources.tls_ca が文字列/nullでない（無い）")
    lim = s.get("id_limit")
    if (
        not isinstance(lim, dict)
        or not isinstance(lim.get("max_ids"), int)
        or not isinstance(lim.get("excluded_ids"), list)
        or lim.get("excluded") != len(lim["excluded_ids"])
        or not all(isinstance(x, str) for x in lim["excluded_ids"])
        or not isinstance(lim.get("note", 0), opt_s)
        or (lim["note"] is None) != (lim["excluded"] == 0)
    ):
        p.append("sources.id_limit が不正（無い）")
    ents = doc.get("entries")
    if not isinstance(ents, list):
        return p + ["entries が配列でない"]
    for e in ents:
        if not isinstance(e, dict) or not isinstance(e.get("id"), str):
            p.append("entry の id が無い")
            continue
        n = e["id"]
        if e.get("status") not in ("ok", "no_cve", "error"):
            p.append(f"{n}: status が不正")
        if not isinstance(e.get("error"), opt_s) or (e.get("status") == "error") != (
            e.get("error") is not None
        ):
            p.append(f"{n}: error と status が不整合")
        if not isinstance(e.get("cves"), list) or not isinstance(e.get("items"), list):
            p.append(f"{n}: cves/items が配列でない")
            continue
        if not all(isinstance(c, str) for c in e["cves"]):
            p.append(f"{n}: cves の要素が文字列でない")
        if [i.get("cve") for i in e["items"] if isinstance(i, dict)] != e["cves"]:
            p.append(f"{n}: items と cves が不一致")
        for i in e["items"]:
            if not isinstance(i, dict):
                p.append(f"{n}: item が不正")
                continue
            st = i.get("epss_status")
            if st not in ("ok", "not_found", "error"):
                p.append(f"{n}: epss_status が不正")
            for key in (
                "cve",
                "epss_status",
                "epss",
                "percentile",
                "kev",
                "kev_date_added",
                "urls",
            ):
                if key not in i:
                    p.append(f"{n}: item の {key} が無い")
            for key in ("epss", "percentile"):
                v = i.get(key)
                if (st == "ok") != is_unit(v) or (v is not None and not is_unit(v)):
                    p.append(f"{n}: {key} が0〜1の数値でない/状態と不整合")
            if not isinstance(i.get("epss_error", 0), opt_s) or (st == "error") != (
                i.get("epss_error") is not None
            ):
                p.append(f"{n}: epss_error と epss_status が不整合")
            if not (i.get("kev") is None or isinstance(i.get("kev"), bool)):
                p.append(f"{n}: kev が真偽値/nullでない")
            for key in ("epss_date", "kev_date_added", "kev_due_date"):
                if not is_date(i.get(key)):
                    p.append(f"{n}: {key} が YYYY-MM-DD/null でない")
            for key in ("kev_ransomware", "kev_required_action"):
                if not isinstance(i.get(key), opt_s):
                    p.append(f"{n}: {key} が文字列/nullでない")
            u = i.get("urls")
            if not isinstance(u, dict) or not isinstance(i.get("cve"), str):
                p.append(f"{n}: urls が辞書でない、または cve が文字列でない")
            elif not all(isinstance(x, str) for x in u.values()):
                p.append(f"{n}: urls の値が文字列でない")
            elif any(
                not str(u.get(key, "")).startswith("https://")
                for key in ("epss", "kev", "nvd", "advisory")
            ):
                p.append(f"{n}: urls が不正")
    return p


def clean(s) -> str:
    """要約に出す文字列から制御文字（Unicodeの C 分類）を除く"""
    return "".join(ch for ch in str(s) if unicodedata.category(ch)[0] != "C")


def summary(doc: dict, out: str, warns=()) -> str:
    lines = ["ID | CVE | EPSS(確率/パーセンタイル/基準日) | KEV(有/無/未取得) | 状態"]
    for e in doc["entries"]:
        ep, kv, notes = [], [], []
        for i in e["items"]:
            if i["epss_status"] == "ok":
                ep.append(
                    f"{i['epss']:.5f}/{i['percentile']:.5f}/{i['epss_date'] or '-'}"
                )
            else:
                ep.append("該当なし" if i["epss_status"] == "not_found" else "取得失敗")
            kv.append("未取得" if i["kev"] is None else ("有" if i["kev"] else "無"))
        errs = [i["epss_error"] for i in e["items"] if i["epss_error"]]
        if errs:
            notes.append(f"EPSS取得失敗: {errs[0]}")
        if any(i["kev"] is None for i in e["items"]):
            notes.append("KEV未取得")
        st = e["status"] if e["status"] != "error" else f"error({e['error']})"
        st += f"（{'、'.join(notes)}）" if notes else ""
        lines.append(
            " | ".join(
                [
                    e["id"],
                    ", ".join(e["cves"]) or "-",
                    ", ".join(ep) or "-",
                    ", ".join(kv) or "-",
                    st,
                ]
            )
        )
    if not doc["entries"]:
        lines.append("IDなし（EPSS・KEVの対象なし）")
    k = doc["sources"]["kev"]
    kev = k["catalog_version"] or (
        f"未取得({k['error']})" if k["error"] else "未取得(CVEなし)"
    )
    ca = doc["sources"]["tls_ca"] or "既定"
    lim = doc["sources"]["id_limit"]
    if lim["excluded"]:
        head = ", ".join(lim["excluded_ids"][:5]) + (
            " 等" if lim["excluded"] > 5 else ""
        )
        lines.append(f"{lim['note']}（--max-ids {lim['max_ids']}。{head}）")
    lines.append(
        f"取得日時: {doc['retrieved_at']} / KEV版: {kev} / CA証明書: {ca} / 出力: {out}"
    )
    lines += [f"WARN: 出力JSONの検査: {w}" for w in warns]
    return "\n".join(clean(x) for x in lines)


def status_line(doc: dict) -> str:
    """--status-line の1行（run_sca_scan.sh 用）: 取得済み／一部未取得／未取得（何も得られない）／対象のCVEなし／
    スキャン出力に脆弱性IDなし。理由は最初の失敗（件数上限による除外は最後）で、証明書の検証失敗が1つでもあれば「CA証明書」"""
    items = [i for e in doc["entries"] for i in e["items"]]
    errs = [e["error"] for e in doc["entries"] if e["status"] == "error"]
    errs += [f"EPSS: {i['epss_error']}" for i in items if i["epss_error"]]
    if doc["sources"]["kev"]["error"]:
        errs.append(f"KEV: {doc['sources']['kev']['error']}")
    if doc["sources"]["id_limit"]["note"]:
        errs.append(doc["sources"]["id_limit"]["note"])
    why_ = (
        "CA証明書"
        if any("証明書を検証できない" in x for x in errs)
        else (errs[0][:120] if errs else "")
    )
    if not doc["entries"]:
        return "EPSS/KEV: スキャン出力に脆弱性IDなし"
    if not items:
        if errs:
            return clean(f"EPSS/KEV: 未取得（理由: {why_}）")
        n = sum(e["status"] == "no_cve" for e in doc["entries"])
        return "EPSS/KEV: 対象のCVEなし" + (
            f"（CVEなしの勧告{n}件は対象外）" if n else ""
        )
    if errs:
        got = any(i["epss_status"] != "error" or i["kev"] is not None for i in items)
        return clean(f"EPSS/KEV: {'一部未取得' if got else '未取得'}（理由: {why_}）")
    cves = {i["cve"] for i in items}
    kev = {i["cve"] for i in items if i["kev"]}
    return f"EPSS/KEV: 取得済み（CVE {len(cves)}件、KEV掲載 {len(kev)}件）"


# --check-report: 報告書（assets/templates/report_template.md の8節・5節の表記）とJSONの照合
# 正規表現は線形のものだけを使い、ラベルでの分割は str.find で行う（長い入力で遅くならない）
ROUND_PLACES = 3  # 丸めの許容は書いた桁の半単位。小数第3位より粗く書いた値（0・0.03等）は第3位の半単位（0.0005）
STATUS_HEAD = "**EPSS・KEV（悪用状況）**:"
ROW_LABEL = "悪用状況（EPSS/KEV）"
DASHES = ("―", "—", "–", "-")
NUM_RE = re.compile(
    r"\d+(?:\.\d+)?(?:[eE]-\d{1,3})?", re.ASCII
)  # JSONの値の写し（9e-05 等）も受ける
URL_RE = re.compile(r"https://[^\s()<>\[\]|]+")
DATE_LABELS = ("取得日時:", "、KEVカタログ版:", "、EPSSの基準日:")
ROW5_LABELS = ("対象:", "。最大EPSS", "、KEV掲載")
VARIANT_HINT = "。表記の揺れ（全角コロン/半角括弧）も確かめる"


def paren(cell: str, head: str) -> bool:
    """cell が「head（理由）」の形で、理由が空でない"""
    return (
        cell.startswith(head + "（")
        and cell.endswith("）")
        and cell[len(head) + 1 : -1].strip() != ""
    )


def ungot(cell: str) -> bool:
    return paren(cell, "未取得")


def reason_ok(got: str, kind: str) -> bool:
    """状況行が「kind（理由: …）」の形で、理由が空でない"""
    head = kind + "（理由:"
    return (
        got.startswith(head)
        and got.endswith("）")
        and got[len(head) : -1].strip() != ""
    )


def cut_outside(s: str, stop: str = "。") -> int:
    """括弧（（）と()）の外にある最初の stop の位置（無ければ -1）。理由の中の「。」で切らないため"""
    depth = 0
    for k, ch in enumerate(s):
        if ch in "（(":
            depth += 1
        elif ch in "）)":
            depth = max(depth - 1, 0)
        elif ch == stop and depth == 0:
            return k
    return -1


def split_labels(s: str, labels):
    """s をラベル（順に現れる）で分け、各ラベルの後ろの値を返す。s がラベル[0]で始まらない・ラベルが欠ければ None"""
    if not s.startswith(labels[0]):
        return None
    out, pos = [], len(labels[0])
    for lab in labels[1:]:
        i = s.find(lab, pos)
        if i < 0:
            return None
        out.append(s[pos:i].strip())
        pos = i + len(lab)
    out.append(s[pos:].strip())
    return out


def strip_comments(text: str) -> str:
    """HTMLコメント（<!-- -->）を除く（行数は保つ。閉じていないものは残す）"""
    out, pos = [], 0
    while True:
        i = text.find("<!--", pos)
        j = text.find("-->", i + 4) if i >= 0 else -1
        if j < 0:
            out.append(text[pos:])
            return "".join(out)
        out += [text[pos:i], "\n" * text.count("\n", i, j + 3)]
        pos = j + 3


def report_sections(text: str) -> dict:
    """{"5": [(行番号, 行)], "8": [...], ...}。HTMLコメントとコードフェンス（```は```で、~~~は~~~で閉じる）の
    中の行は含めない（見出し・表・状況行・悪用状況の行として数えない）"""
    out: dict[str, list[tuple[int, str]]] = {}
    cur, fence = None, None
    for n, line in enumerate(strip_comments(text).splitlines(), 1):
        s = line.lstrip()
        if fence:
            if (
                not line.startswith(("    ", "\t"))
                and s.startswith(fence)
                and s.rstrip() == fence[0] * len(s.rstrip())
            ):
                fence = None
            continue
        m = None if line.startswith(("    ", "\t")) else re.match(r"`{3,}|~{3,}", s)
        if m and not (
            m.group(0)[0] == "`" and "`" in s[m.end() :]
        ):  # インラインコード（```x```）は除く
            fence = m.group(0)
            continue
        m = re.match(r"##\s+(\d+)\.", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        elif cur is not None:
            out[cur].append((n, line))
    return out


def md_cells(line: str) -> list[str]:
    """Markdownの表の1行をセルに分ける（`\\|` はセル内の |）"""
    s = line.strip()
    s = s.removeprefix("|")
    s = s[:-1] if s.endswith("|") and not s.endswith("\\|") else s
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", s)]


def epss_table(lines):
    """8節のEPSS・KEVの表の行 [(行番号, セル)]。表が無ければ None"""
    for k, (_, line) in enumerate(lines):
        c = md_cells(line) if line.lstrip().startswith("|") else []
        if (
            len(c) >= 3
            and c[0] == "勧告ID"
            and c[1] == "CVE"
            and c[2].startswith("EPSS")
        ):
            rows = []
            for n, l2 in lines[k + 1 :]:
                if not l2.lstrip().startswith("|"):
                    break
                c2 = md_cells(l2)
                if not all(re.fullmatch(r":?-+:?", x) for x in c2):
                    rows.append((n, c2))
            return rows
    return None


def exploit_rows(lines):
    """5節の「悪用状況（EPSS/KEV）」行 [(指摘番号, 行番号, 内容, 同じ指摘の他の行の本文)]"""
    found = [("5節", [])]
    for n, line in lines:
        m = re.match(r"###\s+(5\.\d+)", line)
        if m:
            found.append((m.group(1), []))
        else:
            c = md_cells(line) if line.lstrip().startswith("|") else []
            found[-1][1].append(
                (n, line, c[1] if len(c) >= 2 and c[0] == ROW_LABEL else None)
            )
    out = []
    for f, ls in found:
        other = "\n".join(line for _, line, r in ls if r is None)
        out += [(f, n, r, other) for n, _, r in ls if r is not None]
    return out


def num_near(cell: str, v) -> bool:
    """cell が v を書いた桁で丸めた値か（許容は書いた桁の半単位。小数第 ROUND_PLACES 位より粗ければその位の半単位）"""
    if NUM_RE.fullmatch(cell) is None:
        return False
    d = decimal.Decimal(cell)
    exponent = d.as_tuple().exponent
    if not isinstance(exponent, int):  # NaN・無限大（NUM_RE により起きない）
        return False
    places = max(-exponent, ROUND_PLACES)
    return abs(d - decimal.Decimal(repr(float(v)))) <= decimal.Decimal(5).scaleb(
        -places - 1
    )


def value_cell(cell: str, st: str, v):
    """EPSS・パーセンタイルのセルの問題（無ければ None）"""
    if st == "ok":
        if num_near(cell, v):
            return None
        return (
            f"JSONに値（{v}）があるのに「{cell}」"
            if cell.startswith("未取得")
            else f"「{cell}」がJSONの値 {v} と一致しない"
        )
    if st == "not_found":
        return (
            None
            if cell == "該当なし"
            else f"「{cell}」は「該当なし」であるべき（not_found）"
        )
    return (
        None
        if ungot(cell)
        else f"「{cell}」は「未取得（理由）」であるべき（epss_status=error）"
    )


def kev_cell(cell: str, i: dict):
    k = i["kev"]
    if k is None:
        return (
            None
            if ungot(cell)
            else f"「{cell}」は「未取得（理由）」であるべき（KEV未取得）"
        )
    want = (
        (
            "掲載（"
            + (f"{i['kev_date_added']}登録" if i["kev_date_added"] else "登録日不明")
            + "）"
        )
        if k
        else "非掲載"
    )
    return None if cell == want else f"「{cell}」がJSONと一致しない（{want}）"


def null_value(cell: str, failed: bool):
    """JSONでnullの取得日時の項目（「なし（理由）」か「未取得（理由）」。failed なら「未取得」に限る）"""
    if ungot(cell) or (not failed and paren(cell, "なし")):
        return None
    return f"「{cell}」は「{'未取得' if failed else 'なし／未取得'}（理由）」であるべき（JSONではnull）"


def check_report_text(text: str, doc) -> tuple[list[str], list[str]]:
    """報告書の8節・5節と doc（None はJSONが無い場合）の照合。(NGの列, WARNの列)"""
    sec = report_sections(text)
    ng: list[str] = []
    warn: list[str] = []
    if "8" not in sec:
        return ["8節（SCA）の見出し「## 8.」が無い"], []
    s8 = sec["8"]
    status = [
        (n, line[len(STATUS_HEAD) :].strip())
        for n, line in s8
        if line.startswith(STATUS_HEAD)
    ]
    table = epss_table(s8)
    dates = [(n, line) for n, line in s8 if re.match(r"取得日時\s*[:：]", line)]
    rows5 = exploit_rows(sec.get("5", []))
    if len(status) != 1:
        ng.append(
            f"8節に「{STATUS_HEAD}」の行が{len(status)}個（1個であるべき{VARIANT_HINT}）"
        )
    if doc is None:  # JSONが無い: 状況の1行だけで、数値を書かない
        got = status[0][1] if status else ""
        if status and not (
            reason_ok(got, "未取得")
            or got in ("スキャン出力に脆弱性IDなし", "対象のCVEなし")
            or paren(got, "対象のCVEなし")
        ):
            ng.append(
                f"L{status[0][0]}: JSONが無いのに状況が「{got}」（未取得（理由: …）等であるべき）"
            )
        if table is not None:
            ng.append("JSONが無いのに8節にEPSS・KEVの表がある")
        ng += [f"L{n}: JSONが無いのに取得日時の行がある" for n, _ in dates]
        ng += [
            f"L{n}（{f}）: JSONが無いのに悪用状況の行に数値がある"
            for f, n, c, _ in rows5
            if re.search(r"最大EPSS\s*\d|KEV掲載\s*\d", c)
        ]
        return ng, warn
    ents = doc["entries"]
    by_id = {e["id"]: e for e in ents}
    items = [i for e in ents for i in e["items"]]
    excluded = set(doc["sources"]["id_limit"]["excluded_ids"])
    osv_fail = not items and any(e["status"] == "error" for e in ents)
    # 状況行: 種類（最初の「（」より前）が --status-line と同じ。取得済み・対象のCVEなしは全体が同じ。
    # 一部未取得・未取得は理由が空でない
    want = status_line(doc)[len("EPSS/KEV: ") :]
    if len(status) == 1:
        got = status[0][1]
        kind = want.split("（")[0]
        if got.split("（")[0] != kind or (
            kind in ("取得済み", "対象のCVEなし") and got != want
        ):
            ng.append(f"L{status[0][0]}: 状況「{got}」がJSONと一致しない（{want}）")
        elif kind in ("一部未取得", "未取得") and not reason_ok(got, kind):
            ng.append(
                f"L{status[0][0]}: 状況「{got}」の理由が無い（{kind}（理由: …）であるべき）"
            )
    # 取得日時・KEVカタログ版・EPSSの基準日（行は1つ。複数あれば全て確かめる）・出典表記
    if not dates:
        ng.append(
            "8節に取得日時の行（取得日時: …、KEVカタログ版: …、EPSSの基準日: …。）が無い"
        )
    elif len(dates) > 1:
        ng.append(
            f"8節に取得日時の行が{len(dates)}個（1個であるべき。L{', L'.join(str(n) for n, _ in dates)}）"
        )
    kev_src, score = doc["sources"]["kev"], doc["sources"]["epss"]["score_date"]
    for n, line in dates:
        parts = split_labels(line, DATE_LABELS)
        end = cut_outside(parts[2]) if parts else -1
        if end < 0:
            ng.append(
                f"L{n}: 取得日時の行の形が違う（取得日時: …、KEVカタログ版: …、EPSSの基準日: …。）{VARIANT_HINT}"
            )
            continue
        if doc["retrieved_at"] not in parts[0]:
            ng.append(
                f"L{n}: 取得日時「{parts[0]}」がJSON（{doc['retrieved_at']}）と一致しない"
            )
        for name, cell, v, failed in (
            (
                "KEVカタログ版",
                parts[1],
                kev_src["catalog_version"],
                bool(kev_src["error"]) or osv_fail,
            ),
            (
                "EPSSの基準日",
                parts[2][:end].strip(),
                score,
                any(i["epss_status"] == "error" for i in items) or osv_fail,
            ),
        ):
            p = (
                (None if cell == v else f"「{cell}」がJSON（{v}）と一致しない")
                if v
                else null_value(cell, failed)
            )
            if p:
                ng.append(f"L{n}: {name}: {p}")
    if "EPSS data from FIRST" not in "\n".join(line for _, line in s8):
        ng.append("8節に出典表記「EPSS data from FIRST」が無い")
    # 8節の表: 勧告ID×CVEごとに1行（no_cve・error は勧告ごとに1行）
    exp = {}
    for e in ents:
        if e["status"] == "ok":
            exp.update({(e["id"], i["cve"]): (e, i) for i in e["items"]})
        else:
            exp[(e["id"], "CVEなし" if e["status"] == "no_cve" else "不明")] = (e, None)
    seen = set()
    for n, c in table or []:
        if len(c) != 6:
            ng.append(f"L{n}: 8節の表の列が{len(c)}個（6個であるべき）")
            continue
        vids, cv = extract_ids(c[0]), c[1]
        cves = [x for x in extract_ids(cv) if CVE_RE.fullmatch(x)]
        if not vids:
            ng.append(f"L{n}: 勧告ID列「{c[0]}」にIDが無い")
            continue
        vid = vids[0]
        if cv == "CVEなし（対象外）":
            key = "CVEなし"
        elif paren(cv, "不明"):
            key = "不明"
        elif len(cves) == 1:
            key = cves[0]
        else:
            ng.append(
                f"L{n}: {vid} のCVE列「{cv}」を読めない（CVE・CVEなし（対象外）・不明（理由））{VARIANT_HINT}"
            )
            continue
        if (vid, key) in seen:
            ng.append(f"L{n}: {vid} / {cv} の行が重複")
            continue
        seen.add((vid, key))
        if (vid, key) not in exp:
            if vid in excluded:  # 件数上限で除外したID: 値を書かない
                if any(NUM_RE.fullmatch(x) for x in c[2:4]) or c[4].startswith(
                    ("掲載", "非掲載")
                ):
                    ng.append(f"L{n}: {vid} は件数上限で除外（値が無い）のに値がある")
                continue
            e = by_id.get(vid)
            j = (
                "JSONに無いID"
                if e is None
                else f"JSON: status={e['status']}、CVE={','.join(e['cves']) or 'なし'}"
            )
            ng.append(f"L{n}: {vid} / {cv} の行がJSONと合わない（{j}）")
            continue
        e, i = exp[(vid, key)]
        if i is None:  # no_cve は「―」、error は「未取得（理由）」
            nocve = e["status"] == "no_cve"
            for col, name in ((2, "EPSS"), (3, "パーセンタイル"), (4, "KEV")):
                if not (c[col] in DASHES if nocve else ungot(c[col])):
                    want_c = "―" if nocve else "未取得（理由）"
                    ng.append(
                        f"L{n}: {vid} の{name}「{c[col]}」は「{want_c}」"
                        f"であるべき（status={e['status']}）"
                    )
            want_urls = {advisory_url(vid)}
        else:
            for col, name, key2 in (
                (2, "EPSS", "epss"),
                (3, "パーセンタイル", "percentile"),
            ):
                p = value_cell(c[col], i["epss_status"], i[key2])
                if p:
                    ng.append(f"L{n}: {vid} / {key} の{name}: {p}")
            p = kev_cell(c[4], i)
            if p:
                ng.append(f"L{n}: {vid} / {key} のKEV: {p}")
            want_urls = set(i["urls"].values())
        got_urls = set(URL_RE.findall(c[5]))
        if got_urls != want_urls:
            miss = sorted(want_urls - got_urls, key=str)
            extra = sorted(got_urls - want_urls, key=str)
            ng.append(
                f"L{n}: {vid} / {cv} の根拠URLがJSONと一致しない（欠落: {miss or 'なし'}、余分: "
                f"{extra or 'なし'}）"
            )
    missing = [k for k in exp if k not in seen]
    if missing and table is None:
        ng.append(f"8節にEPSS・KEVの表が無い（JSONの{len(missing)}行分）")
    else:
        ng += [f"JSONの {v}（{k}）が8節の表に無い" for v, k in missing]
    # 5節の悪用状況の行: 対象の勧告のJSONから最大EPSSとKEV掲載件数を計算して照合
    json_ids = set(by_id) | {i["cve"] for i in items}
    for f, n, c, other in rows5:
        where = f"L{n}（{f}）"
        parts = split_labels(c, ROW5_LABELS)
        if not parts:
            ng.append(
                f"{where}: 悪用状況の行の形が違う（対象: …。最大EPSS …、KEV掲載 …。詳細は8節）{VARIANT_HINT}"
            )
            continue
        tg, es, unknown = extract_ids(parts[0]), [], False
        for t in tg:  # 勧告ID（JSONのentries[].id）か、いずれかの勧告のCVE
            hit = [by_id[t]] if t in by_id else [e for e in ents if t in e["cves"]]
            if hit:
                es += [e for e in hit if e not in es]
            elif t in excluded:
                unknown = True
            else:
                ng.append(f"{where}: 対象の {t} がJSONに無い")
        if not tg:
            ng.append(f"{where}: 対象の勧告IDが無い")
            continue
        covered = set(tg) | {e["id"] for e in es} | {x for e in es for x in e["cves"]}
        lack = [x for x in extract_ids(other) if x in json_ids and x not in covered]
        if lack:
            warn.append(
                f"{where}: 同じ指摘に現れるJSONのID（{', '.join(lack)}）が対象に無い（勧告IDの列挙漏れ）"
            )
        its = [i for e in es for i in e["items"]]
        unknown = unknown or any(e["status"] == "error" for e in es)
        if es and not its and not unknown:
            ng.append(f"{where}: CVEの無い指摘（{'、'.join(tg)}）に悪用状況の行がある")
            continue
        ep, kv = parts[1], parts[2]
        if (
            cut_outside(kv) >= 0
        ):  # KEVは「KEV掲載 N件（…）」の部分だけ（括弧の外の最初の「。」まで）
            kv = kv[: cut_outside(kv)].strip()
        ok = [i for i in its if i["epss_status"] == "ok"]
        if ok:
            mx = max(i["epss"] for i in ok)
            tops = {i["cve"] for i in ok if i["epss"] == mx}
            num = ep.split("（")[0].strip()
            listed = {x for x in extract_ids(ep[len(num) :]) if CVE_RE.fullmatch(x)}
            if not num_near(num, mx):
                ng.append(
                    f"{where}: 最大EPSS「{ep}」がJSONから計算した値 {mx}（{','.join(sorted(tops))}）"
                    f"と一致しない"
                )
            elif (
                not paren(ep[len(num) :].strip(), "")
                or not listed
                or not listed <= tops
            ):
                ng.append(
                    f"{where}: 最大EPSSのCVE「{ep[len(num) :].strip()}」"
                    f"が最大のCVE（{','.join(sorted(tops))}）でない"
                )
        elif its and not unknown and all(i["epss_status"] == "not_found" for i in its):
            if ep != "該当なし":
                ng.append(
                    f"{where}: 最大EPSS「{ep}」は「該当なし」であるべき（全CVEがnot_found）"
                )
        elif not ungot(ep):
            ng.append(
                f"{where}: 最大EPSS「{ep}」は「未取得（理由）」であるべき（値が無い）"
            )
        known = [i for i in its if i["kev"] is not None]
        if known:
            kset = {i["cve"] for i in known if i["kev"]}
            cnt = kv.split("件")[0] if "件" in kv else None
            rest = kv[len(cnt) + 1 :].strip() if cnt is not None else None
            listed = {x for x in extract_ids(rest or "") if CVE_RE.fullmatch(x)}
            if (
                cnt is not None
                and cnt != cnt.strip()
                and cnt.strip().isascii()
                and cnt.strip().isdigit()
            ):
                ng.append(
                    f"{where}: KEV掲載「{kv}」の形が違う（数字と「件」の間に空白を入れず「{cnt.strip()}件」と書く）"
                )
            elif cnt is None or not (cnt.isascii() and cnt.isdigit()):
                ng.append(
                    f"{where}: KEV掲載「{kv}」の形が違う（JSONから計算すると「{len(kset)}件」）"
                    f"{VARIANT_HINT}"
                )
            elif int(cnt) != len(kset):
                ng.append(
                    f"{where}: KEV掲載「{kv}」がJSONから計算した件数 {len(kset)}件 と一致しない"
                )
            elif (
                (rest and not paren(rest, "")) or listed != kset or (not kset and rest)
            ):
                ng.append(
                    f"{where}: KEV掲載の括弧内「{rest}」"
                    f"が掲載CVE（{','.join(sorted(kset)) or 'なし'}。全件を挙げ、0件なら括弧を省く）と合わない"
                )
        elif not ungot(kv):
            ng.append(
                f"{where}: KEV掲載「{kv}」は「未取得（理由）」であるべき（KEVの値が無い）"
            )
    # 8節（他の箇所を含む）と悪用状況の行に現れるIDのうち、JSONに無いもの
    known_ids = json_ids | excluded
    text8 = (
        "\n".join(line for _, line in s8) + "\n" + "\n".join(c for _, _, c, _ in rows5)
    )
    extra = [x for x in extract_ids(text8) if x not in known_ids]
    if extra:
        warn.append(
            f"報告書のSCA由来のIDがJSONに無い（{len(extra)}件: "
            f"{', '.join(extra[:10])}{' 等' if len(extra) > 10 else ''}）"
        )
    return ng, warn


def check_report(report: str, json_path: str | None) -> int:
    """--check-report の本体。終了コード 0=OK（WARNのみを含む） 1=NG 2=入力エラー"""
    try:
        with open(report, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"報告書を読めない: {e}", file=sys.stderr)
        return 2
    doc = None
    if (
        json_path is not None
    ):  # 読込と形の検査だけを囲む（照合本体の想定外の例外は隠さない）
        try:
            with open(json_path, encoding="utf-8") as f:
                doc = json.load(f)
            bad = validate(doc)
        except (OSError, ValueError) as e:
            print(f"JSONを読めない: {e}", file=sys.stderr)
            return 2
        except (RecursionError, AttributeError, KeyError, TypeError) as e:
            print(f"JSONの形が不正（{type(e).__name__}）", file=sys.stderr)
            return 2
        if bad:
            print(f"JSONの形が不正（validate）: {'; '.join(bad[:5])}", file=sys.stderr)
            return 2
    ng, warn = check_report_text(text, doc)
    for x in ng:
        print("NG:", clean(x))
    for x in warn:
        print("WARN:", clean(x))
    print(
        f"RESULT: {f'NG（{len(ng)}件）' if ng else 'OK'}"
        f"{'' if doc is not None else '（JSONなしとして検査）'}"
    )
    return 1 if ng else 0


def writable(path: str) -> bool:
    if os.path.isdir(path):
        return False
    if os.path.exists(path):
        return os.access(path, os.W_OK)
    d = os.path.dirname(os.path.abspath(path))
    return os.path.isdir(d) and os.access(d, os.W_OK)


def main(a, get=None) -> int:
    """get を渡すと通信を差し替える（自己テスト用）"""
    text = ""
    if a.from_text:
        try:
            with open(a.from_text, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            print(f"入力ファイルを読めない: {e}", file=sys.stderr)
            return 2
    ids, bad = collect_ids(text, a.id)
    if bad:
        print(f"IDの形式が不正: {clean(', '.join(bad))}", file=sys.stderr)
        return 2
    for path, name in ((a.out, "--out"), (a.kev_cache, "--kev-cache")):
        if path and not writable(path):
            print(f"{name} の書き込み先に書けない: {path}", file=sys.stderr)
            return 2
    tls = Tls()
    if get is None:
        mx = getattr(a, "max_seconds", MAX_SECONDS)
        get = with_retry(Guard(lambda u, t: http_get(u, t, tls), a.timeout, mx))
    doc = build(ids, get, a.kev_cache, tls=tls, max_ids=getattr(a, "max_ids", MAX_IDS))
    warns = validate(doc)
    try:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2, allow_nan=False)
            f.write("\n")
    except (OSError, ValueError) as e:
        print(f"出力ファイルに書けない: {e}", file=sys.stderr)
        return 2
    print(summary(doc, a.out, warns))
    if getattr(a, "status_line", False):
        print(status_line(doc))
    return 0


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--from-text", metavar="FILE", help="SCAの生出力テキスト（IDを抽出する）"
    )
    ap.add_argument(
        "--id", action="append", default=[], metavar="ID", help="脆弱性ID（繰り返し可）"
    )
    ap.add_argument("--out", metavar="FILE", help="出力JSON")
    ap.add_argument(
        "--kev-cache",
        metavar="PATH",
        help="KEVカタログの保存先（省略時は一時ファイル）",
    )
    ap.add_argument(
        "--timeout", type=float, help="1リクエストのタイムアウト秒（既定20）"
    )
    ap.add_argument("--max-seconds", type=float, help="通信全体の時間上限秒（既定120）")
    ap.add_argument("--max-ids", type=int, help="処理するIDの件数上限（既定200）")
    ap.add_argument(
        "--status-line",
        action="store_true",
        help="要約の後に取得状況の1行を出す（run_sca_scan.sh 用）",
    )
    ap.add_argument(
        "--check-report",
        metavar="REPORT",
        help="報告書（Markdown）の8節・5節のEPSS・KEVをJSONと照合する",
    )
    ap.add_argument(
        "--json",
        metavar="FILE",
        help="--check-report で照合する出力JSON（省くとJSONが無い場合の検査）",
    )
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if not a.self_test and (a.check_report is not None or a.json is not None):
        if a.check_report is None:
            ap.error("--json は --check-report と使う")
        fetch_opts = (
            a.out,
            a.from_text,
            a.id or None,
            a.kev_cache,
            a.timeout,
            a.max_seconds,
            a.max_ids,
        )
        if a.status_line or any(x is not None for x in fetch_opts):
            ap.error(
                "--check-report は取得用の引数（--out・--from-text・--id・--kev-cache・--timeout・--"
                "max-seconds・"
                "--max-ids・--status-line）と使わない"
            )
        return a
    # 既定値はここで入れる（--check-report と取得用の引数の併用を見分けるため、argparse の既定は None）
    a.timeout = 20.0 if a.timeout is None else a.timeout
    a.max_seconds = MAX_SECONDS if a.max_seconds is None else a.max_seconds
    a.max_ids = MAX_IDS if a.max_ids is None else a.max_ids
    if a.self_test:
        return a
    if not a.out or (a.from_text is None and not a.id):
        ap.error("--out と、--from-text または --id が必要")
    if not (math.isfinite(a.timeout) and a.timeout > 0):
        ap.error("--timeout は正の有限の数")
    if not (math.isfinite(a.max_seconds) and a.max_seconds > 0):
        ap.error("--max-seconds は正の有限の数")
    if a.max_ids < 1:
        ap.error("--max-ids は1以上")
    if a.kev_cache == "":
        ap.error("--kev-cache が空")
    return a


def self_test() -> int:
    """自己検査の本体は scripts/selftests/st_fetch_epss_kev.py（本体の読込を減らすため分けた）。"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "selftests"))
    import st_fetch_epss_kev

    return st_fetch_epss_kev._st_entry(globals())


if __name__ == "__main__":
    a = parse_args()
    if a.self_test:
        sys.exit(self_test())
    sys.exit(
        check_report(a.check_report, a.json) if a.check_report is not None else main(a)
    )
