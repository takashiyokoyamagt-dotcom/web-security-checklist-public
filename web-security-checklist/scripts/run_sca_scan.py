#!/usr/bin/env python3
"""検出したスタックに応じて依存関係の脆弱性スキャン(SCA)を実行する（標準ライブラリのみ）。
使い方: run_sca_scan.py [対象ディレクトリ]
run_sca_scan.sh（bash版）と同じ出力・終了コード。.sh は本ファイルを呼ぶ薄いラッパー。
ツールが存在しない/実行できない場合はエラーを握りつぶさず、その旨を出力する。
最後に「== EPSS/KEV ==」の節で、スキャンの標準出力の脆弱性IDから fetch_epss_kev.py でEPSS・KEVを取得する
（取得できなくてもスキャンの終了コードは変えない）。環境変数: SCA_EPSS_KEV=0 で省略、
SCA_EPSS_KEV_OUT=結果JSONの保存先（省略時は一時ディレクトリ。対象ディレクトリの中には書かない）。
取得のため、ツールの標準出力はパイプ経由で受けて表示しつつ一時ファイルにも残す。標準出力が端末でなくなるので、
ツールの色付けや表の幅が端末で直接実行したときと変わり得る。標準出力と標準エラーの行の前後も変わり得る。
外部コマンドは shell=False のリスト引数で起動し、実行ファイルは PATH から絶対パスで探す（chdir の前。対象の中・相対・"." の項目は除く）
（Windowsでは npm.cmd 等。起動は絶対パスのみ）。対象パスをシェル文字列に連結しない（作業ディレクトリは cwd= で渡す）。
fetch_epss_kev.py はこのスクリプトと同じディレクトリから探し、sys.executable -I で起動する。
終了コード 0=少なくとも1つSCAを実行 / 1=対象に移動できない・実行可能なSCAツールなし。Python 3.9以上。"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile

MSG_AUDIT_FAIL = "npm audit が非ゼロ終了しました(脆弱性検出 or 実行エラー)。上記出力を確認してください。"


class _Out:
    """標準出力。ツールの出力（バイト列）を表示しつつ、必要なら一時ファイルにも残す"""

    def __init__(self):
        self.capture = None  # 開いた一時ファイル（バイナリ）。None ならキャプチャしない

    def line(self, text):
        # 見出しや注意の行もツール出力と同じ経路（bash版では FIFO 経由）。キャプチャにも入る
        if self.capture is None:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
        else:
            self.raw((text + "\n").encode("utf-8"))

    def raw(self, data):
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        if self.capture is not None:
            self.capture.write(data)
            self.capture.flush()


def _run(out, argv, cwd=None):
    """argv を shell=False で実行し、標準出力を out へ流す。戻り値は終了コード（起動できなければ 127）"""
    try:
        if out.capture is None:
            sys.stdout.flush()
            return subprocess.run(argv, cwd=cwd).returncode
        p = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE)
        while True:
            chunk = p.stdout.read1(65536)
            if not chunk:
                break
            out.raw(chunk)
        p.stdout.close()
        return p.wait()
    except OSError:
        return 127


def _under(path, base):
    """path が base の中（base 自身を含む）か"""
    a = os.path.normcase(os.path.realpath(path)).rstrip("\\/") + os.sep
    b = os.path.normcase(os.path.realpath(base)).rstrip("\\/") + os.sep
    return a.startswith(b)


def _resolve_tools(target_abs):
    """ツールの絶対パスを、chdir の前に、整理した PATH から決める。
    Windows は検索で作業ディレクトリが先頭になるため、対象に置かれた pip-audit.CMD 等を実行しないよう、
    PATH から空・"."・相対・対象の中の項目を除き、結果が対象の中なら捨てる。以降は絶対パスだけで起動する"""
    entries = []
    for e in os.environ.get("PATH", "").split(os.pathsep):
        if e and e != "." and os.path.isabs(e) and not _under(e, target_abs):
            entries.append(e)
    if os.name == "nt":
        allowed = {".com", ".exe", ".bat", ".cmd"}
        exts = [x for x in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if x.lower() in allowed]
    else:
        exts = [""]
    tools = {}
    for name in ("npm", "pip-audit", "mvn", "osv-scanner"):
        tools[name] = None
        for d in entries:
            for x in exts:
                p = os.path.join(d, name + x)
                if os.path.isfile(p) and (os.name == "nt" or os.access(p, os.X_OK)) and not _under(p, target_abs):
                    tools[name] = os.path.abspath(p)
                    break
            if tools[name]:
                break
    return tools


def _scan_npm(out, state):
    out.line("== npm audit ==")
    npm = state["tools"]["npm"]
    if not npm:
        out.line("npm が見つかりません。手動でインストールして実行してください。")
        return
    audit = [npm, "audit", "--audit-level=high"]
    if os.path.isfile("package-lock.json") or os.path.isfile("npm-shrinkwrap.json"):
        if _run(out, audit) != 0:
            out.line(MSG_AUDIT_FAIL)
        state["ran_any"] = True
        return
    # lockfileが無いとnpm auditはENOLOCKで失敗する。対象は変更せず、一時ディレクトリにpackage.jsonだけを複製してlockfileを生成し、そこで監査する。
    out.line(
        "注意: lockfileが無いため、package.jsonから一時ディレクトリでlockfileを生成して監査します(対象は変更しません)。"
        "範囲指定(^/~)は最新の該当版に解決されるため、実際に導入される版と異なる可能性があります。"
        "報告書には「lockfile無し・一時生成lockfileで監査」と明記してください。"
    )
    try:
        state["sca_tmp"] = tmp = tempfile.mkdtemp()
    except OSError:
        tmp = ""
    if not tmp or not os.path.isdir(tmp):
        out.line("一時ディレクトリを作成できません。npm auditは未実施として報告してください。")
        return
    # cp と同じく、失敗は標準エラーに出す（その後の処理は続ける）
    for name in ("package.json", ".npmrc"):
        if name == ".npmrc" and not os.path.isfile(name):
            continue
        try:
            shutil.copy(name, tmp)
        except OSError as e:
            print(f"cp: cannot copy '{name}': {e.strerror or e}", file=sys.stderr)
    err_log = os.path.join(tmp, "err.log")
    with open(err_log, "wb") as ef:
        cmd = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        try:
            rc = subprocess.run(cmd, cwd=tmp, stdout=subprocess.DEVNULL, stderr=ef).returncode
        except OSError:
            rc = 127
    if rc == 0:
        if _run(out, audit, cwd=tmp) != 0:
            out.line(MSG_AUDIT_FAIL)
        state["ran_any"] = True
    else:
        out.line("lockfileの一時生成に失敗しました(ネットワーク不可等)。npm auditは未実施として報告してください。")
        with open(err_log, "rb") as f:  # head -5
            head = b"".join(f.read().splitlines(keepends=True)[:5])
        if head and not head.endswith(b"\n"):
            head += b"\n"
        out.raw(head)


def _scan(out, state):
    isf = os.path.isfile
    if isf("package.json"):
        _scan_npm(out, state)

    if isf("requirements.txt") or isf("pyproject.toml"):
        out.line("== pip-audit ==")
        exe = state["tools"]["pip-audit"]
        if exe:
            if _run(out, [exe]) != 0:
                out.line("pip-audit が非ゼロ終了しました(脆弱性検出 or 実行エラー)。上記出力を確認してください。")
            state["ran_any"] = True
        else:
            out.line("pip-audit が見つかりません。'pip install pip-audit' でインストールしてから実行してください。")

    if isf("pom.xml") or isf("build.gradle") or isf("build.gradle.kts"):
        out.line("== OWASP Dependency-Check (Maven) ==")
        exe = state["tools"]["mvn"]
        if exe:
            if _run(out, [exe, "-q", "org.owasp:dependency-check-maven:check"]) != 0:
                out.line("dependency-check が非ゼロ終了しました。上記出力を確認してください。")
            state["ran_any"] = True
        else:
            out.line("mvn が見つかりません。手動でOWASP Dependency-Checkを実行してください。")

    exe = state["tools"]["osv-scanner"]
    if exe:
        out.line("== osv-scanner (汎用) ==")
        if _run(out, [exe, "-r", "."]) != 0:
            out.line("osv-scanner が非ゼロ終了しました。上記出力を確認してください。")
        state["ran_any"] = True


def _epss(out, state, script_dir, epss_kev, epss_out, epss_skip, epss_work):
    out.line("== EPSS/KEV ==")
    fetch = os.path.join(script_dir, "fetch_epss_kev.py")
    if epss_kev == "0":
        epss_skip = "SCA_EPSS_KEV=0 で省略"
    elif epss_skip:
        pass
    elif not state["ran_any"]:
        epss_skip = "SCA未実施"
    elif not os.path.isfile(fetch):
        epss_skip = "fetch_epss_kev.py が見つからない"
    elif epss_out:
        out_dir = os.path.dirname(epss_out.rstrip("/\\") or epss_out)  # dirname(1) と同じく末尾の区切りは無視
        if os.path.isdir(out_dir) and _under(out_dir, os.getcwd()):
            epss_skip = "SCA_EPSS_KEV_OUT が対象ディレクトリの中"
    if not epss_skip:
        epss_json = epss_out or os.path.join(epss_work, "epss-kev.json")
        # -I: 対象ディレクトリ（カレント）のモジュールや PYTHON* 環境変数を読まない。-X utf8 は出力をUTF-8に揃える
        cmd = [sys.executable, "-I", "-X", "utf8", fetch, "--from-text", os.path.join(epss_work, "sca-output.txt"),
               "--out", epss_json, "--timeout", "10", "--max-seconds", "45", "--status-line"]
        sys.stdout.flush()
        try:
            rc = subprocess.run(cmd).returncode
        except OSError:
            rc = 127
        if rc == 0:
            out.line(f"JSON: {epss_json}（報告書と同じ保存先へ複製する）")
        else:
            epss_skip = f"fetch_epss_kev.py が失敗（終了コード{rc}）"
    if epss_skip:
        out.line(f"EPSS/KEV: 未取得（理由: {epss_skip}）")


def main(argv):
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", newline="\n")
        except (AttributeError, ValueError):
            pass
    # cd の前に、スクリプトの場所と出力先（相対なら呼び出し時のカレントディレクトリ基準）を絶対パスにする
    script_dir = os.path.dirname(os.path.abspath(__file__))
    epss_kev = os.environ.get("SCA_EPSS_KEV") or "1"
    epss_out = os.environ.get("SCA_EPSS_KEV_OUT") or ""
    if epss_out and not os.path.isabs(epss_out):
        epss_out = os.path.join(os.getcwd(), epss_out)

    target = argv[0] if argv and argv[0] else "."
    tools = None
    try:
        if target.startswith("-"):  # bash の cd "-x" はオプション扱いで失敗する
            raise OSError("option-like target")
        target_abs = os.path.abspath(target)
        if not os.path.isdir(target_abs):
            raise OSError("not a directory")
        tools = _resolve_tools(target_abs)  # chdir の前に決める
        os.chdir(target)
    except OSError:
        print(f"対象ディレクトリに移動できません: {target} (存在とアクセス権を確認してください)", file=sys.stderr)
        return 1

    out = _Out()
    state = {"ran_any": False, "sca_tmp": "", "tools": tools}
    epss_work = ""
    epss_skip = ""
    # SIGTERM でも片付け（finally）を通す
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    except (ValueError, OSError):
        pass
    try:
        if epss_kev != "0":
            if _under(tempfile.gettempdir(), os.getcwd()):
                epss_skip = "作業用一時ディレクトリが対象の中"
            else:
                try:
                    epss_work = tempfile.mkdtemp(prefix="sca-epss-kev.")
                    out.capture = open(os.path.join(epss_work, "sca-output.txt"), "wb")
                except OSError:
                    epss_skip = "一時ファイルを作成できない"
        _scan(out, state)
        if out.capture is not None:
            out.capture.close()
            out.capture = None
        _epss(out, state, script_dir, epss_kev, epss_out, epss_skip, epss_work)
        if not state["ran_any"]:
            print("実行可能なSCAツールが見つかりませんでした。SCAスキャンは未実施として報告してください。", file=sys.stderr)
            return 1
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        if out.capture is not None:
            out.capture.close()
        if state["sca_tmp"]:
            shutil.rmtree(state["sca_tmp"], ignore_errors=True)
        if epss_work:
            try:
                os.remove(os.path.join(epss_work, "sca-output.txt"))
            except OSError:
                pass
            try:
                os.rmdir(epss_work)  # 結果JSONを置いたときは残る
            except OSError:
                pass
        sys.stdout.flush()
        sys.stderr.flush()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
