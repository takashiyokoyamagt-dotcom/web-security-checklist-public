"""check_refs.py の自己検査（--self-test）の本体。本体から分けた（読込を減らすため。P6）。
単独では実行しない。`python3 scripts/check_refs.py --self-test` が呼ぶ。
本体のモジュールの名前（関数・定数）をこのモジュールの名前空間に写してから、元のコードをそのまま実行する。"""
from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import stat
import sys
import tempfile

_MAIN_FILE = None  # 本体のファイルのパス（_st_entry が入れる）
_MAIN_GLOBALS = None  # 本体の globals()。本体の定数を一時的に変える検査はここを書き換える


FILES = {
    "app/routes/session.js": "\n".join(
        [
            "const UserDAO = require('../data/user-dao');",  # 1
            "function SessionHandler(db) {",  # 2
            "  const userDAO = new UserDAO(db);",  # 3
            "  this.handleSignup = (req, res) => {",  # 4
            "    const userName = req.body.userName;",  # 5
            "    userDAO.getUserByUserName(userName, (err, user) => {",  # 6
            "      if (user) { return res.render('signup'); }",  # 7
            "      userDAO.addUser(userName, (e, u) => res.redirect('/'));",  # 8
            "    });",  # 9
            "  };",  # 10
            "}",  # 11
        ]
    )
    + "\n",
    "app/data/user-dao.js": "\n".join(
        ["function UserDAO(db) {", "  this.addUser = (userName, cb) => {"]
        + ["    // pad"] * 40
        + [
            "  };",  # 43
            "  this.getUserByUserName = (userName, cb) => {",  # 44
            "    usersCol.findOne({ userName: userName }, cb);",  # 45
            "  };",  # 46
            "}",  # 47
        ]
    )
    + "\n",
    "app/index.js": "const a = 1;\nconst b = 2;\n",
    "lib/index.js": "line1\nline2\nline3\n",
    "Gruntfile.js": "\n".join(["// x"] * 9 + ['grunt.loadNpmTasks("grunt-retire");'])
    + "\n",
    "Dockerfile": "FROM node:12\nCOPY . .\nRUN npm install\n",
    "config/env/all.js": (
        "module.exports = {\n  cookieSecret: 'x',\n  cryptoKey: 'y'\n};\n"
    ),
    "node_modules/jsonwebtoken/verify.js": "module.exports = function verify() {};\n",
    "docs/README.md": "# x\n\nMONGO_URL を設定する\n",
}


def _report(*paras: str) -> str:
    body = "\n\n".join(paras)
    return f"# 報告書\n\n## 5. 指摘詳細\n\n### 5.1 [High] テスト\n\n{body}\n\n## 6. リスク分析\n"


def self_test() -> int:
    fails: list[str] = []

    def ok(label, cond):
        if not cond:
            fails.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        for rel, s in FILES.items():
            p = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(s)
        repo = Repo(tmp)

        def go(*paras, **k):
            return check(_report(*paras), repo, **k)

        # 1. 正常系: 識別子が参照行の近傍にある（バッククォート・本文のキャメルケース）
        r = go("`getUserByUserName` が検索する（app/data/user-dao.js:44-46）。")
        ok("正常(バッククォート)", not r["ng"] and not r["warn"] and r["chk"] == 1)
        r = go("サインアップは userDAO.getUserByUserName（session.js:6）で調べる。")
        ok(
            "正常(短いパス・ドット連結)",
            not r["ng"] and not r["warn"] and r["res"] == 1,
        )
        # 2. (c) 行番号のずれ: 別の関数の位置（±30行の外）と、近いずれ（±30行以内）
        r = go("まず userDAO.getUserByUserName（app/data/user-dao.js:2-3）で調べる。")
        w = r["warn"][0] if r["warn"] else ""
        ok(
            "ずれ(別関数)",
            len(r["warn"]) == 1 and "±30行以内に無い" in w and "L44" in w,
        )
        r = go("`findOne` で探す（app/data/user-dao.js:38）。")
        ok("ずれ(近い)", len(r["warn"]) == 1 and "L45（+7行）" in r["warn"][0])
        # 3. 前後3行以内は WARN にしない（範囲外なら近接として数える）
        r = go("`findOne` で探す（app/data/user-dao.js:42）。")
        ok("近接はWARNでない", not r["warn"] and len(r["near"]) == 1)
        r = go("`findOne` で探す（app/data/user-dao.js:41）。")
        ok("前後3行の外はWARN", len(r["warn"]) == 1)
        r = go("`findOne` で探す（app/data/user-dao.js:41）。", window=4)
        ok("--windowで広げる", not r["warn"])
        # 4. (a) 実在しないファイル・(b) 行数の超過・範囲の逆転・0行目
        r = go("認証が無い（app/routes/nothere.js:3）。")
        ok("ファイルなしはNG", len(r["ng"]) == 1 and "無い" in r["ng"][0])
        r = go("設定（config/env/all.js:5）と（config/env/all.js:3-9）。")
        ok("行数超過はNG", len(r["ng"]) == 2 and "行数4" in r["ng"][0])
        r = go("逆（config/env/all.js:3-2）と（config/env/all.js:0）。")
        ok("範囲の逆転・0行目はNG", len(r["ng"]) == 2)
        # 5. 識別子が参照先のファイルに無ければ照合しない（別ファイルの語・無いことを述べる語）
        r = go("`helmet` が無い（app/index.js:1）。`csrfProtection` も無い。")
        ok("ファイルに無い語は使わない", not r["warn"] and r["chk"] == 0)
        # 6. 短い語・一般的な語は使わない
        r = go("`data` と `user` と `cb` を渡す（app/data/user-dao.js:44）。")
        ok("短い語・STOP", r["chk"] == 0)
        # 7. コードフェンスの中（diffの+/-行・該当コード）は読まない
        r = go("```diff\n+ x (app/routes/nothere.js:3)\n- y\n```")
        ok("フェンス内は対象外", r["n"] == 0 and not r["ng"])
        # 8. 複数の範囲・区切り（, 、 ・）・#L 形式
        r = go("`grunt-retire` を読む（Gruntfile.js:1-2,10）。")
        ok("複数範囲(,)", not r["warn"] and r["chk"] == 1)
        r = go(
            "`grunt-retire`（Gruntfile.js:1・10）。`grunt-retire`（Gruntfile.js#L9-L10）。"
        )
        ok("区切り・と#L", not r["warn"] and r["chk"] == 2 and r["n"] == 2)
        r = go("`grunt-retire` を読む（Gruntfile.js:1-2、4）。")
        ok("複数範囲の全てで外ならWARN", len(r["warn"]) == 1)
        r = go("参照（config/env/all.js:2、30行目）")
        ok("「30行目」は続きの番号でない", r["n"] == 1 and not r["ng"])
        # 9. URL・ポート・IP・製品名・依存の内部・拡張子なしの語
        r = go(
            "http://localhost:3000 と mongodb://mongo:27017 と 192.168.56.20:8080 に"
            "接続し、localhost:4000 で待つ。Node.js:12 と node_modules/x/y.js:3 も。"
        )
        ok(
            "URL・ポート等は参照でない",
            not r["ng"] and r["n"] == 2 and len(r["skip"]) == 2,
        )
        r = go("基底イメージ（Dockerfile:1）と `npm install`（Dockerfile:3）。")
        ok("拡張子なしの実在ファイル", r["n"] == 2 and not r["ng"] and not r["warn"])
        # 9b. リポジトリに無いファイル: 実在するディレクトリの下なら NG、依存の置き場所にあれば対象外、
        # どちらでもなければ未解決（WARN。依存を導入していない対象・成果物のファイル名）
        r = go("検証（verify.js:1）と（lib/types/json.js:57）と（json.js:3）。")
        ok(
            "依存の内部・未解決",
            not r["ng"]
            and len(r["skip"]) == 1
            and sorted(r["unres"]) == ["json.js", "lib/types/json.js"],
        )
        r = go("（config/nothere.js:1）と（env/nothere.js:1）。")
        ok("実在するディレクトリの下はNG", len(r["ng"]) == 2 and not r["unres"])
        # 9c. ルートのパス・コマンド等の語句はバッククォートでも識別子にしない
        r = go(
            "`/login` の応答（app/data/user-dao.js:2）と `npm install`（Dockerfile:1）。"
        )
        ok("ルートのパス・コマンド", r["chk"] == 0)
        r = go("`res.redirect('/')`（app/routes/session.js:2）。")
        ok("記号のあるコード片は使う", len(r["warn"]) == 1)
        # 10. 候補が複数（index.js）: 行数はどれかで足りればよく、識別子もどれかで近ければよい
        r = go("定数（index.js:3）。")
        ok("候補が複数", not r["ng"] and r["amb"] == 1)
        r = go("定数（index.js:4）。")
        ok("候補が複数で全て超過はNG", len(r["ng"]) == 1)
        # 11. 識別子は文字位置が最も近い参照に割り当てる（同じ文の別の参照の語で照合しない）
        r = go(
            "`cookieSecret`（config/env/all.js:2）を使い、"
            "userDAO.addUser（app/routes/session.js:8）で登録する。"
        )
        ok("最寄りの参照に割り当て", not r["warn"] and r["chk"] == 2)
        r = go(
            "検索は `getUserByUserName` を使い、登録は（app/data/user-dao.js:2）で行う。"
        )
        ok("読点の別の節には割り当てない", r["chk"] == 0)
        # 12. 単位は表のセルと文: 別のセル・別の文の語は割り当てない
        r = go(
            "| ファイル | `app/data/user-dao.js:2` | `getUserByUserName` |",
            "参照 app/data/user-dao.js:2。`getUserByUserName` は別の文。",
        )
        ok("セル・文で区切る", not r["warn"] and r["chk"] == 0 and r["n"] == 2)
        r = go("| 項目 | `getUserByUserName`（app/data/user-dao.js:2） |")
        ok("同じセル内は照合する", len(r["warn"]) == 1)
        # 13. 5節の外（6節）と見出しは読まない
        t = (
            _report("本文なし。")
            + "\n| AV | N | `findOne`（app/data/user-dao.js:2） |\n"
        )
        r = check(t, repo)
        ok("6節は対象外", r["n"] == 0)
        # 14. CLI（終了コード）と入力エラー
        rp = os.path.join(tmp, "r.md")

        def cli(text, *extra):
            with open(rp, "w", encoding="utf-8") as f:
                f.write(text)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["--report", rp, "--repo", tmp, *extra])
            return rc, buf.getvalue()

        rc, out = cli(_report("`findOne`（app/data/user-dao.js:45）。"))
        ok("CLI OK", rc == 0 and out.rstrip().endswith("RESULT: OK"))
        rc, out = cli(_report("`findOne`（app/data/user-dao.js:2）。"))
        ok("CLI WARNはrc0", rc == 0 and "WARN:" in out and "100.0%" in out)
        rc, out = cli(_report("（app/data/user-dao.js:99）。"))
        ok("CLI NGはrc1", rc == 1 and "RESULT: NG (1件)" in out)
        rc, out = cli(_report("（sign.js:1）と（sign.js:2）。"))
        ok("CLI 未解決はWARNでrc0", rc == 0 and out.count("WARN: 未解決: sign.js") == 1)
        rc, out = cli("# 5節なし\n")
        ok("CLI 節なしはrc2", rc == 2 and "RESULT: ERROR" in out)
        rc, out = cli(_report("`findOne`（app/data/user-dao.js:42）。"), "--verbose")
        ok("CLI --verbose", rc == 0 and "INFO: 近接:" in out)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--report", os.path.join(tmp, "none.md"), "--repo", tmp])
        ok("CLI 報告書なしはrc2", rc == 2)
        # 15. 否定の語の直前の識別子は使わない（同じ節、「が、」に続く次の節）
        r = go("`getUserByUserName` を呼ばず（app/data/user-dao.js:2）。")
        ok("否定（呼ばず）", r["chk"] == 0)
        r = go("app/data/user-dao.js:2 は getUserByUserName による確認が、存在しない。")
        ok("否定（次の節の述語）", r["chk"] == 0)
        r = go("app/data/user-dao.js:2 は getUserByUserName を呼び、結果を返す。")
        ok("否定でなければ照合", len(r["warn"]) == 1)
        # 16. 区切りだけで並んだ参照は1組（どれかの近傍にあればよい）
        r = go(
            "（app/routes/session.js:6, app/data/user-dao.js:2）: getUserByUserName を呼ぶ。"
        )
        ok("並んだ参照は1組", not r["warn"] and r["chk"] == 1)
        # 17. 関数等の定義が範囲の上（--search 行以内）にあれば、本体を指す参照として扱う
        r = go("addUser の中（app/data/user-dao.js:20）で保存する。")
        ok("定義の本体", not r["warn"] and r["chk"] == 1)
        r = go("addUser の中（app/data/user-dao.js:40）で保存する。")
        ok("定義から遠い本体はWARN", len(r["warn"]) == 1)
        # 18. 文書（README等）の参照は識別子で照合しない
        r = go("`MONGO_URL` の説明（docs/README.md:1）。")
        ok("文書は(c)の対象外", r["n"] == 1 and r["chk"] == 0 and not r["ng"])
        # 19. 全角のコロン、「6節」「3組」は続きの番号でない、記号のあるコード片
        r = go("`findOne`（app/data/user-dao.js：45）と（app/data/user-dao.js：99）。")
        ok("全角のコロン", r["n"] == 2 and r["chk"] == 1 and len(r["ng"]) == 1)
        r = go("（config/env/all.js:2、6節を参照）と（config/env/all.js:2、3組）。")
        ok("「6節」「3組」は番号でない", r["n"] == 2 and not r["ng"])
        r = go("`cookieSecret: 'x'`（config/env/all.js:2）。")
        ok("記号のあるコード片", r["chk"] == 1 and not r["warn"])
        # 20. 修正案の部分は --extra-root（修正後のツリー）でも成り立てばよい
        after = os.path.join(tmp, "after")
        os.makedirs(os.path.join(after, "app"))
        with open(os.path.join(after, "app", "new.js"), "w", encoding="utf-8") as f:
            f.write("a\nb\nfunction csrfCheck() {}\n")
        fixrep = "**推奨される修正**\n\n新設の `csrfCheck`（app/new.js:3）。"
        r = go(fixrep)
        ok("修正案の新規ファイル（extraなし）はNG", len(r["ng"]) == 1)
        r = go(fixrep, extra=Repo(after))
        ok("修正案の新規ファイル（extraあり）", not r["ng"] and r["chk"] == 1)
        r = go("新設の `csrfCheck`（app/new.js:3）。", extra=Repo(after))
        ok("修正案の外はextraを使わない", len(r["ng"]) == 1)
        # 21. BOM・CRLFの報告書と、CRLFの対象ファイル
        with open(os.path.join(tmp, "crlf.js"), "wb") as f:
            f.write(b"a\r\nb\r\nfindMe();\r\n")
        with open(rp, "wb") as f:
            f.write(
                b"\xef\xbb\xbf"
                + _report("`findMe`（crlf.js:3）と（crlf.js:4）。")
                .replace("\n", "\r\n")
                .encode("utf-8")
            )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["--report", rp, "--repo", tmp])
        out = buf.getvalue()
        ok("BOM・CRLF", rc == 1 and "行数3" in out and "識別子で照合1件" in out)
    # 22. 特殊ファイル・リポジトリの外へのリンク・「..」は読まない（FIFOで待たない）
    with tempfile.TemporaryDirectory() as top:
        sp = os.path.join(top, "repo")
        os.makedirs(sp)
        with open(os.path.join(top, "outside.js"), "w", encoding="utf-8") as f:
            f.write("secret();\n")
        with open(os.path.join(sp, "a.js"), "w", encoding="utf-8") as f:
            f.write("ok();\n")
        made = []
        for name, make in (
            ("fifo.js", lambda p: os.mkfifo(p)),
            ("hosts.js", lambda p: os.symlink("/etc/hosts", p)),
            ("zero.js", lambda p: os.symlink("/dev/zero", p)),
            ("out.js", lambda p: os.symlink(os.path.join(top, "outside.js"), p)),
        ):
            try:
                make(os.path.join(sp, name))
                made.append(name)
            except (OSError, AttributeError):
                pass  # 作れない環境（Windows等）では省略
        rsp = Repo(sp)
        ok("特殊ファイルは一覧に入れない", rsp.files == ["a.js"])
        refs = "".join(f"（{n}:1）" for n in made)
        r = check(_report(f"{refs}と（../outside.js:1）と（a.js:1）。"), rsp)
        ok(
            "特殊ファイル・外へのリンクは未解決",
            not r["ng"] and sorted(r["special"]) == sorted(made),
        )
        ok("「..」は解決しない", "../outside.js" in r["unres"] and r["res"] == 1)
        ok("特殊ファイルは読まない", all(rsp.lines(n) is None for n in made))
    if fails:
        print("self-test NG: " + ", ".join(fails))
        return 1
    print(
        "self-test OK (正常系 + 行のずれ・実在・行数・区切り・対象外・割り当て・否定・"
        "定義・修正後のツリー・特殊ファイル・CLI)"
    )
    return 0


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
