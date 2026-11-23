#!/usr/bin/env python3
"""対象ディレクトリ(デフォルト:カレント)のファイルから使用スタックを検出し、
対応する references/lang/*.md のパスを標準出力に列挙する（標準ライブラリのみ）。
使い方: detect_stack.py [対象ディレクトリ]
終了コードは常に0。.sh は本ファイルを呼ぶ薄いラッパー。DBの検出はP4で旧bash版から変えた（語の境界、Pipfile・kts）。
Linux・Windows・macOS で動く。Python 3.9以上。"""

from __future__ import annotations

import os
import re
import sys

# DB使用の簡易検出。語は英数字の境界で区切る（P4: 旧.shは部分一致で "upgrade" の pg でも出ていた）。
# 語の後の数字は許す（mysql2・psycopg2・sqlite3）。区切りの "-"・"/"・"@" は境界（pg-promise・@prisma/client・data-jpa）
DB_WORDS = (
    "pg", "postgres", "postgresql", "mysql", "mariadb", "sqlite", "better-sqlite", "mongodb", "mongoose",
    "prisma", "typeorm", "sequelize", "knex", "drizzle-orm", "mikro-orm",
    "sqlalchemy", "django", "psycopg", "asyncpg", "pymysql", "peewee", "pymongo", "tortoise-orm",
    "jpa", "hibernate", "jdbc", "mybatis", "jooq",
)
DB_RE = re.compile(
    rb"(?<![A-Za-z0-9])(?:" + b"|".join(re.escape(w.encode()) for w in DB_WORDS) + rb")\d*(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# 検査するファイル（P4: Pipfile と build.gradle.kts も検査する）
DB_FILES = ("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "pom.xml", "build.gradle",
            "build.gradle.kts")


def _isfile(target, name):
    return os.path.isfile(os.path.join(target, name))


def _any_file_matches(target):
    for name in DB_FILES:
        path = os.path.join(target, name)
        try:
            with open(path, "rb") as f:
                if DB_RE.search(f.read()):
                    return True
        except OSError:
            continue  # 無い・読めない・ディレクトリ: grep の 2>/dev/null と同じく無視
    return False


def detect(target, script_dir):
    """戻り値 (標準出力の行のリスト, 標準エラーの行のリスト)"""
    lang_dir = script_dir + "/../references/lang"
    out, err = [], []
    found = False

    if _isfile(target, "package.json") or _isfile(target, "tsconfig.json"):
        out.append(f"nodejs-typescript: {lang_dir}/nodejs-typescript.md")
        found = True
    if any(_isfile(target, n) for n in ("requirements.txt", "pyproject.toml", "Pipfile")):
        out.append(f"python: {lang_dir}/python.md")
        found = True
    if any(_isfile(target, n) for n in ("pom.xml", "build.gradle", "build.gradle.kts")):
        out.append(f"java: {lang_dir}/java.md")
        found = True
    if _any_file_matches(target):
        out.append(f"database: {script_dir}/../references/checklists/database/_index.md")
    if not found:
        err.append(
            "unknown_stack: 該当する言語別referenceが見つかりませんでした。"
            "references/checklists/principles.md の原則ベースで判断してください。"
        )
    return out, err


def main(argv):
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", newline="\n")
        except (AttributeError, ValueError):
            pass
    target = argv[0] if argv and argv[0] else "."  # ${1:-.}
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out, err = detect(target, script_dir)
    for line in out:
        print(line)
    for line in err:
        print(line, file=sys.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
