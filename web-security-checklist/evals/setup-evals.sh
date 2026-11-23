#!/usr/bin/env bash
# 評価用サンプルアプリ sample-vulnerable-app の実行環境（node_modules/ と種データ入りの data/app.db）を作る。
#
# 使い方:
#   setup-evals.sh [--force] <アプリのディレクトリ>   コピーした先に作る（通常はこちら）
#   setup-evals.sh [--force] --in-place               元の evals/sample-vulnerable-app に作る
#     --force     既存の data/app.db を消して作り直す（既定では上書きしない）。
#     --in-place  このスクリプトと同じ場所の sample-vulnerable-app に書き込む。明示したときだけ書き込む
#                 （引数なしでは何もしない。元の evals/ に node_modules/ や data/ を作らないため）。
#
# 注意:
# - ネットワーク（npm レジストリと、sqlite3 のプリビルドの取得先の GitHub）が必要。npm ci が package-lock.json に
#   固定した版を取得し、sqlite3 のネイティブモジュール（プリビルドの取得、失敗すれば node-gyp でのビルド。ビルドには
#   python3 と C++ コンパイラが要る）を用意するため、--ignore-scripts は付けない。
# - 対象アプリのコード・package.json・package-lock.json は変更しない。書き込むのは、アプリのディレクトリの
#   node_modules/（npm ci が既存のものを消して作り直す）と data/app.db、npm のキャッシュ（~/.npm）、ビルドに
#   落ちたときは node-gyp のキャッシュ（~/.cache/node-gyp、macOS では ~/Library/Caches/node-gyp）である。
# - 種データは、このスクリプトと同じ場所の sample-vulnerable-app-seed.js（表の定義はアプリの db.js のもの）。
# - 必要なもの: Node.js と npm（sqlite3 の CLI は不要）。macOS の bash 3.2 と Linux の bash で動く。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEED="$SCRIPT_DIR/sample-vulnerable-app-seed.js"

usage() {
  awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0"
}

FORCE=0
IN_PLACE=0
APP_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
  --force) FORCE=1 ;;
  --in-place) IN_PLACE=1 ;;
  -h | --help)
    usage
    exit 0
    ;;
  "")
    echo "空の引数は使えない（アプリのディレクトリか --in-place を指定する）" >&2
    exit 2
    ;;
  -*)
    echo "不明な引数: $1" >&2
    exit 2
    ;;
  *)
    if [ -n "$APP_DIR" ]; then
      echo "アプリのディレクトリは1つだけ指定する: $1" >&2
      exit 2
    fi
    APP_DIR="$1"
    ;;
  esac
  shift
done

if [ "$IN_PLACE" -eq 1 ] && [ -n "$APP_DIR" ]; then
  echo "--in-place とアプリのディレクトリは同時に指定できない" >&2
  exit 2
fi
if [ "$IN_PLACE" -eq 1 ]; then
  APP_DIR="$SCRIPT_DIR/sample-vulnerable-app"
elif [ -z "$APP_DIR" ]; then
  usage >&2
  echo "書き込み先を指定する（アプリのディレクトリ、または元の場所なら --in-place）" >&2
  exit 2
fi
for f in package.json package-lock.json db.js; do
  if [ ! -f "$APP_DIR/$f" ]; then
    echo "$APP_DIR/$f が無い（sample-vulnerable-app かそのコピーを指定する）" >&2
    exit 1
  fi
done
if [ ! -f "$SEED" ]; then
  echo "種データのスクリプトが無い: $SEED" >&2
  exit 1
fi
cd "$APP_DIR"

echo "== npm ci ($(pwd))"
if ! npm ci --no-audit --no-fund; then
  echo "npm ciに失敗した（ネットワーク・プロキシ・レジストリを確認する。sqlite3 のビルドに落ちた場合は python3 と C++ コンパイラも要る）" >&2
  exit 1
fi
if ! node -e "require('sqlite3')"; then
  echo "sqlite3 のネイティブモジュールを読めない（npm がインストールスクリプトを止めていないか、allow-scripts の警告を確認する）" >&2
  exit 1
fi

DB=data/app.db
if [ -f "$DB" ] && [ "$FORCE" -eq 0 ]; then
  echo "== $DB は既にあるので作らない（作り直すときは --force）"
  exit 0
fi
rm -f "$DB"
mkdir -p data
echo "== 種データで $DB を作る"
if ! node "$SEED"; then
  rm -f "$DB"
  echo "種データの投入に失敗した（$DB は残していない）" >&2
  exit 1
fi
echo "== 完了: node server.js で起動する（PORT の既定は3000）"
