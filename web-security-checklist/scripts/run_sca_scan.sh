#!/bin/sh
# run_sca_scan.py を呼ぶ薄いラッパー（旧 run_sca_scan.sh と同じ引数で動く）。
# python3 → python → py -3 の順に、Python 3.9以上のものを探して exec する。
# 使い方: run_sca_scan.sh [対象ディレクトリ]
d="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)" || exit 1
case "$(uname -s 2>/dev/null)" in
CYGWIN* | MINGW* | MSYS*) command -v cygpath >/dev/null 2>&1 && d="$(cygpath -m "$d")" ;;
esac
chk='import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c "$chk" >/dev/null 2>&1; then
    exec "$c" "$d/run_sca_scan.py" "$@"
  fi
done
if command -v py >/dev/null 2>&1 && py -3 -c "$chk" >/dev/null 2>&1; then
  exec py -3 "$d/run_sca_scan.py" "$@"
fi
echo "Python 3.9以上（python3 / python / py -3）が見つかりません。" >&2
exit 127
