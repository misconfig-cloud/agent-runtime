#!/bin/sh
set -eu

prefix=${MISCONFIG_INSTALL_PREFIX:-/usr/local}
assume_yes=0
keep_state=0

usage() {
  echo "usage: ./uninstall.sh [--prefix /absolute/path] --yes [--keep-state]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      prefix=$2
      shift 2
      ;;
    --yes)
      assume_yes=1
      shift
      ;;
    --keep-state)
      keep_state=1
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[ "$assume_yes" -eq 1 ] || { usage; exit 2; }
case "$prefix" in
  /*) ;;
  *) echo "uninstall: --prefix must be an absolute path" >&2; exit 2 ;;
esac

target_binary=$prefix/bin/misconfig
if [ ! -e "$target_binary" ]; then
  echo "Misconfig is not installed at $target_binary"
  exit 0
fi
if [ "$keep_state" -ne 1 ]; then
  "$target_binary" uninstall --yes
fi
rm -f -- "$target_binary"
echo "Removed $target_binary"

