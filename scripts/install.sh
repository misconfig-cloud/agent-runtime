#!/bin/sh
set -eu

prefix=${MISCONFIG_INSTALL_PREFIX:-/usr/local}
assume_yes=0

usage() {
  echo "usage: ./install.sh [--prefix /absolute/path] [--yes]" >&2
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
    *)
      usage
      exit 2
      ;;
  esac
done

case "$prefix" in
  /*) ;;
  *) echo "install: --prefix must be an absolute path" >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_binary=$script_dir/misconfig
target_dir=$prefix/bin
target_binary=$target_dir/misconfig

[ -f "$source_binary" ] || { echo "install: misconfig must be next to install.sh" >&2; exit 1; }
if [ -e "$target_binary" ] && [ "$assume_yes" -ne 1 ]; then
  echo "install: $target_binary already exists; pass --yes to replace it" >&2
  exit 1
fi

mkdir -p "$target_dir"
install -m 0755 "$source_binary" "$target_binary"

echo "Installed $target_binary"
echo "Enroll without putting a secret in argv:"
echo "  $target_binary setup --tenant TENANT --actor EMAIL --token-file -"

