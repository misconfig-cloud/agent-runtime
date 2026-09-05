#!/bin/sh
set -eu

prefix=${MISCONFIG_INSTALL_PREFIX:-/usr/local}
assume_yes=0
required_version=

usage() {
  echo "usage: ./install.sh [--prefix /absolute/path] [--require-version VERSION] [--yes]" >&2
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
    --require-version)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      required_version=$2
      shift 2
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
staged_binary=$target_dir/.misconfig.install.$$
backup_binary=$target_dir/.misconfig.backup.$$

cleanup() {
  rm -f -- "$staged_binary"
}
trap cleanup EXIT HUP INT TERM

install -m 0755 "$source_binary" "$staged_binary"
version_output=$("$staged_binary" version) || {
  echo "install: staged runtime did not pass its version check" >&2
  exit 1
}
case "$version_output" in
  "misconfig "*) staged_version=${version_output#misconfig } ;;
  *) echo "install: staged runtime returned an invalid version" >&2; exit 1 ;;
esac
if [ -n "$required_version" ] && [ "$staged_version" != "$required_version" ]; then
  echo "install: archive version $staged_version does not match required version $required_version" >&2
  exit 1
fi

had_previous=0
if [ -e "$target_binary" ]; then
  mv "$target_binary" "$backup_binary"
  had_previous=1
fi
if ! mv "$staged_binary" "$target_binary"; then
  if [ "$had_previous" -eq 1 ]; then
    mv "$backup_binary" "$target_binary" || {
      echo "install: replacement and automatic restore failed; previous runtime remains at $backup_binary" >&2
      exit 1
    }
  fi
  echo "install: atomic replacement failed; previous runtime was restored" >&2
  exit 1
fi
if ! "$target_binary" version >/dev/null 2>&1; then
  rm -f -- "$target_binary"
  if [ "$had_previous" -eq 1 ]; then
    mv "$backup_binary" "$target_binary" || {
      echo "install: verification and automatic restore failed; previous runtime remains at $backup_binary" >&2
      exit 1
    }
  fi
  echo "install: installed runtime failed verification; previous runtime was restored" >&2
  exit 1
fi
rm -f -- "$backup_binary"

echo "Installed $target_binary ($staged_version)"
echo "Pair this device in your browser:"
echo "  $target_binary setup --control https://console.misconfig.cloud"
