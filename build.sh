#!/usr/bin/env bash

set -euxo pipefail

rm -rf dist/

# x86
meson setup --cross-file cross-i686-w64-mingw32.txt build32
# without `--tags runtime`, the .a files are also installed
meson install  -C build32 --destdir ../dist/32bit --tags runtime,doc

# x86_64
meson setup --cross-file cross-x86_64-w64-mingw32.txt build64
meson install  -C build64 --destdir ../dist/64bit --tags runtime,doc

# docs
cp README.md dist/
# only copy MOD_README, I might have something in data_mods for testing
mkdir -p dist/data_mods
cp data_mods/MOD_README.txt dist/data_mods/

# while we wait for mesonbuild issue #4019 / PR #11954 to be solved, need to
# rename the special builds ourselves
shopt -s globstar
for i in dist/**/special_builds/**/*.dll; do
    mv "$i" "$(echo "$i" | sed 's/ifs_hook.*.dll$/ifs_hook.dll/')"
done

VERSION=$(meson introspect --projectinfo build32 | jq -r .version)

cd dist
zip -9r "ifs_layeredfs_$VERSION.zip" ./*
