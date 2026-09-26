#!/usr/bin/env bash
# Builds the Windows x64 installer:
#
#   dist/Nexus-<version>-Setup-x64.exe
#   dist/Nexus-<version>-Setup-x64.exe.sha256
#   dist/RELEASE-NOTES.md
#
# Requirements (Linux, macOS or Git Bash on Windows): Go, Node.js/npm,
# makensis (NSIS 3.x), curl, unzip, tar with xz, sha256sum or shasum.
# Optional: x86_64-w64-mingw32-windres (icon + version info in nexus.exe),
# osslsigncode or signtool (Authenticode signing).
#
# Environment:
#   NEXUS_VERSION=x.y.z   override the version from ./VERSION (test builds)
#   SKIP_WEB=1            reuse frontend/dist
#   PG_WINDOWS_DIR=DIR    use an unpacked PostgreSQL (bin/lib/share) instead of downloading
#   VCRUNTIME_DIR=DIR     directory with vcruntime140.dll, vcruntime140_1.dll, msvcp140.dll
#   CACHE_DIR=DIR         download cache (default build/cache)
#   SIGN_PFX / SIGN_PFX_PASSWORD_FILE / SIGN_TIMESTAMP_URL   sign binaries and the installer
#
# Nothing secret is embedded: keys and passwords are generated on the target computer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/deployments/windows"
VERSION="${NEXUS_VERSION:-$(tr -d ' \r\n' < "$ROOT/VERSION")}"
ARCH=x64
BUILD="$ROOT/build/windows"
STAGE="$BUILD/stage"
APP="$STAGE/app/$VERSION"
CACHE_DIR="${CACHE_DIR:-$ROOT/build/cache}"
DIST="$ROOT/dist"
OUT="Nexus-$VERSION-Setup-$ARCH.exe"
# shellcheck source=deps.env
source "$HERE/deps.env"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION must be MAJOR.MINOR.PATCH (got '$VERSION')"
need go; need makensis; need curl; need unzip; need tar
MAKENSIS_VERSION="$(makensis -VERSION 2>/dev/null || true)"
[[ "$MAKENSIS_VERSION" == v3* ]] || die "NSIS 3.x required (found '$MAKENSIS_VERSION')"

fetch() { # url sha256 file
  local url="$1" want="$2" file="$3"
  mkdir -p "$(dirname "$file")"
  if [[ ! -f "$file" ]] || [[ "$(sha256 "$file")" != "$want" ]]; then
    log "Downloading $(basename "$file")"
    curl -fsSL --retry 4 --retry-delay 2 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  local got; got="$(sha256 "$file")"
  [[ "$got" == "$want" ]] || die "checksum mismatch for $file: $got (expected $want)"
}

rm -rf "$BUILD"
mkdir -p "$APP" "$DIST" "$CACHE_DIR"

# ---------------------------------------------------------------- web UI
if [[ "${SKIP_WEB:-}" != "1" ]]; then
  need npm
  log "Building web interface"
  (cd "$ROOT/frontend" && npm ci --no-audit --no-fund && npm run build)
fi
[[ -f "$ROOT/frontend/dist/index.html" ]] || die "frontend/dist is missing (unset SKIP_WEB)"
cp -R "$ROOT/frontend/dist" "$APP/web"

# ---------------------------------------------------------------- resources
V4="$VERSION.0"
VC="${VERSION//./,},0"
SYSO="$ROOT/backend/cmd/nexus/rsrc_windows_amd64.syso"
rm -f "$SYSO"
if command -v x86_64-w64-mingw32-windres >/dev/null 2>&1; then
  log "Compiling Windows resources (icon, version, manifest)"
  sed "s|@VERSION4@|$V4|" "$HERE/nexus.manifest" > "$BUILD/nexus.manifest"
  sed -e "s|@ASSETS@|$HERE/assets|" -e "s|@MANIFEST@|$BUILD/nexus.manifest|" -e "s|@VERSIONC@|$VC|g" \
      -e "s|@VERSION@|$VERSION|g" -e "s|@NAME@|nexus|g" -e "s|@DESCRIPTION@|Nexus Network Intelligence|" \
      "$HERE/nexus.rc.in" > "$BUILD/nexus.rc"
  PREPROC=cpp; command -v cpp >/dev/null 2>&1 || PREPROC=x86_64-w64-mingw32-gcc
  x86_64-w64-mingw32-windres --preprocessor="$PREPROC" -c 65001 -O coff -o "$SYSO" "$BUILD/nexus.rc"
else
  echo "   (windres not found: nexus.exe gets no icon/version resource)"
fi

# ---------------------------------------------------------------- backend
log "Building nexus.exe $VERSION"
(cd "$ROOT/backend" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$VERSION" -o "$APP/nexus.exe" ./cmd/nexus)
rm -f "$SYSO"

# ---------------------------------------------------------------- PostgreSQL
PGSRC="$BUILD/pgsrc"
if [[ -n "${PG_WINDOWS_DIR:-}" ]]; then
  log "Using PostgreSQL from $PG_WINDOWS_DIR"
  PGSRC="$PG_WINDOWS_DIR"
else
  JAR="$CACHE_DIR/$(basename "$PG_URL")"
  fetch "$PG_URL" "$PG_SHA256" "$JAR"
  mkdir -p "$PGSRC"
  unzip -q -o "$JAR" 'postgres-windows-x86_64.txz' -d "$BUILD"
  tar -xJf "$BUILD/postgres-windows-x86_64.txz" -C "$PGSRC"
fi
log "Staging PostgreSQL (server only)"
PG="$APP/pgsql"
mkdir -p "$PG/bin" "$PG/lib" "$PG/share"
# Executables and the DLLs they (and the server modules) load.
for f in postgres.exe pg_ctl.exe initdb.exe \
         icudt67.dll icuin67.dll icuuc67.dll libcrypto-3-x64.dll libssl-3-x64.dll libiconv-2.dll libintl-9.dll \
         liblz4.dll libzstd.dll libpq.dll libwinpthread-1.dll libxml2.dll libxslt.dll zlib1.dll libecpg.dll libpgtypes.dll; do
  [[ -f "$PGSRC/bin/$f" ]] || die "PostgreSQL bundle lacks bin/$f"
  cp "$PGSRC/bin/$f" "$PG/bin/"
done
# Server modules, without test modules and procedural languages needing Perl/Python/Tcl.
for f in "$PGSRC"/lib/*.dll; do
  b="$(basename "$f")"
  case "$b" in
    test_*|regress.dll|worker_spi.dll|plsample.dll|dummy_*|*plperl*|*plpython*|pltcl*|delay_execution.dll) continue ;;
  esac
  cp "$f" "$PG/lib/"
done
# Shared data without message translations (the server runs with lc_messages=C).
(cd "$PGSRC/share" && tar -cf - --exclude=./locale .) | (cd "$PG/share" && tar -xf -)

# ---------------------------------------------------------------- VC++ runtime (app-local)
if [[ -n "${VCRUNTIME_DIR:-}" ]]; then
  VCDIR="$VCRUNTIME_DIR"
else
  WHL="$CACHE_DIR/$(basename "$VCRT_URL")"
  fetch "$VCRT_URL" "$VCRT_SHA256" "$WHL"
  VCDIR="$BUILD/vcrt"
  mkdir -p "$VCDIR"
  unzip -q -o -j "$WHL" "msvc_runtime-$VCRT_VERSION.data/data/Scripts/vcruntime140.dll" \
    "msvc_runtime-$VCRT_VERSION.data/data/Scripts/vcruntime140_1.dll" "msvc_runtime-$VCRT_VERSION.data/data/Scripts/msvcp140.dll" \
    "msvc_runtime-$VCRT_VERSION.dist-info/licenses/LICENSE" -d "$VCDIR"
fi
for f in vcruntime140.dll vcruntime140_1.dll msvcp140.dll; do
  [[ -f "$VCDIR/$f" ]] || die "VC++ runtime file $f not found in $VCDIR"
  cp "$VCDIR/$f" "$PG/bin/"
done

# ---------------------------------------------------------------- notices
log "Adding licenses and notices"
mkdir -p "$APP/licenses"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$APP/"
cp "$ROOT/docs/THIRD_PARTY_LICENSES.md" "$APP/licenses/THIRD_PARTY_LICENSES.md"
cp "$HERE/licenses/"*.txt "$APP/licenses/"
[[ -f "$VCDIR/LICENSE" ]] && cp "$VCDIR/LICENSE" "$APP/licenses/Microsoft-VC-Runtime-REDIST.txt"
cp "$HERE/assets/nexus.ico" "$APP/nexus.ico"

# ---------------------------------------------------------------- signing (optional)
sign() { # file
  [[ -n "${SIGN_PFX:-}" ]] || return 0
  local ts="${SIGN_TIMESTAMP_URL:-http://timestamp.digicert.com}"
  if command -v osslsigncode >/dev/null 2>&1; then
    osslsigncode sign -pkcs12 "$SIGN_PFX" ${SIGN_PFX_PASSWORD_FILE:+-readpass "$SIGN_PFX_PASSWORD_FILE"} \
      -n "Nexus Network Intelligence" -h sha256 -ts "$ts" -in "$1" -out "$1.signed" && mv "$1.signed" "$1"
  elif command -v signtool >/dev/null 2>&1 || command -v signtool.exe >/dev/null 2>&1; then
    local pw=""; [[ -n "${SIGN_PFX_PASSWORD_FILE:-}" ]] && pw="$(cat "$SIGN_PFX_PASSWORD_FILE")"
    signtool sign /fd sha256 /tr "$ts" /td sha256 /f "$SIGN_PFX" ${pw:+/p "$pw"} "$1"
  else
    die "SIGN_PFX is set but neither osslsigncode nor signtool is available"
  fi
}
SIGNED=no
if [[ -n "${SIGN_PFX:-}" ]]; then
  log "Signing nexus.exe"
  sign "$APP/nexus.exe"
  SIGNED=yes
fi

# ---------------------------------------------------------------- installer
log "Packaging installer with NSIS $MAKENSIS_VERSION"
PGVER="${PG_VERSION%.0}"
makensis -V2 -INPUTCHARSET UTF8 \
  -DVERSION="$VERSION" -DSTAGE="$STAGE" -DASSETS="$HERE/assets" -DOUTFILE="$DIST/$OUT" \
  -DPGVERSION="$PGVER" -DSIGNED="$SIGNED" "$HERE/installer.nsi"
if [[ "$SIGNED" == yes ]]; then
  log "Signing installer"
  sign "$DIST/$OUT"
fi

# ---------------------------------------------------------------- checksum + notes
(cd "$DIST" && printf '%s  %s\n' "$(sha256 "$OUT")" "$OUT" > "$OUT.sha256")
sed -e "s|@VERSION@|$VERSION|g" -e "s|@FILE@|$OUT|g" -e "s|@SHA256@|$(cut -d' ' -f1 "$DIST/$OUT.sha256")|g" \
    -e "s|@PGVERSION@|$PGVER|g" -e "s|@SIGNED@|$([[ $SIGNED == yes ]] && echo 'Authenticode-signed' || echo 'NOT code-signed (no certificate configured); Windows SmartScreen may ask for confirmation')|g" \
    "$HERE/RELEASE-NOTES.md.in" > "$DIST/RELEASE-NOTES.md"

log "Done"
ls -l "$DIST"
cat "$DIST/$OUT.sha256"
