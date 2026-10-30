#!/usr/bin/env bash
# Build the runtime helpers with the release's locked security dependencies.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
GO=${GO:-go}
OUT=${1:?usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export CGO_ENABLED=0 GOTOOLCHAIN=local
[[ $("$GO" env GOVERSION) == go1.26.10 ]] || {
    echo 'The qualified helper toolchain is Go 1.26.10' >&2
    exit 1
}

# Verify the exact upstream module before applying the committed dependency locks.
"$GO" mod download -json github.com/osrg/gobgp/v4@v4.7.0 > "$WORK/gobgp.json"
SOURCE=$(python3 - "$WORK/gobgp.json" <<'PY'
import json, sys
record = json.load(open(sys.argv[1]))
assert record['Sum'] == 'h1:KPnmJVDFx1AJ39ESNpzHukAzaQYa4kRR5c7BbuDJhuM='
print(record['Dir'])
PY
)
cp -R "$SOURCE" "$WORK/gobgp"
chmod -R u+w "$WORK/gobgp"
cp "$HERE/gobgp/go.mod" "$HERE/gobgp/go.sum" "$WORK/gobgp/"
(
    cd "$WORK/gobgp"
    "$GO" build -mod=readonly -trimpath -ldflags='-s -w' -o "$OUT/gobgp" ./cmd/gobgp
    # Optional daemon supports the isolated CLI/gRPC interoperability smoke.
    if [[ ${BUILD_GOBGPD:-0} == 1 ]]; then
        "$GO" build -mod=readonly -trimpath -ldflags='-s -w' -o "$OUT/gobgpd" ./cmd/gobgpd
    fi
    cmp go.mod "$HERE/gobgp/go.mod"
    cmp go.sum "$HERE/gobgp/go.sum"
)
(
    cd "$HERE/kubectl"
    "$GO" build -mod=readonly -trimpath \
        -ldflags='-s -w -X k8s.io/component-base/version.gitVersion=v1.35.9-kube-dc.1 -X k8s.io/component-base/version.gitTreeState=dirty -X k8s.io/component-base/version.gitMajor=1 -X k8s.io/component-base/version.gitMinor=35' \
        -o "$OUT/kubectl" .
)
"$OUT/kubectl" version --client -o json > "$OUT/kubectl-version.json"
"$GO" version -m "$OUT/gobgp" > "$OUT/gobgp-buildinfo.txt"
"$GO" version -m "$OUT/kubectl" > "$OUT/kubectl-buildinfo.txt"
sha256sum "$OUT/gobgp" "$OUT/kubectl" > "$OUT/helpers.sha256"
