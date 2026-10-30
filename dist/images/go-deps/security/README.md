# Release helper builds

The 0.9.11 Kube-DC image replaces the base image's GoBGP and kubectl binaries.
The base contains vulnerable x/net, x/text and gRPC versions. The application
version remains GoBGP 4.7.0; kubectl uses the installation baseline, 1.35.9.
Both builds use Go 1.26.10 and committed dependency locks. Use the dedicated
`Dockerfile.kube-dc-release`; upstream image targets retain their original inputs. The image also
updates Noble's libbrotli1 to 1.1.0-2ubuntu0.1.

`kubectl/main.go` is copied without modification from
[`kubernetes/kubernetes` v1.35.9](https://github.com/kubernetes/kubernetes/blob/v1.35.9/cmd/kubectl/kubectl.go).
Its SHA-256 is `b9660b8cacc734cf667f56fd55ae622e8f829536ac18aadf5fb1db0f8eb7edd5`.
The wrapper links published Kubernetes 0.35.9 modules. Its version reports
`v1.35.9-kube-dc.1` and a dirty source tree to identify the dependency patches.

The GoBGP source is the checksum-verified Go module at
[`osrg/gobgp` v4.7.0](https://github.com/osrg/gobgp/tree/v4.7.0), commit
`8b5edc2c55cbec9e7df33123a07811a119d44542`. The build script replaces its
dependency locks with the committed `gobgp/go.mod` and `gobgp/go.sum`.

With Go 1.26.10 on your path, build the helpers into the image context:

```sh
dist/images/go-deps/security/build.sh dist/images
make build-go
docker build -f dist/images/Dockerfile.kube-dc-release --build-arg BASE_TAG='v1.15.32@sha256:66b92e480a50f74ec6ab48a5a1195bc08f625b1fe75558b8cda65ecdddb5e186' dist/images
```

Set `BUILD_GOBGPD=1` to build a test daemon for an isolated loopback CLI/gRPC
smoke. Only `gobgp` and `kubectl` are copied into the runtime image. Keep the
generated build information and hashes with the image's SBOM and scan results.
Scan the assembled image before publishing it; rebuilding the five Kube-OVN
executables alone does not cover tools inherited from its base image.

Relevant security fixes:

- [gRPC HTTP/2 memory exhaustion](https://github.com/advisories/GHSA-vp52-pcj8-j9qc)
- [cert-manager ACME solver policy](https://github.com/advisories/GHSA-8rvj-mm4h-c258)
- [Ubuntu Brotli update](https://ubuntu.com/security/CVE-2026-111497)
