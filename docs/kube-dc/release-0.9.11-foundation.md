# Kube-DC 0.9.11 project load-balancer foundation

This candidate rebases the retained, previously inactive Kube-DC project
load-balancer foundation onto upstream Kube-OVN 1.15.32. It preserves ownership
checks and the VPC deletion guard, and updates x/net to 0.62.0 with its security
closure. These helpers do not activate Core's prospective project-LB feature.
The earlier foundation was not a published, deployed provider fork.

Focused ownership tests and the ordinary load-balancer regression tests pass.
The ownership tests also pass against real Open vSwitch OVSDB 3.3.9, including
absence and foreign-ownership cases. The complete OVS, controller, OVSDB client and BFD supervisor regression suites
pass. `make lint` passes with golangci-lint 2.15.0 and the Go 1.26.10 modernize
tool. Compatibility cleanup aliases the libcap import and reports asynchronous
test cleanup errors without changing runtime behavior.

The candidate patches the cert-manager SDK to 1.20.3. A dedicated release
Dockerfile rebuilds GoBGP and kubectl from locked security dependencies and
updates Brotli; see [helper build instructions](../../dist/images/go-deps/security/README.md).
The patched GoBGP CLI/daemon passes configure/add/read/delete operations over
loopback gRPC with external BGP listeners disabled. Runtime image scanning and
live EIP/FIP/LB/MTU acceptance remain release gates.
