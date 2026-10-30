# Kube-DC 0.9.11 project load-balancer foundation

This candidate rebases the retained, previously inactive Kube-DC project
load-balancer foundation onto upstream Kube-OVN 1.15.32. It preserves ownership
checks and the VPC deletion guard, and updates x/net to 0.62.0 with its security
closure. These helpers do not activate Core's prospective project-LB feature.
The earlier foundation was not a published, deployed provider fork.

Focused ownership tests and the ordinary load-balancer regression tests pass.
The ownership tests also pass against real Open vSwitch OVSDB 3.3.9, including
absence and foreign-ownership cases. Runtime binaries, the immutable image and
live EIP/FIP/LB/MTU acceptance remain release gates.
