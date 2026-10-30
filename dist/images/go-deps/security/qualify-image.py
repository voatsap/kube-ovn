#!/usr/bin/env python3
"""Scan the complete assembled release image, including inherited helpers."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def run(*args):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SYFT_', 'GRYPE_'))}
    return subprocess.check_output(args, text=True, env=env, timeout=600)


def qualify(image, output):
    info = json.loads(run('docker', 'image', 'inspect', image))[0]
    identity = info['Id']
    assert (info['Os'], info['Architecture']) == ('linux', 'amd64')
    source = info['Config']['Labels']['org.opencontainers.image.revision']
    assert re.fullmatch('[a-f0-9]{40}', source)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / 'syft.yaml').write_text('check-for-app-update: false\nexclude: []\nscope: squashed\ndefault-catalogers: [image]\nfile:\n  metadata:\n    selection: all\n')
    (output / 'grype.yaml').write_text('check-for-app-update: false\nonly-fixed: false\nonly-notfixed: false\nignore: []\n')
    sbom = output / 'sbom.cdx.json'
    scan = output / 'vulnerabilities.json'
    sbom.write_text(run('syft', '--config', str(output / 'syft.yaml'), 'docker:' + identity, '-o', 'cyclonedx-json'))
    data = json.loads(sbom.read_text())
    files = {c['name'] for c in data['components'] if c['type'] == 'file'}
    required = {'/usr/bin/gobgp', '/usr/bin/kubectl'} | {
        '/kube-ovn/' + name for name in ('kube-ovn', 'kube-ovn-cmd', 'kube-ovn-daemon',
                                       'kube-ovn-controller', 'kube-ovn-bfdd-supervisor')}
    assert required <= files, 'Incomplete executable coverage: ' + str(required - files)
    expected = {'golang.org/x/net': 'v0.62.0', 'golang.org/x/text': 'v0.43.0',
                'google.golang.org/grpc': 'v1.83.2', 'github.com/cert-manager/cert-manager': 'v1.20.3',
                'k8s.io/kubectl': 'v0.35.9', 'libbrotli1': '1.1.0-2ubuntu0.1'}
    for name, version in expected.items():
        actual = {c.get('version') for c in data['components'] if c['name'] == name}
        assert actual == {version}, f'{name}: expected {version}, found {actual}'
    scan.write_text(run('grype', '--config', str(output / 'grype.yaml'), 'sbom:' + str(sbom), '-o', 'json'))
    findings = json.loads(scan.read_text())
    assert not findings.get('ignoredMatches'), 'Suppressed scan findings'
    counts = collections.Counter(m['vulnerability']['severity'] for m in findings['matches'])
    blocking = [{'id': m['vulnerability']['id'], 'package': m['artifact']['name'],
                 'version': m['artifact']['version']} for m in findings['matches']
                if m['vulnerability']['severity'] in ('Critical', 'High')]
    assert run('docker', 'image', 'inspect', image, '--format', '{{.Id}}').strip() == identity
    record = {'imageConfigID': identity, 'sourceRevision': source, 'rawSeverityCounts': dict(counts),
              'requiredExecutables': sorted(required), 'securityDependencies': expected,
              'blockingFindings': blocking, 'criticalHighGatePassed': not blocking,
              'syftVersion': json.loads(run('syft', 'version', '-o', 'json')),
              'grypeVersion': findings['descriptor']['version'], 'database': findings['descriptor']['db']['status'],
              'sbomSHA256': hashlib.sha256(sbom.read_bytes()).hexdigest(),
              'scanSHA256': hashlib.sha256(scan.read_bytes()).hexdigest()}
    (output / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    if blocking:
        raise RuntimeError(f'{len(blocking)} Critical/High findings remain')
    print(json.dumps({'imageConfigID': identity, 'rawSeverityCounts': counts, 'criticalHighGatePassed': True}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    qualify(args.image, args.output)
