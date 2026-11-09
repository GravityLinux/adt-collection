#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Redact a raw ADT binary; emit text by default, or binary with --binary."""


import argparse
from pathlib import Path
import re


# These identify hardware interfaces, not the individual machine. Preserve them
# so references, node names, and m1n1's typed decoding continue to work.
STRUCTURAL_PROPERTIES = {'name', 'compatible', 'device_type', 'AAPL,phandle',
                         '#address-cells', '#size-cells', '#interrupt-cells'}
CHOSEN_KEEP = {'#address-cells', 'AAPL,phandle', 'board-id', 'chip-id', 'chip-epoch',
               'dram-base', 'dram-size', 'dram-type', 'dram-vendor', 'dram-vendor-id',
               'dram-ecc', 'dram-ecc-mode', 'display-boot-rotation', 'display-corner-radius',
               'display-rotation', 'display-scale', 'firmware-version',
               'system-firmware-version', 'secure-boot', 'security-domain',
               'embedded-panic-log-size', 'dart-clock-gapf-rsvd-slices',
               'dart-clock-gapf-ungang-count', 'dart-clock-gapf-ungang-entries',
               'dart-clock-protection', 'dart-gapf-sr-region'}
CHOSEN_PUBLIC_SUBTREES = ('/chosen/carveout-memory-map', '/chosen/lock-regs')
# Configuration subtrees can identify the owner through property or node names,
# as well as values. Omit them entirely when redacting.
PRIVATE_SUBTREES = {'/iboot-syscfg', '/options', '/filesystems-props'}
SENSITIVE_PROPERTY = re.compile(
    r'nvram|serial|mac[-_]?address|ecid|nonce|seed|uuid|udid|guid|'
    r'unique[-_](chip|device|container)[-_]id|die[-_]id|aes[-_]key|'
    r'(^|[-_])key($|[-_])|keybag|hash|cert|calib|manifest|auth[-_]blob|'
    r'entropy|snapshot|host[-_]os|syscfg|boot[-_]?args?|bootarg|imei|meid|'
    r'region-info|country-of-origin|config-number|model-config|repair|'
    r'breadcrumb|bootp|measurement|ticket|account|password|credential|secret|token|'
    r'edid|eeprom|speaker-thiele-small|speaker-trim-gains|wifi-rfem-info', re.I)



def should_redact(path, key):
    if key in STRUCTURAL_PROPERTIES:
        return False
    # Redact every NVRAM payload, including nvram-proxy-data, regardless of path.
    if SENSITIVE_PROPERTY.search(key):
        return True
    if path == '/chosen':
        return key not in CHOSEN_KEEP
    if path.startswith('/chosen/'):
        return not any(path == p or path.startswith(p + '/') for p in CHOSEN_PUBLIC_SUBTREES)
    return False



def redact_tree(tree, parent=None):
    """Return a redacted copy of an ADTNodeStruct tree."""
    name = next(p['value'] for p in tree['properties'] if p['name'] == 'name')
    name = name.rstrip(b'\0').decode()
    path = '' if parent is None else f'{parent}/{name}'
    properties = []
    for prop in tree['properties']:
        prop = dict(prop)
        if should_redact(path, prop['name']):
            prop['value'] = bytes(len(prop['value']))
            # Zero bytes are data, not a firmware template string. Clear the
            # template bit while retaining the original payload length.
            prop['size'] = len(prop['value'])
        properties.append(prop)
    children = []
    for child in tree['children']:
        child_name = next(p['value'] for p in child['properties'] if p['name'] == 'name')
        child_name = child_name.rstrip(b'\0').decode()
        child_path = f'{path}/{child_name}'
        if child_path not in PRIVATE_SUBTREES:
            children.append(redact_tree(child, path))
    return {'property_count': len(properties), 'child_count': len(children),
            'properties': properties, 'children': children}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='raw ADT binary')
    parser.add_argument('output', type=Path, help='redacted text (or binary with --binary)')
    parser.add_argument('--binary', action='store_true', help='write binary ADT instead of text')
    args = parser.parse_args()
    from adt import ADTNodeStruct, load_adt

    tree = ADTNodeStruct.parse(args.input.read_bytes())
    data = ADTNodeStruct.build(redact_tree(tree))
    if args.binary:
        args.output.write_bytes(data)
    else:
        args.output.write_text(str(load_adt(data)) + '\n')


if __name__ == '__main__':
    main()
