#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Convert an IODeviceTree plist to an ADT, redacting identifying data by default.

Capture: ioreg -p IODeviceTree -l -a -w0 > iodevicetree.plist
Usage: ioreg2adt.py INPUT OUTPUT [--binary] [--unredacted]
Text is the default. Requires construct; the m1n1 parser is bundled locally.
"""

import argparse
from pathlib import Path
import plistlib

from redact import redact_tree


def is_pci_shadow(entry):
    return entry.get('IOObjectClass') == 'IOPCIDevice' and 'IOPCIDeviceDeviceTreeEntry' in entry


def firmware_identities(entry):
    if not isinstance(entry.get('name'), bytes) or is_pci_shadow(entry):
        return set()
    identities = set()
    phandle = entry.get('AAPL,phandle')
    if isinstance(phandle, bytes):
        identities.add((phandle, entry['name'].rstrip(b'\0')))
    for child in entry.get('IORegistryEntryChildren', []):
        identities.update(firmware_identities(child))
    return identities


def convert_tree(tree, unredacted=False):
    identities = firmware_identities(tree)

    def node(entry, parent=None):
        name = entry['name'].rstrip(b'\0').decode() or entry.get('IORegistryEntryName', 'unnamed')
        here = '' if parent is None else f'{parent}/{name}'
        encoded_name = name.encode() + b'\0'
        props = [{'name': 'name', 'size': len(encoded_name), 'value': encoded_name}]
        for key, value in entry.items():
            if key == 'name' or not isinstance(value, bytes) or key.startswith('IO'):
                continue
            props.append({'name': key, 'size': len(value), 'value': value})
        children = []
        for child in entry.get('IORegistryEntryChildren', []):
            if not isinstance(child.get('name'), bytes):
                continue
            cname = child['name'].rstrip(b'\0').decode() or child.get('IORegistryEntryName', '')
            cpath = f'{here}/{cname}'
            # Keep original firmware entries instead of IOPCIFamily's copies,
            # which have duplicate phandles and runtime PCI address cells.
            if is_pci_shadow(child):
                identity = (child.get('AAPL,phandle'), child['name'].rstrip(b'\0'))
                if identity not in identities:
                    raise ValueError(f'No original firmware node for PCI copy {cpath}')
                continue
            children.append(node(child, here))
        return {'property_count': len(props), 'child_count': len(children),
                'properties': props, 'children': children}

    built = node(tree)
    return built if unredacted else redact_tree(built)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', type=Path, help='ioreg -p IODeviceTree -l -a -w0 archive')
    parser.add_argument('output', type=Path, help='output ADT text (or binary with --binary)')
    parser.add_argument('--binary', action='store_true', help='write binary ADT instead of text')
    parser.add_argument('--unredacted', action='store_true',
                        help='preserve identifying and boot/security values and private configuration nodes')
    args = parser.parse_args()
    from adt import ADTNodeStruct, load_adt

    root = plistlib.loads(args.input.read_bytes())
    if isinstance(root, list):
        if len(root) != 1:
            raise ValueError('Expected a single IORegistry root')
        root = root[0]
    tree = root['IORegistryEntryChildren'][0]
    tree = dict(tree, name=b'device-tree\0')
    data = ADTNodeStruct.build(convert_tree(tree, args.unredacted))
    if args.binary:
        args.output.write_bytes(data)
    else:
        args.output.write_text(str(load_adt(data)) + '\n')


if __name__ == '__main__':
    main()
