from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from adt import ADTNodeStruct
from ioreg2adt import convert_tree
from redact import redact_tree


class StandaloneRedactionTests(unittest.TestCase):
    def test_redaction_clears_template_flag_without_mutating_input(self):
        template = b'syscfg/SrNm/0x20\0'
        source = convert_tree({'name': b'device-tree\0', 'serial-number': template,
                               'board-id': b'\x02\0\0\0'}, unredacted=True)
        source['properties'][1]['size'] |= 0x80000000
        original = deepcopy(source)
        result = redact_tree(source)
        self.assertEqual(source, original)
        self.assertEqual(result['properties'][1],
                         {'name': 'serial-number', 'size': len(template), 'value': bytes(len(template))})
        self.assertEqual(result['properties'][2], source['properties'][2])

    def test_standalone_binary_cli_matches_converter_redaction(self):
        tree = {'name': b'device-tree\0', 'serial-number': b'SERIAL123\0',
                'IORegistryEntryChildren': [
                    {'name': b'chosen\0', 'nvram-proxy-data': b'private NVRAM payload'},
                    {'name': b'options\0', 'owner': b'private owner'}]}
        raw = ADTNodeStruct.build(convert_tree(tree, unredacted=True))
        expected = ADTNodeStruct.build(convert_tree(tree))
        script = Path(__file__).with_name('redact.py').resolve()
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'raw.bin', Path(directory) / 'safe.bin'
            source.write_bytes(raw)
            subprocess.run([sys.executable, str(script), str(source), str(output), '--binary'],
                           check=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(ADTNodeStruct.build(redact_tree(ADTNodeStruct.parse(expected))), expected)


if __name__ == '__main__':
    unittest.main()
