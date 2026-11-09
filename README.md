# Collection of Apple Silicon Device Trees

The format of this repo is

```
MACOS_VERSION/SOC-BOARD.txt
```

ie

```
26.6.2/t8140-j700.txt
```

## Extracting from Graviton (preferred)

With the target running Graviton's proxy mode, run the following on the host
from a full Graviton checkout. Set `M1N1DEVICE` to the target's serial device:

```sh
export M1N1DEVICE=/dev/cu.usbmodemXXXX
cd proxyclient
python3 -m m1n1.adt --retrieve tree.bin
python3 -m m1n1.adt tree.bin > tree.txt
```

This saves the raw boot-time ADT and its decoded text. We highly recommend
redacting the binary before sharing publicly:

```sh
python3 adt-collection/tools/redact.py tree.bin tree.redacted.txt
```

## Extracting From macOS

Dump the running system's device tree with `ioreg`, then convert it to the
collection's text format:

```sh
python3 -m pip install -r tools/requirements.txt
ioreg -p IODeviceTree -l -a -w0 > tree.plist
python3 tools/ioreg2adt.py tree.plist tree.txt
```

Add `--binary` for binary output or `--unredacted` to retain private values and
configuration subtrees.

## Legal

These trees are considered uncopyrightable hardware facts. Accordingly, the
UNLICENSE places these into the public domain.

All scripts in `tools/` are licensed GPL-2.0-or-later; the GPL text is in
`tools/LICENSE.GPL2`.
