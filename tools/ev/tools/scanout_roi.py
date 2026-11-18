#!/usr/bin/env python3
"""Read-only ROI extraction from actual owned QMP PNG; no image synthesis/edit."""
import json
import hashlib
from pathlib import Path
import sys
import signal
signal.alarm(2)
from PIL import Image

path = Path(sys.argv[1])
mode = sys.argv[2]
if mode == "label":
    if len(sys.argv) != 6:
        raise SystemExit("label ROI argument count refused")
    rx, ry, length = map(int, sys.argv[3:6])
    if not 1 <= length <= 60 or not 0 <= rx <= 640 - (length + 1) * 6 or not 0 <= ry <= 473:
        raise SystemExit("label ROI bounds refused")
elif mode == "binding":
    if len(sys.argv) != 3:
        raise SystemExit("binding ROI argument count refused")
else:
    if len(sys.argv) != 5:
        raise SystemExit("pane ROI argument count refused")
    pane, row, length = map(int, sys.argv[2:5])
    if pane not in (0, 1, 2) or row not in range(-1, 8) or not 0 <= length <= 48:
        raise SystemExit("ROI bounds refused")
with Image.open(path) as image:
    if image.format != "PNG" or not 640 <= image.width <= 4096 or not 480 <= image.height <= 4096:
        raise SystemExit("actual scanout geometry refused")
    x, y = (image.width - 640) // 2, (image.height - 480) // 2
    rgb = image.convert("RGB")
    if mode == "label":
        label = rgb.crop((x + rx, y + ry, x + rx + (length + 1) * 6, y + ry + 7)).tobytes()
        print(json.dumps({"width": image.width, "height": image.height, "label": label.hex()}))
        raise SystemExit(0)
    if mode == "binding":
        # Root title/nonce, exact object/recipient, and selected name. This
        # compares actual pixels only; it cannot attest a protected scope.
        binding = rgb.crop((x + 2, y + 11, x + 640, y + 38)).tobytes()
        print(json.dumps({"width": image.width, "height": image.height, "binding_sha256": hashlib.sha256(binding).hexdigest()}))
        raise SystemExit(0)
    if pane != 2:
        x, y = x + pane * 320, y + 91
    # Root selected factory geometry at scale1; this is a visual wait heuristic,
    # not a protected-wire query, trusted presentation or consent receipt.
    sy, sw = (11, 384) if pane == 2 else (172, 120)
    status = rgb.crop((x + 2, y + sy, x + 2 + sw, y + sy + 7)).tobytes()
    nx, ny = (14, 69 + row * 10) if pane == 0 else ((4, 25) if pane == 1 else (2, 31))
    name = rgb.crop((x + nx, y + ny, x + nx + (length + 1) * 6, y + ny + 7)).tobytes()
    rights = rgb.crop((x + 152, y + 71, x + 218, y + 78)).tobytes() if pane == 2 else b""
    print(json.dumps({"width": image.width, "height": image.height, "status": status.hex(), "name": name.hex(), "rights": rights.hex()}))
