"""Prints one line per example file, in the same form as tests/web_check.mjs.

Run: .venv/bin/python tests/python_check.py
If the two outputs are identical, the Python tool and the web page agree.
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from kns.crypto import CryptoError, decrypt_block, derive_key  # noqa: E402
from kns.format import KnsError, check_image_name, parse  # noqa: E402

for path in sorted((Path(__file__).parent.parent / "examples").glob("*.kns")):
    try:
        kns = parse(path.read_text(encoding="utf-8"))
        key = derive_key("example-password", kns.header)
        texts = []
        for i, block in enumerate(kns.blocks, start=1):
            if block.header["type"] == "image":
                check_image_name(block.header.get("name"))
                data = decrypt_block(key, i, block)
                texts.append(f"<image {block.header['name']} {len(data)} bytes {hashlib.sha256(data).hexdigest()}>")
            else:
                texts.append(decrypt_block(key, i, block).decode("utf-8"))
        result = "OK " + json.dumps(texts, ensure_ascii=False, separators=(",", ":"))
    except (KnsError, CryptoError) as error:
        result = f"ERROR {error}"
    print(f"{path.name} -> {result}")
