"""Rebuild the files in examples/. Run: .venv/bin/python make_examples.py

The valid files are really encrypted, with the password below. Each
invalid file is a valid one with exactly one thing broken.
"""
import struct
import zlib
from pathlib import Path

from kns.crypto import derive_key, encrypt_block, new_file_header
from kns.format import KnsFile, serialize

PASSWORD = "example-password"
OUT = Path(__file__).parent / "examples"
MESSAGES = [
    ("kanishk", "2026-10-07", "Meet at 6pm"),
    ("asha", "2026-10-08", "See you there 😀"),
    ("kanishk", "2026-10-08", "This one is long on purpose, so that its payload is wrapped over "
                              "several lines in the file and the parser has to join them again."),
]


def tiny_png(size=48, colour=(47, 93, 80)):
    """A real PNG file: a plain square of one colour."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    row = b"\x00" + bytes(colour) * size
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(row * size))
            + chunk(b"IEND", b""))


def build(messages, image=None):
    """Encrypt the text messages, then one image block if `image` is given."""
    kns = KnsFile(header=new_file_header())
    key = derive_key(PASSWORD, kns.header)
    for index, (sender, date, text) in enumerate(messages, start=1):
        kns.blocks.append(encrypt_block(key, index, text.encode("utf-8"), sender=sender, date=date))
    if image:
        kns.blocks.append(encrypt_block(key, len(kns.blocks) + 1, image, type="image",
                                        sender="asha", date="2026-10-09", name="square.png"))
    return serialize(kns)


def without_line(text, start, count=1):
    """Remove `count` lines, beginning at the first line that starts with `start`."""
    lines = text.split("\n")
    at = next(i for i, line in enumerate(lines) if line.startswith(start))
    del lines[at:at + count]
    return "\n".join(lines)


def with_extra_line(text, extra):
    return text.replace("from: kanishk\n", f"from: kanishk\n{extra}\n", 1)


one, two, three = build(MESSAGES[:1]), build(MESSAGES[:2]), build(MESSAGES)
nonces = [line for line in two.split("\n") if line.startswith("nonce:")]

files = {
    "valid_no_messages": build([]),
    "valid_one_message": one,
    "valid_three_messages": three.replace("\n[message]", "\n# a short conversation\n\n[message]", 1),
    "valid_with_image": build(MESSAGES[:1], image=tiny_png()),
    "invalid_no_magic": without_line(one, "#KNS"),
    "invalid_missing_salt": without_line(one, "salt:"),
    "invalid_missing_iterations": without_line(one, "iterations:"),
    "invalid_duplicate_key": with_extra_line(one, "from: someone else"),
    "invalid_bad_key": with_extra_line(one, "Sent By: kanishk"),
    "invalid_no_colon": with_extra_line(one, "this line has no colon"),
    "invalid_no_separator": without_line(two, "---", count=2),
    "invalid_missing_nonce": without_line(one, "nonce:"),
    "invalid_missing_type": without_line(one, "type:"),
    "invalid_empty_payload": without_line(two, "---", count=2).replace(nonces[0], nonces[0] + "\n---", 1),
    "invalid_repeated_nonce": two.replace(nonces[1], nonces[0]),
}

for old in OUT.glob("*.kns"):
    old.unlink()
for name, text in files.items():
    (OUT / f"{name}.kns").write_text(text, encoding="utf-8")
print(f"Wrote {len(files)} files to {OUT}")
