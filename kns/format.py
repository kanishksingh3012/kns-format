"""Read and write the text structure of .kns files. See SPEC.md.

This module knows nothing about passwords or encryption. It only turns
text into a KnsFile and a KnsFile back into text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAGIC = "#KNS v1"
BLOCK_START = "[message]"
SEPARATOR = "---"
FILE_REQUIRED = ("cipher", "kdf", "iterations", "salt")
BLOCK_REQUIRED = ("type", "nonce")
KEY_PATTERN = re.compile(r"[a-z0-9_]+")
WRAP = 64  # payload characters per line when writing
IMAGE_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}")
IMAGE_ENDINGS = (".png", ".jpg", ".jpeg", ".gif", ".webp")


class KnsError(Exception):
    """The text is not a valid .kns file."""

    def __init__(self, message, line=None):
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass
class Block:
    header: dict[str, str]
    payload: str = ""  # base64 text, with line breaks removed
    line: int = field(default=0, compare=False)  # where its [message] line was


@dataclass
class KnsFile:
    header: dict[str, str]
    blocks: list[Block] = field(default_factory=list)


def parse(text: str) -> KnsFile:
    lines = [line.strip() for line in text.splitlines()]
    if not lines or lines[0] != MAGIC:
        raise KnsError(f"missing or wrong magic line, expected '{MAGIC}'", 1)

    kns = KnsFile(header={})
    block = None  # the block being read. None while still in the file header
    in_payload = False
    payload_lines = []  # joined once per block, which stays fast for large images

    for number, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        if line == BLOCK_START:
            _finish(kns, block, in_payload, payload_lines)
            block = Block(header={}, line=number)
            in_payload = False
            payload_lines = []
        elif in_payload:
            payload_lines.append(line)
        elif line.startswith("#"):
            continue
        elif line == SEPARATOR and block is not None:
            in_payload = True
        else:
            header = kns.header if block is None else block.header
            _read_header_line(line, number, header)

    _finish(kns, block, in_payload, payload_lines)
    return kns


def _read_header_line(line, number, header):
    if ":" not in line:
        raise KnsError("expected 'key: value'", number)
    key, value = (part.strip() for part in line.split(":", 1))
    if not KEY_PATTERN.fullmatch(key):
        raise KnsError(f"invalid key '{key}', only a-z, 0-9 and _ are allowed", number)
    if key in header:
        raise KnsError(f"duplicate key '{key}'", number)
    header[key] = value


def _finish(kns, block, in_payload, payload_lines):
    """Check the section that just ended: the file header, or one block."""
    if block is None:
        for key in FILE_REQUIRED:
            if key not in kns.header:
                raise KnsError(f"missing required file header field '{key}'")
        return

    if not in_payload:
        raise KnsError(f"message has no '{SEPARATOR}' separator", block.line)
    for key in BLOCK_REQUIRED:
        if key not in block.header:
            raise KnsError(f"missing required field '{key}'", block.line)
    block.payload = "".join(payload_lines)
    if not block.payload:
        raise KnsError("empty payload", block.line)
    if any(other.header["nonce"] == block.header["nonce"] for other in kns.blocks):
        raise KnsError("same nonce as an earlier message", block.line)
    kns.blocks.append(block)


def check_image_name(name):
    """Raise KnsError unless name is a plain, safe image file name."""
    name = name or ""
    if not IMAGE_NAME.fullmatch(name) or not name.lower().endswith(IMAGE_ENDINGS):
        raise KnsError("image name must use only letters, digits, . _ - and end in .png, .jpg, .jpeg, .gif or .webp")


def serialize_block(block: Block) -> str:
    out = [BLOCK_START]
    out += [f"{key}: {value}" for key, value in block.header.items()]
    out.append(SEPARATOR)
    out += [block.payload[i:i + WRAP] for i in range(0, len(block.payload), WRAP)]
    return "\n".join(out) + "\n"


def serialize(kns: KnsFile) -> str:
    out = [MAGIC]
    out += [f"{key}: {value}" for key, value in kns.header.items()]
    head = "\n".join(out) + "\n"
    return head + "".join("\n" + serialize_block(block) for block in kns.blocks)
