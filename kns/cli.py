"""The command-line tool. Run it as: python -m kns add|read|list FILE"""
from __future__ import annotations

import argparse
import datetime
import getpass
import os
import re
import sys
from pathlib import Path

from .crypto import CryptoError, decrypt_block, derive_key, encrypt_block, new_file_header
from .format import KnsError, KnsFile, check_image_name, parse, serialize, serialize_block


def ask_password(confirm=False):
    password = os.environ.get("KNS_PASSWORD")  # for scripts and tests
    if password is None:
        password = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Repeat password: ") != password:
            raise CryptoError("the two passwords do not match")
    if not password:
        raise CryptoError("the password cannot be empty")
    return password


def ask_message():
    if sys.stdin.isatty():
        return input("Message: ")
    return sys.stdin.read().rstrip("\n")


def label(index, block):
    sender = block.header.get("from", "unknown sender")
    date = block.header.get("date", "no date")
    return f"[{index}] {sender}, {date}"


def image_name_from(path):
    """A file name that is safe to store, made from the image's own name."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", path.name).lstrip(".")
    check_image_name(name)
    return name


def save_image(folder, index, name, data):
    if folder is None:
        return f"(image: {name}, {len(data)} bytes. Add --images FOLDER to save it)"
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"{index}-{name}"
    try:
        with target.open("xb") as file:  # "x" refuses to overwrite an existing file
            file.write(data)
    except FileExistsError:
        return f"(image not saved: {target} already exists)"
    return f"(image saved to {target})"


def cmd_add(args):
    kind, name, content = "text", None, None
    if args.image:
        image = Path(args.image)
        kind, name, content = "image", image_name_from(image), image.read_bytes()
        if not content:
            raise CryptoError("the image file is empty")

    path = Path(args.file)
    if path.exists():
        old_text = path.read_text(encoding="utf-8")
        kns = parse(old_text)
        key = derive_key(ask_password(), kns.header)
        if kns.blocks:
            decrypt_block(key, 1, kns.blocks[0])  # fails if this is not the file's password
    else:
        old_text = None
        kns = KnsFile(header=new_file_header())
        key = derive_key(ask_password(confirm=True), kns.header)

    if content is None:
        message = args.message if args.message is not None else ask_message()
        if not message.strip():
            raise CryptoError("the message is empty")
        content = message.encode("utf-8")

    index = len(kns.blocks) + 1
    date = args.date or datetime.date.today().isoformat()
    block = encrypt_block(key, index, content, type=kind, sender=args.sender, date=date, name=name)

    if old_text is None:
        kns.blocks.append(block)
        path.write_text(serialize(kns), encoding="utf-8")
    else:
        # Append instead of rewriting, so the existing text stays untouched.
        gap = "\n" if old_text.endswith("\n") else "\n\n"
        with path.open("a", encoding="utf-8") as file:
            file.write(gap + serialize_block(block))
    print(f"Added message {index} to {path}")


def cmd_read(args):
    kns = parse(Path(args.file).read_text(encoding="utf-8"))
    if not kns.blocks:
        print("No messages.")
        return
    key = derive_key(ask_password(), kns.header)
    for index, block in enumerate(kns.blocks, start=1):
        kind = block.header["type"]
        if kind == "text":
            body = decrypt_block(key, index, block).decode("utf-8")
        elif kind == "image":
            name = block.header.get("name")
            check_image_name(name)
            body = save_image(args.images, index, name, decrypt_block(key, index, block))
        else:
            body = f"(skipped: this version cannot show type '{kind}')"
        print(f"{label(index, block)}\n{body}\n")


def cmd_list(args):
    kns = parse(Path(args.file).read_text(encoding="utf-8"))
    for index, block in enumerate(kns.blocks, start=1):
        kind = block.header["type"]
        if "name" in block.header:
            kind += f": {block.header['name']}"
        print(f"{label(index, block)} ({kind})")
    print(f"{len(kns.blocks)} message(s)")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kns", description="Create and read encrypted .kns message files.")
    commands = parser.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="add a message, creating the file if it does not exist")
    add.add_argument("file")
    add.add_argument("--from", dest="sender", help="sender name, readable without the password")
    add.add_argument("--date", help="defaults to today")
    content = add.add_mutually_exclusive_group()
    content.add_argument("-m", "--message", help="the message text. If left out, you are asked for it")
    content.add_argument("--image", metavar="PATH", help="add an image file instead of text")
    add.set_defaults(run=cmd_add)

    read = commands.add_parser("read", help="decrypt and show the messages")
    read.add_argument("file")
    read.add_argument("--images", metavar="FOLDER", help="save decrypted images into this folder")
    read.set_defaults(run=cmd_read)

    list_ = commands.add_parser("list", help="show senders and dates, no password needed")
    list_.add_argument("file")
    list_.set_defaults(run=cmd_list)

    args = parser.parse_args(argv)
    try:
        args.run(args)
    except (KnsError, CryptoError, OSError, UnicodeDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0
