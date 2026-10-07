# KNS

A small text file format for password-protected messages and images,
with a command-line tool to write and read `.kns` files and a web page
to read them on any device.

The format is described in [SPEC.md](SPEC.md).

This is a learning project. For anything that really matters, use an
established tool such as Signal or age.

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

## Use

```bash
.venv/bin/python -m kns add chat.kns --from kanishk          # asks for a password and a message
.venv/bin/python -m kns add chat.kns --from kanishk --image photo.jpg
.venv/bin/python -m kns list chat.kns                         # senders and dates, no password
.venv/bin/python -m kns read chat.kns --images saved          # shows messages, saves images
```

One password unlocks a whole file. There is no way to recover a
forgotten password.

## Web reader

`web/index.html` is a single page with no dependencies. It reads a
`.kns` file in the browser and sends nothing anywhere. Browsers only
allow decryption on pages served over https or from localhost.

To publish the current page to GitHub Pages:

```bash
git subtree push --prefix web origin gh-pages
```

## Tests

```bash
.venv/bin/python -m unittest
node tests/web_check.mjs        # the web page's code against examples/
```

The files in `examples/` use the password `example-password`.
