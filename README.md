# KNS

A small text file format for password-protected messages and images,
with a command-line tool and a web page that both write and read `.kns`
files. The page works on any device with nothing to install:
https://kanishksingh3012.github.io/kns-format/

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

## Web page

`web/index.html` is a single page with no dependencies. It reads and
writes `.kns` files in the browser and sends nothing anywhere. A short
file can also be sent as a link that opens straight in the page; the
file travels after the `#`, which browsers do not send to the server.
Its look follows HeroUI's default theme, in plain CSS. Browsers only
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
