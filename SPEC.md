# KNS file format, version 1

A `.kns` file is a plain-text container for one or more encrypted
messages. One password unlocks every message in the file. Who sent each
message and when is readable by anyone. The message content is not.

## Structure

A file has a magic line, a file header, and then zero or more blocks.
Each block is one message.

```
#KNS v1
cipher: aes-256-gcm
kdf: pbkdf2-sha256
iterations: 600000
salt: <base64>

[message]
type: text
from: kanishk
date: 2026-10-07
nonce: <base64>
---
<base64 ciphertext>

[message]
type: text
from: asha
date: 2026-10-08
nonce: <base64>
---
<base64 ciphertext>
```

1. **Magic line**: the first line, exactly `#KNS v1`
2. **File header**: `key: value` lines that apply to the whole file
3. **Blocks**: each one is
   - a line that is exactly `[message]`
   - a **block header** of `key: value` lines
   - a separator line that is exactly `---`
   - the **payload**: the encrypted content in base64, on one or more lines

## Rules

1. The file is UTF-8 text with `\n` line endings.
2. Line 1 must be exactly `#KNS v1`.
3. A header line is split on its first `:`. The left side is the key,
   the right side is the value. Spaces around both are removed.
4. Keys may contain only `a-z`, `0-9` and `_`.
5. In a header, lines starting with `#` are comments and are ignored.
6. Blank lines are ignored everywhere, and so are spaces at the start
   or end of any line.
7. A key may appear only once in the file header, and only once in any
   one block header. Two different blocks may use the same key.
8. Unknown keys are kept but not checked, so later versions can add fields.
9. The file header ends at the first `[message]` line or the end of the file.
10. A block header ends at the first line that is exactly `---`.
11. A payload ends at the next `[message]` line or the end of the file.
    Its lines are joined together before decoding, so a long payload may
    be wrapped across many lines.
12. Blocks are kept in the order they appear in the file.

Base64 never contains `[`, `]` or `-`, so a payload line can never be
mistaken for a `[message]` or `---` line.

## File header fields

| Key          | Required | Meaning                                                |
|--------------|----------|--------------------------------------------------------|
| `cipher`     | yes      | Encryption method. v1 allows only `aes-256-gcm`        |
| `kdf`        | yes      | Password-to-key method. v1 allows only `pbkdf2-sha256` |
| `iterations` | yes      | How many rounds the kdf runs. 600000 recommended       |
| `salt`       | yes      | 16 random bytes, base64                                |

## Block header fields

| Key     | Required | Meaning                                              |
|---------|----------|------------------------------------------------------|
| `type`  | yes      | What the payload holds: `text` or `image`            |
| `nonce` | yes      | 12 random bytes, base64. Must differ for every block |
| `from`  | no       | Sender, free text                                    |
| `date`  | no       | Free text, `YYYY-MM-DD` recommended                  |
| `name`  | images   | The image's file name, for example `photo.jpg`       |

A parser must still read a block whose type it does not know, and leave
it to the caller to skip it.

An image `name` is 1 to 100 characters from `A-Z a-z 0-9 . _ -`, does
not start with `.`, and ends in `.png`, `.jpg`, `.jpeg`, `.gif` or
`.webp` (in any letter case). It is never a path. A reader must refuse
to open an image block whose name breaks this rule.

Everything in the headers is public. Only payloads are secret.

## Errors

A parser must reject the file, with the line number where one applies, when:

- the magic line is missing or wrong
- a header line has no `:`
- a key contains characters outside `a-z`, `0-9`, `_`
- a key appears twice in the same header
- a required file header field is missing
- a required block header field is missing
- a block has no `---` separator
- a block's payload is empty
- two blocks have the same nonce

A file with a valid file header and no blocks is valid. It holds no messages.

## Encryption

The key is 32 bytes, made from the password (as UTF-8) and the salt
with PBKDF2-HMAC-SHA256, run `iterations` times.

Each payload is the message content encrypted with AES-256-GCM, using
the key and that block's nonce. The payload holds the ciphertext
followed by the 16-byte GCM tag, in base64.

For a `text` block, the content is the message as UTF-8. For an
`image` block, the content is the bytes of the image file, unchanged.

### Tamper protection

Each block is locked to its position and its public fields. When
encrypting or decrypting block number N (the first block is 1), the
"associated data" given to AES-GCM is the UTF-8 form of these five
lines joined by `\n`:

```
KNS1
<N>
<type>
<from, or empty if absent>
<date, or empty if absent>
```

If the block has a `name`, it is added as a sixth line.

Decryption then fails if a payload, `type`, `from`, `date` or `name`
was edited, or if blocks were reordered or removed from the middle.

Removing blocks from the end of a file cannot be detected.

### Checked at decryption time

These are not parse errors. A file can be well formed and still fail here:

- `cipher` or `kdf` is not one this version supports
- `iterations` is not a whole number from 1 to 10000000
- `salt`, `nonce` or a payload is not valid base64, or has the wrong length
- the password is wrong, or the file was tampered with

## Examples

See `examples/`. Files named `valid_*.kns` must parse. Files named
`invalid_*.kns` must be rejected, each for one specific reason.

The valid files are really encrypted. Their password is
`example-password`, so any implementation can be checked against them.
`make_examples.py` rebuilds the whole folder.
