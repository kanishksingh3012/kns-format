// Checks the web page's JavaScript against the files in examples/.
// Run: node tests/web_check.mjs
// It prints one line per file, in the same form as tests/python_check.py,
// so the two outputs can be compared.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(join(root, "web", "index.html"), "utf8");
const code = html.match(/<script id="kns-core">([\s\S]*?)<\/script>/)[1];
const core = new Function(code + "\nreturn { parse, deriveKey, decryptBlock, imageType, KnsError, " +
  "newFileHeader, encryptBlock, serializeFileHeader, appendBlock, imageNameFrom };")();
const { parse, deriveKey, decryptBlock, imageType, KnsError } = core;

// Writing: make a new file, and add to one the Python tool made, then read both back.
// With a folder as argument, the two files are also saved there for the Python tool to read.
{
  const { newFileHeader, encryptBlock, serializeFileHeader, appendBlock, imageNameFrom } = core;
  const picture = Uint8Array.from({ length: 70000 }, (_, i) => (i * 7) % 256);
  if (imageNameFrom(".my photo (1).PNG") !== "my_photo__1_.PNG") throw new Error("imageNameFrom is wrong");

  const header = newFileHeader();
  let key = await deriveKey("example-password", header);
  let fresh = serializeFileHeader(header);
  fresh = appendBlock(fresh, await encryptBlock(key, 1, new TextEncoder().encode("written in the browser 😀"),
    { type: "text", from: "  asha \t", date: "2026-10-10" }));
  fresh = appendBlock(fresh, await encryptBlock(key, 2, picture,
    { type: "image", from: "asha", date: "2026-10-10", name: "pic.png" }));

  const old = readFileSync(join(root, "examples", "valid_three_messages.kns"), "utf8");
  const oldKns = parse(old);
  key = await deriveKey("example-password", oldKns.header);
  const added = appendBlock(old, await encryptBlock(key, oldKns.blocks.length + 1,
    new TextEncoder().encode("a reply from the browser"), { type: "text", from: "asha", date: "2026-10-10" }));
  if (!added.startsWith(old)) throw new Error("adding a message changed the existing text");

  for (const [text, count] of [[fresh, 2], [added, 4]]) {
    const kns = parse(text);
    if (kns.blocks.length !== count) throw new Error("wrong number of messages after writing");
    const k = await deriveKey("example-password", kns.header);
    for (let i = 0; i < count; i++) await decryptBlock(k, i + 1, kns.blocks[i]);
  }
  if (parse(fresh).blocks[0].header.get("from") !== "asha") throw new Error("sender was not trimmed");

  if (process.argv[2]) {
    writeFileSync(join(process.argv[2], "web_new.kns"), fresh);
    writeFileSync(join(process.argv[2], "web_added.kns"), added);
  }
}

// The same names must be accepted or refused by kns.format.check_image_name.
const names = { "photo.jpg": true, "IMG_1234.JPEG": true, "a-b.c.webp": true, "../x.png": false,
  "a/b.png": false, ".hidden.png": false, "photo.svg": false, "png": false, "": false,
  "has space.png": false, ["a".repeat(97) + ".png"]: false, ["a".repeat(96) + ".png"]: true };
for (const [name, good] of Object.entries(names)) {
  let accepted = true;
  try { imageType(name); } catch (error) { accepted = false; }
  if (accepted !== good) throw new Error(`image name '${name}' should be ${good ? "accepted" : "refused"}`);
}

let failed = false;
for (const name of readdirSync(join(root, "examples")).filter((n) => n.endsWith(".kns")).sort()) {
  const text = readFileSync(join(root, "examples", name), "utf8");
  let result;
  try {
    const kns = parse(text);
    const key = await deriveKey("example-password", kns.header);
    const texts = [];
    for (let i = 0; i < kns.blocks.length; i++) {
      const block = kns.blocks[i];
      if (block.header.get("type") === "image") {
        imageType(block.header.get("name"));
        const data = await decryptBlock(key, i + 1, block);
        const hash = Buffer.from(await crypto.subtle.digest("SHA-256", data)).toString("hex");
        texts.push(`<image ${block.header.get("name")} ${data.length} bytes ${hash}>`);
      } else {
        texts.push(new TextDecoder().decode(await decryptBlock(key, i + 1, block)));
      }
    }
    result = "OK " + JSON.stringify(texts);
    if (name.startsWith("invalid_")) failed = true;
  } catch (error) {
    if (!(error instanceof KnsError)) throw error;
    result = "ERROR " + error.message;
    if (name.startsWith("valid_")) failed = true;
  }
  console.log(`${name} -> ${result}`);
}
process.exit(failed ? 1 : 0);
