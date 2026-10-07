// Checks the web page's JavaScript against the files in examples/.
// Run: node tests/web_check.mjs
// It prints one line per file, in the same form as tests/python_check.py,
// so the two outputs can be compared.
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(join(root, "web", "index.html"), "utf8");
const code = html.match(/<script id="kns-core">([\s\S]*?)<\/script>/)[1];
const { parse, deriveKey, decryptBlock, imageType, KnsError } =
  new Function(code + "\nreturn { parse, deriveKey, decryptBlock, imageType, KnsError };")();

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
