import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const directory = new URL("../dist/assets", import.meta.url);
const files = readdirSync(directory).filter((name) => name.endsWith(".js"));
const sizes = files.map((name) => [name, statSync(join(directory.pathname, name)).size]);
const total = sizes.reduce((sum, [, size]) => sum + size, 0);
const maximumChunk = Math.max(...sizes.map(([, size]) => size), 0);
if (total > 700_000 || maximumChunk > 350_000) {
  throw new Error(`bundle bound exceeded: total=${total}, maximumChunk=${maximumChunk}`);
}
console.log(
  `bundle: ${files.length} chunks, ${total} bytes, largest ${maximumChunk} bytes`
);
