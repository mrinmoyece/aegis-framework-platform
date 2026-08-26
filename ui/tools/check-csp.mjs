import { readFileSync, readdirSync } from "node:fs";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
if (/<script(?![^>]*\bsrc=)/i.test(html)) throw new Error("inline script violates CSP");
if (/\son\w+=/i.test(html)) throw new Error("inline event handler violates CSP");
for (const file of readdirSync(new URL("../src", import.meta.url), {
  recursive: true
})) {
  if (typeof file !== "string" || !/\.(ts|tsx)$/.test(file)) continue;
  const source = readFileSync(new URL(`../src/${file}`, import.meta.url), "utf8");
  if (source.includes("dangerouslySetInnerHTML") || /\.innerHTML\s*=/.test(source)) {
    throw new Error(`dangerous HTML sink found in authored source ${file}`);
  }
}
console.log("csp: built HTML has no inline scripts, handlers, or dangerous HTML sink");
