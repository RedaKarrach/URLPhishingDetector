// Runs docs/engine.js on a list of URLs and prints the results as JSON.
// Usage: node tests/web_parity.mjs <model.json> <urls.json>
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const engine = await import(pathToFileURL(resolve(import.meta.dirname, "../docs/engine.js")).href);
engine.init(JSON.parse(readFileSync(process.argv[2], "utf-8")));
const urls = JSON.parse(readFileSync(process.argv[3], "utf-8"));
process.stdout.write(JSON.stringify(urls.map((u) => engine.scan(u))));
