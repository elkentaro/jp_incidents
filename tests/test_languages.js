"use strict";
// Run with node tests/test_languages.js. Checks translation coverage without a browser.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.join(__dirname, "..");
function checkShape(reference, translated, label) {
  assert.deepEqual(Object.keys(translated).sort(), Object.keys(reference).sort(), label);
  for (const key of Object.keys(reference)) {
    assert.equal(typeof translated[key], typeof reference[key], `${label}.${key}`);
    if (typeof reference[key] === "object") checkShape(reference[key], translated[key], `${label}.${key}`);
    if (typeof reference[key] === "string") assert.ok(translated[key].trim(), `${label}.${key} is empty`);
    if (typeof reference[key] === "function") {
      const result = translated[key](12345, 67890);
      assert.equal(typeof result, "string");
      assert.ok(!result.includes("undefined"), `${label}.${key}`);
    }
  }
}
for (const [script, html] of [["app.js", "index.html"], ["sources.js", "sources.html"], ["supporters.js", "supporters.html"]]) {
  const source = fs.readFileSync(path.join(root, script), "utf8");
  const end = source.indexOf(script === "supporters.js" ? "let saved;" : "const elements =");
  const copy = vm.runInNewContext(source.slice(source.indexOf("const copy ="), end) + "\ncopy;");
  for (const language of ["en", "ja", "es"]) {
    checkShape(copy.en, copy[language], `${script}:${language}`);
    const markup = fs.readFileSync(path.join(root, html), "utf8");
    for (const [, key] of markup.matchAll(/data-i18n(?:-placeholder|-aria)?="([^"]+)"/g)) {
      assert.equal(typeof copy[language][key], "string", `${html}:${language}:${key}`);
    }
  }
  if (script !== "supporters.js") {
    for (const saved of ["en", "ja", "es", "invalid", "", null]) {
      const selected = vm.runInNewContext(source.slice(0, source.indexOf("function replaceContent")) + "savedLanguage();", {localStorage: {getItem: () => saved}});
      assert.equal(selected, ["en", "ja", "es"].includes(saved) ? saved : null);
    }
  }
}
console.log("PASS: English/Japanese/Spanish translation parity, markup keys, dynamic copy, stored language validation");
