"use strict";
// Run with node tests/test_recent_filter.js.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../app.js"), "utf8");
const now = Date.parse("2026-10-24T12:00:00Z");
const elements = {search: {value: ""}, type: {value: ""}, confidence: {value: ""}, recent: {checked: true}};
const context = {Date: {now: () => now, parse: Date.parse}, elements,
  state: {language: "en", incidents: []}};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf("const copy ="), source.indexOf("const elements =")), context);
vm.runInContext('function text(key) { return copy[state.language][key]; }', context);
vm.runInContext(source.slice(source.indexOf("function recentlyChanged("), source.indexOf("function sortValue(")), context);
for (const [row, expected] of [
  [{added_at: "2026-10-24T11:00:00Z", published_at: "2020-01-01"}, true],
  [{added_at: "2020-01-01T00:00:00Z", updated_at: "2026-10-24T12:00:00Z"}, true],
  [{updated_at: "2026-10-23T12:00:00.001Z"}, true],
  [{updated_at: "2026-10-23T12:00:00Z"}, false],
  [{updated_at: "2026-10-24T12:00:00.001Z"}, false],
  [{updated_at: "2026-10-24T20:59:59+09:00"}, true],
  [{updated_at: "invalid", added_at: null, published_at: "2026-10-24"}, false],
  [{updated_at: "2026-10-24"}, false], [{}, false],
]) assert.equal(context.recentlyChanged(row), expected, JSON.stringify(row));
context.state.incidents = [
  {id: "new", added_at: "2026-10-24T01:00:00Z", organization: "Example", incident_type: "data leak", confidence: "high"},
  {id: "updated", added_at: "2020-01-01T00:00:00Z", updated_at: "2026-10-24T00:00:00Z", organization: "Other", incident_type: "ransomware", confidence: "low"},
  {id: "old", updated_at: "2026-10-22T00:00:00Z", organization: "Example", incident_type: "data leak", confidence: "high"},
];
const ids = () => Array.from(context.filteredIncidents(), row => row.id);
assert.deepEqual(ids(), ["new", "updated"]);
elements.search.value = "example";
assert.deepEqual(ids(), ["new"]);
elements.search.value = ""; elements.type.value = "ransomware";
assert.deepEqual(ids(), ["updated"]);
elements.confidence.value = "high";
assert.deepEqual(ids(), []);
elements.type.value = "";
assert.deepEqual(ids(), ["new"]);
elements.recent.checked = false;
assert.deepEqual(ids(), ["new", "old"]);
console.log("PASS: additions/updates, exact rolling cutoff, offsets, future/missing/invalid timestamps, combined search/type/confidence filters and unchecked state");
