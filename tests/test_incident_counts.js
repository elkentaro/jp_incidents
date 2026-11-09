"use strict";
// Run with node tests/test_incident_counts.js.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../app.js"), "utf8");
const elements = {search: {value: ""}, type: {value: ""}, confidence: {value: ""}, recent: {checked: false}};
const state = {language: "en", updatedAt: "2026-11-09T05:16:13Z", incidents: []};
const context = {elements, state};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf("const copy ="), source.indexOf("const elements =")), context);
vm.runInContext('function text(key) { return copy[state.language][key]; }', context);
vm.runInContext(source.slice(source.indexOf("function tokyoDateKey("), source.indexOf("function renderTrend(")), context);
vm.runInContext(source.slice(source.indexOf("function recentlyChanged("), source.indexOf("function sortValue(")), context);

const row = (id, date, extra = {}) => ({id, published_at: date, organization: "Example", incident_type: "data leak", confidence: "high", ...extra});
state.incidents = [
  row("start", "2026-08-11T15:00:00Z"), // August 12, midnight in Japan.
  row("before", "2026-08-11T14:59:59Z"),
  row("end", "2026-11-09T14:59:59Z", {incident_categories: ["data leak", "ransomware"]}),
  row("after", "2026-11-09T15:00:00Z"),
  row("offset", "2026-11-09T00:00:00+09:00", {confidence: "low"}),
  row("disclosure", "2025-10-15T15:00:00Z", {disclosed_at: "2026-11-09T00:00:00Z"}),
  row("invalid", "invalid"), row("missing", null), row("empty", ""), row("undefined", undefined),
];
const check = (expectedTotal, expectedOutside) => {
  const selected = context.filteredIncidents();
  const trend = context.incidentTrend(selected);
  assert.equal(trend.total, expectedTotal);
  assert.equal(trend.outside, expectedOutside);
  assert.equal(trend.total + trend.outside, selected.length);
  assert.equal(trend.days.length, 90);
  assert.equal(trend.days[0].key, "2026-08-12");
  assert.equal(trend.days[89].key, "2026-11-09");
  return trend;
};
const trend = check(3, 7);
assert.equal(trend.days[0].count, 1);
assert.equal(trend.days[89].count, 2);
elements.type.value = "ransomware";
check(1, 0);
elements.confidence.value = "low";
check(0, 0);
elements.type.value = "";
check(1, 0);
elements.confidence.value = "";
elements.search.value = "no matches";
check(0, 0);
elements.search.value = "";
elements.recent.checked = true;
state.incidents[1].updated_at = new Date(Date.now() - 1000).toISOString();
check(0, 1); // A recent edit does not change the old incident's chart date.
elements.recent.checked = false;
check(3, 7);

// A directory with more than one page contributes all matching rows to the chart.
state.incidents = Array.from({length: 105}, (_, i) => row(String(i), "2026-11-09T00:00:00Z"));
check(105, 0);
console.log("PASS: chart/directory count reconciliation, JST boundaries, old disclosures, invalid dates, multi-tag records, filters, recent edits, empty results and multiple pages");
