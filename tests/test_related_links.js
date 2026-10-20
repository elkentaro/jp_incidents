"use strict";
// Run with node tests/test_related_links.js. No browser or external dependencies.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const source = fs.readFileSync(path.join(__dirname, "../app.js"), "utf8");

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.listeners = {};
    this.textContent = "";
  }
  append(...nodes) { this.children.push(...nodes); }
  setAttribute(key, value) { this.attributes[key] = value; }
  getAttribute(key) { return key === "href" ? this.href : this.attributes[key]; }
  addEventListener(event, callback) { this.listeners[event] = callback; }
  get childElementCount() { return this.children.length; }
  focus() { focused = this.id; }
  scrollIntoView() { scrolled = this.id; }
}
let focused, scrolled, rendered = [];
const state = {
  language: "en", loaded: true, page: 1, sortKey: "organization", sortDirection: "asc",
  incidents: Array.from({length: 102}, (_, i) => ({
    id: `id-${i}`, organization: `Organization ${i}`, published_at: "2026-10-20",
    incident_type: "other", confidence: "high", confidence_score: 80, sources: [], related: [],
  })),
};
state.incidents[0].related = [
  {incident_id: "id-101", relationship: "affected_by"},
  {incident_id: "id-1", relationship: "same_organization"},
  {incident_id: "withdrawn", relationship: "affects"},
];
const elements = {search: {value: "restrictive"}, type: {value: "data leak"}, confidence: {value: "low"}};
const location = {hash: ""};
const history = {pushState(_, __, hash) { location.hash = hash; }};
const handlers = {};
const context = {
  state, elements, location, history, PAGE_SIZE: 100, URL, Intl, Date,
  window: {addEventListener: (name, callback) => { handlers[name] = callback; }},
  document: {
    createElement: tag => new Element(tag),
    createTextNode: text => Object.assign(new Element("#text"), {textContent: text}),
    getElementById: id => rendered.find(row => row.id === id),
  },
  render: () => {
    const all = context.sortedIncidents(state.incidents);
    rendered = all.slice((state.page - 1) * 100, state.page * 100).map(context.incidentRow);
  },
};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf("const copy ="), source.indexOf("const elements =")), context);
vm.runInContext('function text(key) { return copy[state.language][key]; }', context);
vm.runInContext(source.slice(source.indexOf("function formatDate("), source.indexOf("function formatUpdated(")), context);
vm.runInContext(source.slice(source.indexOf("function sortValue("), source.indexOf("function updateSortHeaders(")), context);
vm.runInContext(source.slice(source.indexOf("function safeSourceLink("), source.indexOf("function pageItems(")), context);

const row = context.incidentRow(state.incidents[0]);
const links = row.children[6].children[0].children;
assert.equal(links.length, 2, "Missing/withdrawn destinations must not be rendered");
assert.equal(links[0].textContent, "Related 1");
assert.equal(links[1].textContent, "Related 2");
assert.equal(links[0].title, "Affected through this incident");
assert.equal(links[1].title, "Another incident at the same organization");
assert.equal(links[0].href, "#incident-id-101", "Use the incident ID, not organization name");
let prevented = false;
links[0].listeners.click({button: 0, preventDefault() { prevented = true; }});
assert.ok(prevented);
assert.equal(state.page, 2);
assert.equal(elements.search.value, "");
assert.equal(elements.type.value, "");
assert.equal(elements.confidence.value, "");
assert.equal(focused, "incident-id-101");
assert.equal(scrolled, focused);
state.incidents[101].organization = "Renamed organization";
handlers.hashchange();
assert.equal(focused, "incident-id-101", "Rename must not break the destination");
location.hash = "#incident-id-0";
handlers.popstate();
assert.equal(state.page, 1);
assert.equal(focused, "incident-id-0");
location.hash = "#incident-%invalid";
assert.doesNotThrow(context.showLinkedIncident);
state.language = "ja";
const japanese = context.incidentRow(state.incidents[0]).children[6].children[0].children;
assert.equal(japanese[0].textContent, "関連 1");
assert.equal(japanese[1].textContent, "関連 2");
console.log("PASS: ID links, role labels, missing targets, filters, pagination, rename, hash/back navigation, Japanese");

state.language = "en";
state.incidents[0].incident_categories = ["ransomware", "data leak"];
state.incidents[0].affected_system = "Reservation system";
state.incidents[0].related[0].evidence_urls = ["https://example.org/notice"];
const enhanced = context.incidentRow(state.incidents[0]);
assert.deepEqual(enhanced.children[2].children.map(tag => tag.textContent), ["Ransomware", "Data leak"]);
assert.equal(enhanced.children[1].children[0].textContent, "Reservation system");
assert.equal(enhanced.children[1].children[1].textContent, "Affected organization");
assert.equal(enhanced.children[6].children[1].children[0].textContent, "Why linked?");
vm.runInContext(source.slice(source.indexOf("function filteredIncidents("), source.indexOf("function sortValue(")), context);
elements.search.value = "";
elements.confidence.value = "";
for (const type of ["ransomware", "data leak"]) {
  elements.type.value = type;
  assert.equal(context.filteredIncidents().filter(r => r.id === "id-0").length, 1);
}
elements.type.value = "other";
assert.equal(context.filteredIncidents().length, 101, "Actual other incidents remain filterable");
elements.type.value = "";
assert.equal(context.filteredIncidents().length, 102, "Categories never inflate record count");
state.aliases = {"old-id": "id-101"};
history.replaceState = history.pushState;
location.hash = "#incident-old-id";
context.showLinkedIncident();
assert.equal(location.hash, "#incident-id-101");
assert.equal(focused, "incident-id-101");
state.language = "ja";
assert.equal(context.incidentRow(state.incidents[0]).children[2].children[0].textContent, "ランサムウェア");
console.log("PASS: independent ransomware tags/filters, Other retained, system/role/evidence, alias redirects");
