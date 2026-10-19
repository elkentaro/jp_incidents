"use strict";

const PAGE_SIZE = 100;

function savedLanguage() {
  try {
    return localStorage.getItem("jp-incidents-language");
  } catch (_) {
    return null;
  }
}

function replaceContent(node, children) {
  while (node.firstChild) node.removeChild(node.firstChild);
  children.forEach((child) => node.appendChild(child));
}

const copy = {
  en: {
    eyebrow: "OPEN-SOURCE INCIDENT INDEX",
    title: "Cyber incidents in Japan",
    description: "Publicly reported cybersecurity incidents affecting Japanese organizations, collected from news, security publications, and official notices.",
    disclaimer: "This index is collected automatically and analyzed with AI. It may contain omissions or errors and should not be regarded as a complete or authoritative record. Verify details with the linked sources.",
    totalIncidents: "Total incidents",
    lastUpdated: "Data updated",
    nextPlannedUpdate: (date) => `Next planned update: ${date}`,
    coverage: "Coverage",
    trendTitle: "90-day incident trend",
    trendCount: (count, peak) => `${count.toLocaleString("en-US")} reported · peak ${peak.toLocaleString("en-US")}/day`,
    trendAria: (total, peak) => `Daily incident counts for the last 90 days. ${total} incidents total; highest daily count ${peak}.`,
    directoryTitle: "Incident directory",
    reset: "Reset filters",
    searchLabel: "Search organizations or sources",
    searchPlaceholder: "Search…",
    typeLabel: "Incident type",
    confidenceLabel: "Confidence",
    date: "Date",
    organization: "Organization",
    incidentType: "Incident type",
    potentialRecords: "Potential records",
    confidence: "Confidence",
    sources: "Sources",
    noResults: "No incidents match these filters.",
    loading: "Loading incident data…",
    loadErrorTitle: "The incident data could not be loaded.",
    loadErrorBody: "Please refresh the page or try again later.",
    paginationLabel: "Incident pages",
    methodNote: "Automated collection from public sources. Confidence reflects source quality, not incident severity.",
    viewSource: "View project on GitHub",
    sourceDirectory: "Sources",
    rssFeed: "RSS feed",
    allTypes: "All incident types",
    allConfidence: "All confidence levels",
    results: (shown, total) => `${shown.toLocaleString("en-US")} of ${total.toLocaleString("en-US")} incidents`,
    page: (page, pages) => `Page ${page} of ${pages}`,
    previous: "Previous",
    next: "Next",
    switchLanguage: "日本語に切り替える",
    sortAscending: (label) => `Sort by ${label}, ascending`,
    sortDescending: (label) => `Sort by ${label}, descending`,
    unknown: "Not stated",
    types: { "data leak": "Data leak", "unauthorized access": "Unauthorized access", other: "Other" },
    levels: { high: "High", medium: "Medium", low: "Low" }
  },
  ja: {
    eyebrow: "公開情報に基づくインシデント一覧",
    title: "日本のサイバーインシデント",
    description: "ニュース、セキュリティ専門メディア、公式発表から収集した、日本の組織に影響する公表済みサイバーインシデントです。",
    disclaimer: "本一覧は公開情報を自動収集し、AIを用いて分析しています。情報の欠落や誤りが含まれる可能性があり、完全または権威ある記録として扱わないでください。詳細はリンク先の情報源でご確認ください。",
    totalIncidents: "インシデント総数",
    lastUpdated: "データ更新日時",
    nextPlannedUpdate: (date) => `次回更新予定：${date}`,
    coverage: "収録期間",
    trendTitle: "過去90日間のインシデント推移",
    trendCount: (count, peak) => `${count.toLocaleString("ja-JP")}件 · 最大${peak.toLocaleString("ja-JP")}件/日`,
    trendAria: (total, peak) => `過去90日間の日別インシデント件数。合計${total}件、1日の最大件数${peak}件。`,
    directoryTitle: "インシデント一覧",
    reset: "絞り込みを解除",
    searchLabel: "組織名・情報源を検索",
    searchPlaceholder: "検索…",
    typeLabel: "インシデント種別",
    confidenceLabel: "信頼度",
    date: "日付",
    organization: "組織",
    incidentType: "インシデント種別",
    potentialRecords: "影響の可能性がある件数",
    confidence: "信頼度",
    sources: "情報源",
    noResults: "条件に一致するインシデントはありません。",
    loading: "インシデントデータを読み込んでいます…",
    loadErrorTitle: "インシデントデータを読み込めませんでした。",
    loadErrorBody: "ページを再読み込みするか、しばらくしてからお試しください。",
    paginationLabel: "インシデントのページ",
    methodNote: "公開情報から自動収集しています。信頼度は情報源の品質を示すもので、被害の深刻度ではありません。",
    viewSource: "GitHubでプロジェクトを見る",
    sourceDirectory: "情報源一覧",
    rssFeed: "RSSフィード",
    allTypes: "すべての種別",
    allConfidence: "すべての信頼度",
    results: (shown, total) => `${total.toLocaleString("ja-JP")}件中 ${shown.toLocaleString("ja-JP")}件`,
    page: (page, pages) => `${pages}ページ中 ${page}ページ`,
    previous: "前へ",
    next: "次へ",
    switchLanguage: "Switch to English",
    sortAscending: (label) => `${label}を昇順で並べ替え`,
    sortDescending: (label) => `${label}を降順で並べ替え`,
    unknown: "記載なし",
    types: { "data leak": "情報漏えい", "unauthorized access": "不正アクセス", other: "その他" },
    levels: { high: "高", medium: "中", low: "低" }
  }
};

const elements = {
  language: document.querySelector("#language-switch"),
  total: document.querySelector("#total-count"),
  updated: document.querySelector("#updated-at"),
  nextUpdate: document.querySelector("#next-update-at"),
  coverage: document.querySelector("#coverage-range"),
  trend: document.querySelector("#trend-chart"),
  trendTotal: document.querySelector("#trend-total"),
  trendStart: document.querySelector("#trend-start"),
  trendEnd: document.querySelector("#trend-end"),
  results: document.querySelector("#result-count"),
  search: document.querySelector("#search"),
  type: document.querySelector("#type-filter"),
  confidence: document.querySelector("#confidence-filter"),
  reset: document.querySelector("#reset-filters"),
  rows: document.querySelector("#incident-rows"),
  loading: document.querySelector("#loading-state"),
  error: document.querySelector("#error-state"),
  empty: document.querySelector("#empty-state"),
  pagination: document.querySelector("#pagination")
};

const state = {
  language: savedLanguage() || (navigator.language.startsWith("ja") ? "ja" : "en"),
  incidents: [],
  dailyCounts: [],
  dateRange: null,
  updatedAt: null,
  page: 1,
  sortKey: "published_at",
  sortDirection: "desc",
  loaded: false
};

function text(key) { return copy[state.language][key]; }

function setOptions(select, options) {
  const selected = select.value;
  replaceContent(select, options.map(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    return option;
  }));
  select.value = selected;
}

function applyLanguage() {
  const languageCopy = copy[state.language];
  document.documentElement.lang = state.language;
  document.title = state.language === "ja" ? "JP Incident Monitor｜日本のサイバーインシデント" : "JP Incident Monitor";
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const value = languageCopy[node.dataset.i18n];
    if (typeof value === "string") node.textContent = value;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.placeholder = languageCopy[node.dataset.i18nPlaceholder];
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    node.setAttribute("aria-label", languageCopy[node.dataset.i18nAria]);
  });
  elements.language.setAttribute("aria-label", languageCopy.switchLanguage);
  document.querySelectorAll("[data-language-option]").forEach((node) => {
    node.classList.toggle("is-active", node.dataset.languageOption === state.language);
  });
  setOptions(elements.type, [
    ["", languageCopy.allTypes],
    ["data leak", languageCopy.types["data leak"]],
    ["unauthorized access", languageCopy.types["unauthorized access"]],
    ["other", languageCopy.types.other]
  ]);
  setOptions(elements.confidence, [
    ["", languageCopy.allConfidence],
    ["high", languageCopy.levels.high],
    ["medium", languageCopy.levels.medium],
    ["low", languageCopy.levels.low]
  ]);
  updateSortHeaders();
  render();
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(state.language === "ja" ? "ja-JP" : "en-CA", {
    year: "numeric", month: "2-digit", day: "2-digit", timeZone: "Asia/Tokyo"
  }).format(date);
}

function formatUpdated(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(state.language === "ja" ? "ja-JP" : "en-US", {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    timeZone: "Asia/Tokyo", timeZoneName: "short"
  }).format(date);
}

function nextPlannedUpdate(value) {
  const updated = new Date(value);
  if (Number.isNaN(updated.valueOf())) return null;
  const hour = 60 * 60 * 1000;
  let next = updated.valueOf() + hour;
  const now = Date.now();
  if (next <= now) next += (Math.floor((now - next) / hour) + 1) * hour;
  return new Date(next);
}

function renderUpdateTimes() {
  elements.updated.textContent = formatUpdated(state.updatedAt);
  const next = nextPlannedUpdate(state.updatedAt);
  elements.nextUpdate.textContent = text("nextPlannedUpdate")(next ? formatUpdated(next) : "—");
}

function formatCoverageRange() {
  const dates = state.incidents
    .map((incident) => new Date(incident.published_at))
    .filter((date) => !Number.isNaN(date.valueOf()))
    .sort((a, b) => a - b);
  if (!dates.length) return "—";
  const formatter = new Intl.DateTimeFormat(state.language === "ja" ? "ja-JP" : "en-US", {
    year: "numeric", month: "short", day: "numeric", timeZone: "Asia/Tokyo"
  });
  const first = formatter.format(dates[0]);
  const last = formatter.format(dates[dates.length - 1]);
  return first === last ? first : `${first} – ${last}`;
}

function tokyoDateKey(date) {
  const parts = new Intl.DateTimeFormat("en-US", {
    year: "numeric", month: "2-digit", day: "2-digit", timeZone: "Asia/Tokyo"
  }).formatToParts(date);
  const values = {};
  parts.forEach((part) => { values[part.type] = part.value; });
  return `${values.year}-${values.month}-${values.day}`;
}

function renderTrend() {
  let days = state.dailyCounts.map((day) => ({
    date: new Date(`${day.date}T00:00:00+09:00`), key: day.date, count: day.count
  }));
  if (days.length !== 90) {
    const dayMs = 24 * 60 * 60 * 1000;
    const now = Date.now();
    days = Array.from({ length: 90 }, (_, index) => {
      const date = new Date(now - (89 - index) * dayMs);
      return { date, key: tokyoDateKey(date), count: 0 };
    });
    const byKey = new Map(days.map((day) => [day.key, day]));
    state.incidents.forEach((incident) => {
      const date = new Date(incident.published_at);
      if (!Number.isNaN(date.valueOf())) {
        const day = byKey.get(tokyoDateKey(date));
        if (day) day.count += 1;
      }
    });
  }

  const total = days.reduce((sum, day) => sum + day.count, 0);
  const actualPeak = Math.max(...days.map((day) => day.count));
  const peak = Math.max(1, actualPeak);
  const locale = state.language === "ja" ? "ja-JP" : "en-US";
  const shortDate = new Intl.DateTimeFormat(locale, { month: "short", day: "numeric", timeZone: "Asia/Tokyo" });
  const bars = days.map((day) => {
    const bar = document.createElement("span");
    bar.className = "trend-bar";
    bar.style.height = day.count ? `${Math.max(2, (day.count / peak) * 100)}%` : "1px";
    bar.title = `${shortDate.format(day.date)}: ${day.count.toLocaleString(locale)}`;
    return bar;
  });
  replaceContent(elements.trend, bars);
  elements.trend.setAttribute("aria-label", text("trendAria")(total, actualPeak));
  elements.trendTotal.textContent = text("trendCount")(total, actualPeak);
  elements.trendStart.textContent = shortDate.format(days[0].date);
  elements.trendEnd.textContent = shortDate.format(days[days.length - 1].date);
}

function filteredIncidents() {
  const query = elements.search.value.trim().toLocaleLowerCase(state.language);
  return state.incidents.filter((incident) => {
    if (elements.type.value && incident.incident_type !== elements.type.value) return false;
    if (elements.confidence.value && incident.confidence !== elements.confidence.value) return false;
    if (!query) return true;
    const searchable = [
      incident.organization,
      text("types")[incident.incident_type],
      ...(incident.sources || []).reduce((values, source) => values.concat([source.name, source.url]), [])
    ].filter(Boolean).join(" ").toLocaleLowerCase(state.language);
    return searchable.includes(query);
  });
}

function sortValue(incident, key) {
  if (key === "published_at") return Date.parse(incident.published_at);
  if (key === "sources") return (incident.sources || []).length;
  if (key === "incident_type") return text("types")[incident.incident_type] || incident.incident_type;
  return incident[key];
}

function sortedIncidents(incidents) {
  const direction = state.sortDirection === "asc" ? 1 : -1;
  const collator = new Intl.Collator(state.language === "ja" ? "ja-JP" : "en-US", {
    numeric: true, sensitivity: "base"
  });
  return [...incidents].sort((first, second) => {
    const a = sortValue(first, state.sortKey);
    const b = sortValue(second, state.sortKey);
    const aMissing = a === null || a === undefined || a === "" || Number.isNaN(a);
    const bMissing = b === null || b === undefined || b === "" || Number.isNaN(b);
    if (aMissing && bMissing) return 0;
    if (aMissing) return 1;
    if (bMissing) return -1;
    const comparison = typeof a === "number" && typeof b === "number"
      ? a - b
      : collator.compare(String(a), String(b));
    return comparison * direction;
  });
}

function updateSortHeaders() {
  document.querySelectorAll("th[data-sort]").forEach((header) => {
    const active = header.dataset.sort === state.sortKey;
    const direction = active ? state.sortDirection : null;
    if (direction) header.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
    else header.removeAttribute("aria-sort");
    const button = header.querySelector("button");
    const labelNode = header.querySelector("[data-i18n]");
    const label = labelNode ? labelNode.textContent : "";
    const nextDirection = active && direction === "asc" ? "desc" : "asc";
    button.setAttribute("aria-label", nextDirection === "asc"
      ? text("sortAscending")(label)
      : text("sortDescending")(label));
  });
}

function safeSourceLink(source) {
  try {
    const url = new URL(source.url);
    if (!/^https?:$/.test(url.protocol)) return null;
    const link = document.createElement("a");
    link.href = url.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = source.name || url.hostname;
    return link;
  } catch (_) {
    return null;
  }
}

function incidentRow(incident) {
  const row = document.createElement("tr");

  const date = document.createElement("td");
  date.className = "date-cell";
  date.dataset.label = text("date");
  date.textContent = formatDate(incident.published_at);

  const organization = document.createElement("td");
  organization.className = "org-cell";
  organization.dataset.label = text("organization");
  organization.textContent = incident.organization || text("unknown");

  const type = document.createElement("td");
  type.dataset.label = text("incidentType");
  const typeTag = document.createElement("span");
  typeTag.className = "tag";
  typeTag.textContent = text("types")[incident.incident_type] || incident.incident_type;
  type.append(typeTag);

  const records = document.createElement("td");
  records.className = "numeric records-cell";
  records.dataset.label = text("potentialRecords");
  records.textContent = Number.isFinite(incident.potential_records)
    ? incident.potential_records.toLocaleString(state.language === "ja" ? "ja-JP" : "en-US")
    : "—";

  const confidence = document.createElement("td");
  confidence.dataset.label = text("confidence");
  const confidenceLabel = document.createElement("span");
  confidenceLabel.className = "confidence";
  confidenceLabel.dataset.level = incident.confidence;
  confidenceLabel.append(document.createTextNode(text("levels")[incident.confidence] || incident.confidence));
  const score = document.createElement("span");
  score.className = "confidence-score";
  score.textContent = `(${incident.confidence_score})`;
  confidenceLabel.append(score);
  confidence.append(confidenceLabel);

  const sources = document.createElement("td");
  sources.dataset.label = text("sources");
  const sourceList = document.createElement("div");
  sourceList.className = "source-list";
  (incident.sources || []).forEach((source) => {
    const link = safeSourceLink(source);
    if (link) sourceList.append(link);
  });
  sources.append(sourceList);

  row.append(date, organization, type, records, confidence, sources);
  return row;
}

function pageItems(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1);
  const values = new Set([1, total, current - 1, current, current + 1]);
  const pages = [...values].filter((page) => page >= 1 && page <= total).sort((a, b) => a - b);
  const output = [];
  pages.forEach((page, index) => {
    if (index && page - pages[index - 1] > 1) output.push("gap");
    output.push(page);
  });
  return output;
}

function pageButton(label, page, disabled = false, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `page-button ${className}`.trim();
  button.textContent = label;
  button.disabled = disabled;
  if (!disabled) button.addEventListener("click", () => {
    state.page = page;
    render();
    document.querySelector("#directory-title").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  return button;
}

function renderPagination(totalPages) {
  replaceContent(elements.pagination, []);
  if (totalPages <= 1) return;
  elements.pagination.append(pageButton(`← ${text("previous")}`, state.page - 1, state.page === 1, "page-arrow"));
  pageItems(state.page, totalPages).forEach((item) => {
    if (item === "gap") {
      const gap = document.createElement("span");
      gap.className = "page-gap";
      gap.textContent = "…";
      elements.pagination.append(gap);
      return;
    }
    const button = pageButton(String(item), item);
    button.setAttribute("aria-label", text("page")(item, totalPages));
    if (item === state.page) button.setAttribute("aria-current", "page");
    elements.pagination.append(button);
  });
  elements.pagination.append(pageButton(`${text("next")} →`, state.page + 1, state.page === totalPages, "page-arrow"));
}

function render() {
  if (!state.loaded) return;
  const filtered = sortedIncidents(filteredIncidents());
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * PAGE_SIZE;
  const visible = filtered.slice(start, start + PAGE_SIZE);

  elements.total.textContent = state.incidents.length.toLocaleString(state.language === "ja" ? "ja-JP" : "en-US");
  renderUpdateTimes();
  elements.coverage.textContent = formatCoverageRange();
  renderTrend();
  elements.results.textContent = `${text("results")(filtered.length, state.incidents.length)} · ${text("page")(state.page, totalPages)}`;
  replaceContent(elements.rows, visible.map(incidentRow));
  elements.empty.hidden = filtered.length !== 0;
  updateSortHeaders();
  renderPagination(totalPages);
}

function filtersChanged() {
  state.page = 1;
  render();
}

elements.language.addEventListener("click", () => {
  state.language = state.language === "en" ? "ja" : "en";
  try { localStorage.setItem("jp-incidents-language", state.language); } catch (_) { /* Safari private mode */ }
  applyLanguage();
});
elements.search.addEventListener("input", filtersChanged);
elements.type.addEventListener("change", filtersChanged);
elements.confidence.addEventListener("change", filtersChanged);
elements.reset.addEventListener("click", () => {
  elements.search.value = "";
  elements.type.value = "";
  elements.confidence.value = "";
  filtersChanged();
  elements.search.focus();
});
document.querySelectorAll("th[data-sort] .sort-button").forEach((button) => {
  button.addEventListener("click", () => {
    const key = button.parentElement.dataset.sort;
    if (state.sortKey === key) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
    else {
      state.sortKey = key;
      state.sortDirection = "asc";
    }
    state.page = 1;
    render();
  });
});

async function loadData() {
  applyLanguage();
  try {
    const response = await fetch("data/incidents.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (!Array.isArray(data.incidents)) throw new Error("Invalid data document");
    state.incidents = data.incidents;
    state.dailyCounts = Array.isArray(data.daily_counts_90d) ? data.daily_counts_90d : [];
    state.dateRange = data.date_range || null;
    state.updatedAt = data.updated_at;
    state.loaded = true;
    elements.loading.hidden = true;
    render();
  } catch (error) {
    console.error("Failed to load incident data", error);
    elements.loading.hidden = true;
    elements.error.hidden = false;
  }
}

loadData();
setInterval(() => { if (state.loaded) renderUpdateTimes(); }, 60 * 1000);
