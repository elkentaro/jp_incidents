"use strict";

function savedLanguage() {
  try { const saved = localStorage.getItem("jp-incidents-language");
    return ["en", "ja", "es"].includes(saved) ? saved : null; } catch (_) { return null; }
}

function replaceContent(node, children) {
  while (node.firstChild) node.removeChild(node.firstChild);
  children.forEach((child) => node.appendChild(child));
}

const copy = {
  es: {
    supporters: "Colaboradores", eyebrow: "TRANSPARENCIA DE LAS FUENTES", title: "Fuentes consultadas",
    description: "Los canales públicos, sitios oficiales, sistemas de divulgación y búsquedas de noticias que consulta el recopilador automático.",
    note: "Las fuentes incluidas se consultan para detectar noticias relevantes; su inclusión no implica que cada página o aviso se convierta en un registro de incidente.",
    total: "Fuentes configuradas", updated: "Directorio actualizado", directory: "Directorio de fuentes",
    searchLabel: "Buscar fuentes", searchPlaceholder: "Buscar…", categoryLabel: "Categoría",
    loading: "Cargando fuentes…", error: "No se pudo cargar el directorio de fuentes.",
    empty: "Ninguna fuente coincide con estos filtros.", incidents: "Incidentes", rssFeed: "Canal RSS",
    footerNote: "Las URL de las fuentes se publican para facilitar la transparencia y la verificación.", project: "Ver el proyecto en GitHub",
    all: "Todas las categorías", switchLanguage: "Idioma",
    groups: {
      discovery: "Noticias, búsquedas y medios especializados", government: "Tokio y ciudades designadas",
      prefecture: "Gobiernos de las prefecturas", national: "Autoridades nacionales",
      disclosure: "Comunicados de empresas cotizadas", transport: "Operadores y grupos de transporte",
      it: "Proveedores de soluciones informáticas y servicios en la nube", retail: "Comercio minorista", distribution: "Distribución y logística",
      healthcare: "Organizaciones sanitarias", telecom: "Operadores de telecomunicaciones y proveedores de Internet",
      finance: "Banca, seguros y pagos", education: "Universidades y educación", utilities: "Servicios de energía y agua",
      manufacturing: "Industria manufacturera y farmacéutica", wholesale: "Proveedores mayoristas"
    }
  },
  en: {
    supporters: "Supporters",
    eyebrow: "SOURCE TRANSPARENCY", title: "Polling sources",
    description: "The public feeds, official sites, disclosure systems, and news searches checked by the automated collector.",
    note: "A listed source is monitored for relevant reports; inclusion does not mean every page or advisory becomes an incident record.",
    total: "Configured sources", updated: "Directory updated", directory: "Source directory",
    searchLabel: "Search sources", searchPlaceholder: "Search…", categoryLabel: "Category",
    loading: "Loading sources…", error: "The source directory could not be loaded.",
    empty: "No sources match these filters.", incidents: "Incidents", rssFeed: "RSS feed",
    footerNote: "Source URLs are published for transparency and verification.", project: "View project on GitHub",
    all: "All categories", switchLanguage: "Language",
    groups: {
      discovery: "News, search & specialist media", government: "Tokyo & designated cities",
      prefecture: "Prefectural governments", national: "National authorities",
      disclosure: "Listed-company disclosures", transport: "Transport operators & groups",
      it: "IT solution providers & cloud", retail: "Retailers", distribution: "Distribution & logistics",
      healthcare: "Healthcare organizations", telecom: "Telecom carriers & ISPs",
      finance: "Banks, insurance & payments", education: "Universities & education",
      utilities: "Energy & water utilities", manufacturing: "Manufacturing & pharmaceuticals",
      wholesale: "Wholesale suppliers"
    }
  },
  ja: {
    supporters: "サポーター",
    eyebrow: "情報源の透明性", title: "監視している情報源",
    description: "自動収集システムが確認する公開フィード、公式サイト、開示システム、ニュース検索の一覧です。",
    note: "掲載された情報源は関連情報の検出対象です。すべてのページや注意喚起がインシデントとして登録されるわけではありません。",
    total: "設定済み情報源", updated: "一覧更新日時", directory: "情報源一覧",
    searchLabel: "情報源を検索", searchPlaceholder: "検索…", categoryLabel: "分類",
    loading: "情報源を読み込んでいます…", error: "情報源一覧を読み込めませんでした。",
    empty: "条件に一致する情報源はありません。", incidents: "インシデント一覧", rssFeed: "RSSフィード",
    footerNote: "透明性と検証のため、監視対象のURLを公開しています。", project: "GitHubでプロジェクトを見る",
    all: "すべての分類", switchLanguage: "言語",
    groups: {
      discovery: "ニュース・検索・専門メディア", government: "東京都・特別区・政令指定都市",
      prefecture: "都道府県", national: "国の機関",
      disclosure: "上場企業の適時開示", transport: "交通事業者・グループ",
      it: "ITソリューション・クラウド", retail: "小売", distribution: "流通・物流",
      healthcare: "医療機関・団体", telecom: "通信事業者・ISP",
      finance: "銀行・保険・決済", education: "大学・教育", utilities: "電力・ガス・水道",
      manufacturing: "製造業・製薬", wholesale: "卸売"
    }
  }
};

const elements = {
  language: document.querySelector("#language-switch"), total: document.querySelector("#source-total"),
  updated: document.querySelector("#source-updated"), search: document.querySelector("#source-search"),
  category: document.querySelector("#source-category"), groups: document.querySelector("#source-groups"),
  loading: document.querySelector("#source-loading"), error: document.querySelector("#source-error"),
  empty: document.querySelector("#source-empty")
};

const state = { language: savedLanguage() || ({ en: "en", ja: "ja", es: "es" }[navigator.language.split("-")[0]] || "en"), sources: [], updatedAt: null };
const groupOrder = ["discovery", "disclosure", "national", "prefecture", "government", "transport", "it", "retail", "distribution", "healthcare", "telecom", "finance", "education", "utilities", "manufacturing", "wholesale"];

function text(key) { return copy[state.language][key]; }

function applyLanguage() {
  const languageCopy = copy[state.language];
  document.documentElement.lang = state.language;
  document.title = state.language === "ja" ? "情報源一覧｜JP Incident Monitor" : state.language === "es" ? "Fuentes — JP Incident Monitor" : "Sources — JP Incident Monitor";
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const value = languageCopy[node.dataset.i18n];
    if (typeof value === "string") node.textContent = value;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.placeholder = languageCopy[node.dataset.i18nPlaceholder];
  });
  elements.language.setAttribute("aria-label", languageCopy.switchLanguage);
  elements.language.querySelectorAll("[data-language-option]").forEach((button) => {
    const active = button.dataset.languageOption === state.language;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const selected = elements.category.value;
  const options = [["", languageCopy.all]].concat(groupOrder.map((group) => [group, languageCopy.groups[group]]));
  replaceContent(elements.category, options.map((entry) => {
    const option = document.createElement("option"); option.value = entry[0]; option.textContent = entry[1]; return option;
  }));
  elements.category.value = selected;
  render();
}

function formatUpdated(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(state.language === "ja" ? "ja-JP" : state.language === "es" ? "es" : "en-US", {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    timeZone: "Asia/Tokyo", timeZoneName: "short"
  }).format(date);
}

function sourceCard(source) {
  const card = document.createElement("article"); card.className = "source-card";
  const link = document.createElement("a"); link.href = source.url; link.target = "_blank";
  link.rel = "noopener noreferrer"; link.textContent = source.name; card.appendChild(link);
  const meta = document.createElement("div"); meta.className = "source-meta";
  try {
    const host = document.createElement("span"); host.textContent = new URL(source.url).hostname; meta.appendChild(host);
  } catch (_) { /* malformed override URL: leave hostname blank */ }
  if (source.sector) {
    const sector = document.createElement("span"); sector.className = "source-sector";
    sector.textContent = source.sector; meta.appendChild(sector);
  }
  card.appendChild(meta); return card;
}

function render() {
  if (!state.sources.length) return;
  const query = elements.search.value.trim().toLocaleLowerCase(state.language);
  const category = elements.category.value;
  const filtered = state.sources.filter((source) => {
    if (category && source.group !== category) return false;
    return !query || `${source.name} ${source.url} ${source.sector || ""}`.toLocaleLowerCase(state.language).includes(query);
  });
  const sections = groupOrder.map((group) => {
    const rows = filtered.filter((source) => source.group === group);
    if (!rows.length) return null;
    const section = document.createElement("section"); section.className = "source-group";
    const heading = document.createElement("div"); heading.className = "source-group-heading";
    const title = document.createElement("h2"); title.textContent = text("groups")[group];
    const count = document.createElement("span"); count.className = "source-group-count";
    count.textContent = rows.length.toLocaleString(state.language === "ja" ? "ja-JP" : state.language === "es" ? "es" : "en-US");
    heading.appendChild(title); heading.appendChild(count); section.appendChild(heading);
    const grid = document.createElement("div"); grid.className = "source-list-grid";
    rows.sort((a, b) => a.name.localeCompare(b.name, state.language)).forEach((source) => grid.appendChild(sourceCard(source)));
    section.appendChild(grid); return section;
  }).filter(Boolean);
  replaceContent(elements.groups, sections);
  elements.empty.hidden = filtered.length !== 0;
  elements.total.textContent = state.sources.length.toLocaleString(state.language === "ja" ? "ja-JP" : state.language === "es" ? "es" : "en-US");
  elements.updated.textContent = formatUpdated(state.updatedAt);
}

elements.language.addEventListener("click", (event) => {
  const button = event.target.closest("[data-language-option]");
  if (!button) return;
  state.language = button.dataset.languageOption;
  try { localStorage.setItem("jp-incidents-language", state.language); } catch (_) { /* Safari private mode */ }
  applyLanguage();
});
elements.search.addEventListener("input", render);
elements.category.addEventListener("change", render);

async function loadSources() {
  applyLanguage();
  try {
    const response = await fetch("data/sources.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (!Array.isArray(data.sources)) throw new Error("Invalid source document");
    state.sources = data.sources; state.updatedAt = data.updated_at;
    elements.loading.hidden = true; render();
  } catch (error) {
    console.error("Failed to load source directory", error);
    elements.loading.hidden = true; elements.error.hidden = false;
  }
}

loadSources();
