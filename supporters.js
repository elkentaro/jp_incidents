"use strict";

const copy = {
  es: {
    supporters: "Colaboradores", eyebrow: "APOYO DE LA COMUNIDAD",
    description: "Gracias a todas las personas que ayudan a mantener JP Incident Monitor.",
    thanks: "Nuestro agradecimiento a", supportEyebrow: "APOYA EL PROYECTO", chipIn: "Haz una aportación",
    supportDescription: "Si este índice te resulta útil, puedes hacer una aportación para apoyar el proyecto.",
    supportButton: "Apoyar en Buy Me a Coffee ↗",
    incidents: "Incidentes", sources: "Fuentes", navigation: "Navegación principal",
    footerNote: "Gracias por apoyar JP Incident Monitor.", project: "Ver el proyecto en GitHub", switchLanguage: "Idioma"
  },
  en: {
    supporters: "Supporters", eyebrow: "COMMUNITY SUPPORT",
    description: "Thank you to everyone helping keep JP Incident Monitor going.",
    thanks: "With thanks to", supportEyebrow: "SUPPORT THE PROJECT", chipIn: "Chip in",
    supportDescription: "If you find the index useful, you can chip in to support the project.",
    supportButton: "Support on Buy Me a Coffee ↗",
    incidents: "Incidents", sources: "Sources", navigation: "Main navigation",
    footerNote: "Thank you for supporting JP Incident Monitor.",
    project: "View project on GitHub", switchLanguage: "Language"
  },
  ja: {
    supporters: "サポーター", eyebrow: "コミュニティの支援",
    description: "JP Incident Monitorの活動を支えてくださる皆さまに感謝します。",
    thanks: "ご支援ありがとうございます", supportEyebrow: "プロジェクトを支援", chipIn: "活動を応援する",
    supportDescription: "このインデックスが役に立ったら、プロジェクトの継続を支援していただけます。",
    supportButton: "Buy Me a Coffeeで支援する ↗",
    incidents: "インシデント一覧", sources: "情報源一覧", navigation: "メインナビゲーション",
    footerNote: "JP Incident Monitorへのご支援に感謝します。",
    project: "GitHubでプロジェクトを見る", switchLanguage: "言語"
  }
};

let saved;
try { saved = localStorage.getItem("jp-incidents-language"); } catch (_) { /* Storage can be disabled. */ }
let language = ["en", "ja", "es"].includes(saved) ? saved : ({ en: "en", ja: "ja", es: "es" }[navigator.language.split("-")[0]] || "en");
const toggle = document.querySelector("#language-switch");
function applyLanguage() {
  const text = copy[language];
  document.documentElement.lang = language;
  document.title = language === "ja" ? "サポーター｜JP Incident Monitor" : language === "es" ? "Colaboradores — JP Incident Monitor" : "Supporters — JP Incident Monitor";
  document.querySelectorAll("[data-i18n]").forEach(node => { node.textContent = text[node.dataset.i18n]; });
  document.querySelectorAll("[data-i18n-aria]").forEach(node => { node.setAttribute("aria-label", text[node.dataset.i18nAria]); });
  toggle.setAttribute("aria-label", text.switchLanguage);
  toggle.querySelectorAll("[data-language-option]").forEach((button) => {
    const active = button.dataset.languageOption === language;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}
toggle.addEventListener("click", (event) => {
  const button = event.target.closest("[data-language-option]");
  if (!button) return;
  language = button.dataset.languageOption;
  try { localStorage.setItem("jp-incidents-language", language); } catch (_) { /* Storage can be disabled. */ }
  applyLanguage();
});
applyLanguage();
