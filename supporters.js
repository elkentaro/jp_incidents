"use strict";

const copy = {
  en: {
    supporters: "Supporters", eyebrow: "COMMUNITY SUPPORT",
    description: "Thank you to everyone helping keep JP Incident Monitor going.",
    thanks: "With thanks to", supportEyebrow: "SUPPORT THE PROJECT", chipIn: "Chip in",
    supportDescription: "If you find the index useful, you can chip in to support the project.",
    supportButton: "Support on Buy Me a Coffee ↗",
    incidents: "Incidents", sources: "Sources", navigation: "Main navigation",
    footerNote: "Thank you for supporting JP Incident Monitor.",
    project: "View project on GitHub", switchLanguage: "日本語に切り替える"
  },
  ja: {
    supporters: "サポーター", eyebrow: "コミュニティの支援",
    description: "JP Incident Monitorの活動を支えてくださる皆さまに感謝します。",
    thanks: "ご支援ありがとうございます", supportEyebrow: "プロジェクトを支援", chipIn: "活動を応援する",
    supportDescription: "このインデックスが役に立ったら、プロジェクトの継続を支援していただけます。",
    supportButton: "Buy Me a Coffeeで支援する ↗",
    incidents: "インシデント一覧", sources: "情報源一覧", navigation: "メインナビゲーション",
    footerNote: "JP Incident Monitorへのご支援に感謝します。",
    project: "GitHubでプロジェクトを見る", switchLanguage: "Switch to English"
  }
};

let saved;
try { saved = localStorage.getItem("jp-incidents-language"); } catch (_) { /* Storage can be disabled. */ }
let language = ["en", "ja"].includes(saved) ? saved : navigator.language.startsWith("ja") ? "ja" : "en";
const toggle = document.querySelector("#language-switch");
function applyLanguage() {
  const text = copy[language];
  document.documentElement.lang = language;
  document.title = language === "ja" ? "サポーター｜JP Incident Monitor" : "Supporters — JP Incident Monitor";
  document.querySelectorAll("[data-i18n]").forEach(node => { node.textContent = text[node.dataset.i18n]; });
  document.querySelectorAll("[data-i18n-aria]").forEach(node => { node.setAttribute("aria-label", text[node.dataset.i18nAria]); });
  toggle.setAttribute("aria-label", text.switchLanguage);
  document.querySelectorAll("[data-language-option]").forEach(node => {
    node.classList.toggle("is-active", node.dataset.languageOption === language);
  });
}
toggle.addEventListener("click", () => {
  language = language === "en" ? "ja" : "en";
  try { localStorage.setItem("jp-incidents-language", language); } catch (_) { /* Storage can be disabled. */ }
  applyLanguage();
});
applyLanguage();
