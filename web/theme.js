// Runs in <head>, before the stylesheet and body are parsed, so the first
// paint already uses CPAMC's theme instead of flashing the light palette for
// dark users. It owns theme handling for the page, including later changes.
(() => {
  "use strict";

  const CPAMC_THEME_KEY = "cli-proxy-theme";
  const root = document.documentElement;
  const embedded = window.self !== window.top;

  function resolveCPAMCTheme() {
    try {
      if (embedded) {
        const parentTheme = window.parent.document.documentElement.getAttribute("data-theme");
        return parentTheme === "dark" || parentTheme === "white" ? parentTheme : "light";
      }
    } catch (_) { /* same-origin storage remains the fallback */ }
    try {
      const persisted = JSON.parse(localStorage.getItem(CPAMC_THEME_KEY) || "null");
      const theme = persisted?.state?.theme;
      if (theme === "dark" || theme === "white" || theme === "light") return theme;
      if (theme === "auto") return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
    } catch (_) { /* use system preference */ }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
  }

  function syncTheme() {
    const theme = resolveCPAMCTheme();
    if (theme === "light") root.removeAttribute("data-theme");
    else root.dataset.theme = theme;
  }

  root.classList.toggle("is-embedded", embedded);
  syncTheme();

  try {
    if (embedded) {
      new MutationObserver(syncTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }
  } catch (_) { /* cross-origin embedding is unsupported for session reuse */ }
  window.addEventListener("storage", (event) => {
    if (event.key === CPAMC_THEME_KEY) syncTheme();
  });
})();
