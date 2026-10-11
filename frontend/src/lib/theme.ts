// Light / dark theme. Dark is the default; the choice is remembered in this browser only.
export const THEME_KEY = "qt-theme";
export type Theme = "dark" | "light";

// Runs in <head> before the first paint, so a saved light theme never flashes dark.
export const themeScript = `try{if(localStorage.getItem("${THEME_KEY}")==="light")document.documentElement.classList.add("light")}catch(e){}`;

export function currentTheme(): Theme {
  return typeof document !== "undefined" && document.documentElement.classList.contains("light")
    ? "light"
    : "dark";
}

const CHANGE = "qt-theme-change";

/** Lets every switch on the page (sidebar and phone menu) follow the same theme. */
export function subscribeTheme(onChange: () => void) {
  window.addEventListener(CHANGE, onChange);
  return () => window.removeEventListener(CHANGE, onChange);
}

export function setTheme(theme: Theme) {
  document.documentElement.classList.toggle("light", theme === "light");
  window.dispatchEvent(new Event(CHANGE));
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // storage blocked (private window): the choice lasts until the page is reloaded
  }
}
