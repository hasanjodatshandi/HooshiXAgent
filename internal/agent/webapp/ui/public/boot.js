(function () {
  try {
    var raw = localStorage.getItem("hooshix-agent-ui");
    var state = raw ? JSON.parse(raw).state : null;
    var language = state && state.language === "en" ? "en" : "fa";
    var theme =
      state && (state.theme === "light" || state.theme === "dark")
        ? state.theme
        : window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light";
    var root = document.documentElement;
    root.lang = language;
    root.dir = language === "fa" ? "rtl" : "ltr";
    root.classList.toggle("dark", theme === "dark");
  } catch (error) {
    document.documentElement.lang = "fa";
    document.documentElement.dir = "rtl";
  }
})();
