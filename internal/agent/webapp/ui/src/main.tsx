import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import "@fontsource-variable/vazirmatn";
import "@/index.css";
import { App } from "@/App";
import { readInitialCapability } from "@/lib/api";
import { applyAppearance, useUi } from "@/stores/ui";

readInitialCapability();
applyAppearance(useUi.getState().language, useUi.getState().theme);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>,
);
