import { StrictMode, Suspense, lazy } from "react";
import { createRoot } from "react-dom/client";

import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-sans/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";

import { App } from "./App.js";
import { openLinksInBrowser } from "./desktop.js";
import "./styles.css";
import { applyAccent, loadAccent } from "./theme.js";

// Before the first render, so the page never flashes the default accent.
applyAccent(loadAccent());
openLinksInBrowser();

// /docs is public and needs no session, so it skips the dashboard entirely.
// Loaded on its own, so the dashboard doesn't carry the docs' text.
const DocsPage = lazy(() => import("./pages/Docs.js").then((module) => ({ default: module.DocsPage })));
const onDocs = /^\/docs(\/|$)/.test(window.location.pathname);

const container = document.getElementById("root");
if (container === null) throw new Error("missing #root element");

createRoot(container).render(
  <StrictMode>
    {onDocs ? (
      <Suspense fallback={null}>
        <DocsPage />
      </Suspense>
    ) : (
      <App />
    )}
  </StrictMode>,
);
