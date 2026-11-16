import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { createWorkbenchStore } from "./store.ts";
import "./styles.css";

const store = createWorkbenchStore();
store.boot();

const container = document.getElementById("root");
if (container === null) {
  throw new Error("The workbench needs a #root element");
}
createRoot(container).render(
  <StrictMode>
    <App store={store} />
  </StrictMode>,
);
