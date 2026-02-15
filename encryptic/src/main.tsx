import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import tabIcon from "./assets/encryptic.png";

function applyTabIcon(iconHref: string) {
  const rels = ["icon", "apple-touch-icon"];

  for (const rel of rels) {
    let link = document.querySelector(`link[rel="${rel}"]`) as HTMLLinkElement | null;
    if (!link) {
      link = document.createElement("link");
      link.rel = rel;
      document.head.appendChild(link);
    }

    if (rel === "icon") {
      link.type = "image/png";
      link.sizes = "32x32";
    }

    link.href = iconHref;
  }
}

applyTabIcon(tabIcon);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
