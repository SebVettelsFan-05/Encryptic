import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

/* Random blob start positions on refresh */
function randomPct() {
  return `${Math.random() * 100}%`;
}
function randomizeBlobs() {
  const root = document.documentElement;
  root.style.setProperty("--blob1x", randomPct());
  root.style.setProperty("--blob1y", randomPct());
  root.style.setProperty("--blob2x", randomPct());
  root.style.setProperty("--blob2y", randomPct());
  root.style.setProperty("--blob3x", randomPct());
  root.style.setProperty("--blob3y", randomPct());
  root.style.setProperty("--blob4x", randomPct());
  root.style.setProperty("--blob4y", randomPct());
  root.style.setProperty("--blob5x", randomPct());
  root.style.setProperty("--blob5y", randomPct());
}
randomizeBlobs();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
