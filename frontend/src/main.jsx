/**
 * rexdr - Frontend
 * main.jsx - React application entry point
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Mounts the React tree, wraps App in the router, and loads
 *           global styles. Nothing else lives here - this file does
 *           exactly one job.
 *
 * --- Part of the REXDR platform. ---
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./design/global.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);