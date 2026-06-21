/**
 * rexdr - Frontend
 * App.jsx - Root application shell
 *
 * Author  : Rayyan Umair
 * Date    : 2026-06-20
 * Purpose : Composes the persistent layout - Sidebar, TopBar, routed
 *           page content, Command Palette, and AI Panel - around the
 *           React Router outlet. This is the one place that assembles
 *           every other piece into the actual REXDR application.
 *
 * --- Part of the REXDR platform. ---
 */

import { useState } from "react";
import { Routes, Route } from "react-router-dom";
import { colors } from "./design/tokens";
import { useEngineHealth } from "./hooks/useEngineHealth";
import Sidebar from "./components/Sidebar/Sidebar";
import TopBar from "./components/TopBar/TopBar";
import CommandPalette from "./components/CommandPalette/CommandPalette";
import AIPanel from "./components/AIPanel/AIPanel";
import Overview from "./pages/Overview";
import EngineView from "./pages/EngineView";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";

export default function App() {
  const { health } = useEngineHealth();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [aiOpen, setAiOpen] = useState(false);

  const aiConfigured = Boolean(import.meta.env.VITE_AI_CONFIGURED === "true");

  return (
    <div style={{ display: "flex", height: "100vh", background: colors.background }}>
      <Sidebar health={health} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <TopBar
          onOpenSearch={() => setPaletteOpen(true)}
          onToggleAI={() => setAiOpen((v) => !v)}
          aiEnabled={aiOpen}
          alertCount={Object.values(health).reduce(
            (sum, h) => sum + (h?.stats?.critical_detections || 0), 0
          )}
        />

        <div style={{ flex: 1, overflow: "hidden" }}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/engine/:engineId" element={<EngineView />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </div>
      </div>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      <AIPanel open={aiOpen} onClose={() => setAiOpen(false)} aiConfigured={aiConfigured} />
    </div>
  );
}