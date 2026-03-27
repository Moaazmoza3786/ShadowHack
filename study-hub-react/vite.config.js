import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    port: 3000,
    host: "127.0.0.1",
    allowedHosts: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // Raise the warning threshold — chunks are intentionally split below this
    chunkSizeWarningLimit: 800,
    rollupOptions: {
      output: {
        /**
         * Function-based manualChunks gives fine-grained control over how
         * modules are grouped. Each group becomes a separate lazy-loaded file,
         * keeping the initial bundle small.
         *
         * Strategy:
         *  - Core React + Router → vendor-react   (always needed)
         *  - Animation + Icons  → vendor-ui        (needed early)
         *  - Heavy 3rd-party    → vendor-heavy      (loaded on demand)
         *  - Terminal deps      → vendor-terminal   (LabWorkspace only)
         *  - Supabase           → vendor-supabase   (auth only)
         *  - Tool pages         → pages-tools-*     (50+ tool pages, split by group)
         *  - CTF pages          → pages-ctf
         *  - Lab pages          → pages-labs
         *  - Career/path pages  → pages-paths
         *  - Admin/analytics    → pages-admin
         *  - Everything else    → auto (per-route code splitting via React.lazy)
         */
        manualChunks(id) {
          // ── Core framework (always loaded) ───────────────────────────────
          if (
            id.includes("node_modules/react/") ||
            id.includes("node_modules/react-dom/") ||
            id.includes("node_modules/react-router-dom/")
          ) {
            return "vendor-react";
          }

          // ── Animation libraries (loaded with layout) ───────────────
          if (
            id.includes("node_modules/framer-motion/")
          ) {
            return "vendor-ui";
          }

          // ── Terminal / WebSocket (LabWorkspace only) ──────────────────────
          if (
            id.includes("node_modules/@xterm/") ||
            id.includes("node_modules/socket.io-client/") ||
            id.includes("node_modules/engine.io-client/")
          ) {
            return "vendor-terminal";
          }

          // ── Supabase (auth screen only) ───────────────────────────────────
          if (id.includes("node_modules/@supabase/")) {
            return "vendor-supabase";
          }

          // ── Heavy rendering / data-vis (loaded on demand) ─────────────────
          if (
            id.includes("node_modules/react-force-graph") ||
            id.includes("node_modules/react-markdown/") ||
            id.includes("node_modules/recharts/")
          ) {
            return "vendor-heavy";
          }

          // ── All remaining node_modules → vendor-misc ──────────────────────
          if (id.includes("node_modules/")) {
            return "vendor-misc";
          }

          // ── App code: tool pages split into small groups ──────────────────
          if (id.includes("/pages/tools/")) {
            // Offensive tools
            if (
              id.includes("PayloadGenerator") ||
              id.includes("XSSPayloads") ||
              id.includes("SQLiPayloads") ||
              id.includes("WebExploitation") ||
              id.includes("AttackChains") ||
              id.includes("C2CommandCenter")
            ) {
              return "pages-tools-offensive";
            }
            // Recon / OSINT tools
            if (
              id.includes("ReconLab") ||
              id.includes("OSINTPro") ||
              id.includes("SubdomainMonitor") ||
              id.includes("TargetManager") ||
              id.includes("JSMonitorPro") ||
              id.includes("VisualMapper")
            ) {
              return "pages-tools-recon";
            }
            // Crypto / encoding tools
            if (
              id.includes("CryptoForge") ||
              id.includes("EncoderTool") ||
              id.includes("HashIdentifier") ||
              id.includes("HashRefinery") ||
              id.includes("StegoAnalyst")
            ) {
              return "pages-tools-crypto";
            }
            // Reporting / utility tools
            if (
              id.includes("ReportBuilder") ||
              id.includes("FindingReporter") ||
              id.includes("ProjectTracker") ||
              id.includes("CommandReference") ||
              id.includes("FileTransferHelper") ||
              id.includes("SubnetCalculator")
            ) {
              return "pages-tools-utils";
            }
            // All other tools
            return "pages-tools-misc";
          }

          // ── CTF pages ─────────────────────────────────────────────────────
          if (id.includes("/pages/ctf/")) {
            return "pages-ctf";
          }

          // ── Lab pages ─────────────────────────────────────────────────────
          if (id.includes("/pages/labs/") || id.includes("LabWorkspace")) {
            return "pages-labs";
          }

          // ── Career / learning path pages ──────────────────────────────────
          if (id.includes("/pages/paths/") || id.includes("LearningTracks")) {
            return "pages-paths";
          }

          // ── Admin & analytics (heavy dashboard code) ─────────────────────
          if (
            id.includes("AdminDashboard") ||
            id.includes("AnalyticsDashboard")
          ) {
            return "pages-admin";
          }

          // ── OWASP module ──────────────────────────────────────────────────
          if (id.includes("OWASP")) {
            return "pages-owasp";
          }

          // All other app code: let Rollup create per-route async chunks
          // (React.lazy() already requests code-splitting for every page)
        },
      },
    },
  },
});
