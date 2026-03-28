# FILE MAPPING — Study-Hub3 Migration

> Generated: 2026-03-28

This document maps every legacy file to its new archive location after the
migration from Vanilla JS → React (Vite).

---

## ✅ ACTIVE PROJECT (DO NOT TOUCH)

| Location | Description |
|---|---|
| `study-hub-react/` | **Main active React app** (Vite + React) |
| `study-hub-react/src/App.jsx` | Root React component |
| `study-hub-react/src/main.jsx` | React entry point |
| `study-hub-react/src/components/` | Shared UI components |
| `study-hub-react/src/pages/` | All page-level components (routed via App.jsx) |
| `study-hub-react/src/pages/tools/` | Tool pages (ReconLab, PasswordCracker, etc.) |
| `study-hub-react/src/context/` | React context providers |
| `study-hub-react/src/hooks/` | Custom React hooks |
| `study-hub-react/src/data/` | Data files (JS/JSX) used by React |
| `study-hub-react/src/lib/` | Utility libraries (supabase, etc.) |
| `study-hub-react/src/services/` | API service files |
| `study-hub-react/src/utils/` | Utility functions |
| `backend/` | Python backend server (keep — active) |
| `study-hub-backend/` | Alternative backend (check if active) |
| `assets/` | Static assets used by the app |
| `templates/` | HTML templates (check if linked to backend) |
| `tracks/` | Track data files |
| `lessons/` | Lesson content files |
| `docker/` | Docker configs |

---

## 📦 ARCHIVED FILES

### `_ARCHIVE_OLD/html-files/`
| Original Path | Reason Archived |
|---|---|
| `index.html` | Root legacy HTML — replaced by `study-hub-react/index.html` |
| `ctf-apps/*/index.html` | Standalone CTF HTML apps — superseded by React CTF pages |
| `labs/level1/`, `labs/level4/`, `labs/level5/` | Old HTML/JS lab files |

### `_ARCHIVE_OLD/css-files/`
| Original Path | Reason Archived |
|---|---|
| `styles.css` | Global legacy stylesheet — replaced by `study-hub-react/src/index.css` |
| `cyberpunk-navbar.css` | Old navbar styles — superseded by `Navbar.jsx` CSS |
| `skill-tree.css` | Old skill tree styles |
| `css/room-style.css` | Old room viewer styles |

### `_ARCHIVE_OLD/js-files/`
| Original Path | Reason Archived |
|---|---|
| `app.js` | Root Vanilla JS app — replaced by `App.jsx` |
| `ad-lab-pro.js`, `ad-lab.js` | Legacy AD lab — replaced by `ADAttackLab.jsx` |
| `ai-assistant.js`, `ai-chatbot.js`, `ai-engine.js` | Old AI modules — replaced by `AIAssistant.jsx` |
| `analytics.js`, `analytics-dashboard.js` | Replaced by `AnalyticsDashboard.jsx` |
| `bug-bounty-hub.js`, `bug-bounty-simulator.js` | Legacy bug bounty — replaced by React tools |
| `career-hub.js` | Replaced by `CareerHub.jsx` |
| `ctf-challenge.js`, `ctf-page.js`, `ctf-rooms.js` | Replaced by CTF React pages |
| `leaderboard.js`, `scoreboard.js` | Replaced by leaderboard React apps |
| `recon-lab.js`, `recon-dashboard.js` | Replaced by `ReconLab.jsx` |
| `...all other root .js files` | Legacy Vanilla JS — all replaced by React equivalents |
| `data/curriculum-data.js`, `data/job-sim-data.js` | Old data files |

### `_ARCHIVE_OLD/duplicates/`
| Original Path | Replaced By |
|---|---|
| `app.js` | `study-hub-react/src/App.jsx` |
| `achievements.js` | `study-hub-react/src/pages/Achievements.jsx` |
| `labs/level5/project-singularity/app.js` | `study-hub-react/src/App.jsx` |

### `_ARCHIVE_OLD/frontend-leaderboard/`
Separate Vite app that was built for the leaderboard — superseded or integrated into `study-hub-react`.

### `_ARCHIVE_OLD/dist-leaderboard/`
Built output of the old leaderboard Vite app.

### `_ARCHIVE_OLD/ai-middleware/`
Old Express.js AI proxy server. Check if this is still needed by the backend.

### `_ARCHIVE_OLD/realtime-leaderboard/`
Old realtime leaderboard Node.js server.

### `_ARCHIVE_OLD/temp-logs/`
Temporary analysis files and log files generated during development.

---

## ⚠️ FILES KEPT IN ROOT (Review Later)

| File | Reason |
|---|---|
| `.gitignore` | Git config — keep |
| `package.json` / `package-lock.json` | Root-level packages — review if needed |
| `README.md` | Documentation — keep |
| `render.yaml` | Deployment config — keep |
| `launch_dev.ps1`, `start-all.bat/sh` | Dev launcher scripts — keep for convenience |
| `setup_labs.ps1/sh` | Lab setup scripts |
| `start-shadowhack.ps1`, `start_realtime.ps1`, `stop-all.bat` | Operational scripts |
| `*.py` scripts | Backend utilities (debug_db, find_course, etc.) |
| `cloudflared.exe` | Tunneling executable |
| `localhost.pem`, `localhost-key.pem` | Dev SSL certs |
| `nginx_proxy.conf` | Nginx config |
