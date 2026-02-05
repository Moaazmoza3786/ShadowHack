import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

function initLeaderboard() {
    const rootElement = document.getElementById('leaderboard-root');
    if (rootElement && !rootElement._reactRoot) {
        const root = ReactDOM.createRoot(rootElement);
        root.render(
            <React.StrictMode>
                <App />
            </React.StrictMode>
        );
        rootElement._reactRoot = root;
    }
}

// Watch for the element to appear (for SPA navigation)
const observer = new MutationObserver(() => {
    if (document.getElementById('leaderboard-root')) {
        initLeaderboard();
    }
});

observer.observe(document.body, { childList: true, subtree: true });

// Also try immediate init
initLeaderboard();
