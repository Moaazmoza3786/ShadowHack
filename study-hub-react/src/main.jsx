import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

const loadConfig = async () => {
  try {
    const response = await fetch('/config.json');
    const config = await response.json();
    window.CYBER_CONFIG = config;
  } catch (error) {
    console.error('Failed to load config:', error);
    // Fallback to default
    window.CYBER_CONFIG = { apiUrl: '/api' };
  }
};

loadConfig().then(() => {
  createRoot(document.getElementById('root')).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
