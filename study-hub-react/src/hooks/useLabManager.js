import { useState, useEffect, useCallback } from 'react';
import { useToast } from '../context/ToastContext';

import { useAppContext } from '../context/AppContext';

export const useLabManager = (labId) => {
    const { apiUrl } = useAppContext();
    const API_BASE = apiUrl;
    const [status, setStatus] = useState('idle'); // idle, starting, running, error
    const [connectionInfo, setConnectionInfo] = useState(null);
    const [terminalOutput, setTerminalOutput] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const { toast } = useToast();
    const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

    // Helper for robust JSON fetching
    const robustFetch = async (url, options = {}) => {
        try {
            const res = await fetch(url, options);
            const text = await res.text();

            if (!res.ok) {
                // If we get HTML but res.ok is false, it's a server error
                throw new Error(`Server returned ${res.status}: ${text.substring(0, 100)}`);
            }

            if (!text.trim().startsWith('{')) {
                // Likely an HTML fallback from Vercel or Cloudflare
                throw new Error(`Unexpected non-JSON response (starts with ${text.trim().substring(0, 10)})`);
            }

            return JSON.parse(text);
        } catch (e) {
            console.warn(`Robust fetch failed for ${url}:`, e.message);
            throw e;
        }
    };

    // Poll for status on mount - Fix: include checkStatus in deps
    useEffect(() => {
        const interval = setInterval(checkStatus, 10000); // Poll every 10s
        checkStatus(); // Initial check
        return () => clearInterval(interval);
    }, [checkStatus]);

    const checkStatus = useCallback(async () => {
        if (!API_BASE || API_BASE === '/api') return; // Don't poll if API not yet loaded or default

        try {
            const user = localStorage.getItem('user_id') || '1';
            const data = await robustFetch(`${API_BASE}/labs/status?user_id=${user}`);

            if (data.success && data.lab) {
                if (data.lab.lab_id === labId) {
                    setStatus('running');
                    setConnectionInfo(data.lab);
                } else {
                    setStatus('idle');
                }
            } else {
                setStatus('idle');
                setConnectionInfo(null);
            }
        } catch (e) {
            // Error is already logged in robustFetch
            setStatus('idle');
        }
    }, [labId, API_BASE]);

    const startLab = async () => {
        setIsLoading(true);
        setStatus('starting');
        if (!isLocal && API_BASE === '/api') {
            const msg = 'Backend tunnel not established. Please run the start-shadowhack script.';
            toast(msg, 'error');
            setTerminalOutput(prev => [...prev, `[CRITICAL] ${msg}`]);
            setIsLoading(false);
            setStatus('error');
            return;
        }
        setTerminalOutput(prev => [...prev, `> Initializing environment for ${labId}...`]);

        try {
            const user = localStorage.getItem('user_id') || '1';
            const data = await robustFetch(`${API_BASE}/labs/spawn`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: user,
                    lab_id: labId
                })
            });

            if (data.success) {
                setStatus('running');
                setConnectionInfo(data);
                toast('Lab Environment Provisioned Successfully', 'success');
                setTerminalOutput(prev => [...prev, `> Container Started: ${data.container_id.substring(0, 12)}`, `> IP: ${data.ip_address}`]);
            } else {
                setStatus('error');
                toast(data.error || 'Failed to start lab', 'error');
                setTerminalOutput(prev => [...prev, `[ERROR] ${data.error}`]);
            }
        } catch (e) {
            setStatus('error');
            toast(e.message || 'Backend connection failed.', 'error');
            setTerminalOutput(prev => [...prev, `[ERROR] ${e.message}`]);
        }
        setIsLoading(false);
    };

    const stopLab = async () => {
        setIsLoading(true);
        if (!isLocal && API_BASE === '/api') {
            toast('Tunnel lost. Cannot terminate remotely.', 'error');
            setIsLoading(false);
            return;
        }
        try {
            const user = localStorage.getItem('user_id') || '1';
            const data = await robustFetch(`${API_BASE}/labs/kill`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: user })
            });

            if (data.success) {
                setStatus('idle');
                setConnectionInfo(null);
                toast('Lab Terminated', 'default');
                setTerminalOutput(prev => [...prev, `> Environment destroyed.`]);
            }
        } catch (e) {
            toast('Failed to stop lab', 'error');
            setStatus('idle');
            setConnectionInfo(null);
        }
        setIsLoading(false);
    };

    const executeCommand = async (command) => {
        if (!isLocal && API_BASE === '/api') {
            return `Connection Error: Backend tunnel not established.`;
        }
        if (status !== 'running') {
            toast('Start the lab first!', 'warning');
            return;
        }

        try {
            const user = localStorage.getItem('user_id') || '1';
            const data = await robustFetch(`${API_BASE}/labs/shell`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    user_id: user,
                    command: command
                })
            });

            if (data.success) {
                return data.output;
            } else {
                return `Error: ${data.error}`;
            }
        } catch (e) {
            return `Connection Error: ${e.message}`;
        }
    };

    return {
        status,
        isLoading,
        connectionInfo,
        startLab,
        stopLab,
        executeCommand,
        terminalOutput,
        checkStatus
    };
};
