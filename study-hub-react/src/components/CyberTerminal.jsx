import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal as TerminalIcon, Maximize2, Minimize2, Power } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { io } from 'socket.io-client';
import { useAppContext } from '../context/AppContext';

const CyberTerminal = ({
    initialHeight = "400px",
    title = "LINUX TOOLING SHELL",
    isConnected = false,
    labId,
    userId = 1
}) => {
    const { apiUrl } = useAppContext();
    const terminalRef = useRef(null);
    const xtermRef = useRef(null);
    const fitAddonRef = useRef(null);
    const socketRef = useRef(null);
    const [isMaximized, setIsMaximized] = useState(false);
    const [sessionId] = useState(() => Math.random().toString(36).substr(2, 9).toUpperCase());

    const connectSocket = React.useCallback((term) => {
        if (socketRef.current) socketRef.current.disconnect();

        const socket = io(apiUrl.replace('/api', '') + '/ws/terminal', {
            query: { lab_id: labId, user_id: userId },
            transports: ['websocket']
        });

        socket.on('connect', () => {
            term.writeln('\x1b[1;32m✓ Terminal session connected\x1b[0m');
            term.write('\r\n');
        });

        socket.on('output', (data) => {
            term.write(data);
        });

        socket.on('terminal_error', (data) => {
            term.writeln(`\r\n\x1b[1;31m⚠ ERROR: ${data.message}\x1b[0m`);
        });

        socket.on('disconnect', () => {
            term.writeln('\r\n\x1b[1;31m✖ Session disconnected\x1b[0m');
        });

        // Handle resize
        term.onResize((size) => {
            socket.emit('resize', { cols: size.cols, rows: size.rows });
        });

        socketRef.current = socket;
    }, [apiUrl, labId, userId]);

    useEffect(() => {
        if (!terminalRef.current) return;

        // Initialize xterm.js
        const term = new Terminal({
            cursorBlink: true,
            theme: {
                background: '#0a0a0a',
                foreground: '#00ff00',
                cursor: '#ff0055',
                selectionBackground: 'rgba(255, 0, 85, 0.3)',
                black: '#000000',
                red: '#ff0055',
                green: '#00ff00',
                yellow: '#ffff00',
                blue: '#00ffff',
                magenta: '#ff00ff',
                cyan: '#00ffff',
                white: '#ffffff',
            },
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            fontSize: 14,
            allowTransparency: true,
            rows: 24,
            cols: 80,
            convertEol: true,
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        
        // Use requestAnimationFrame to ensure DOM is ready before opening/fitting
        requestAnimationFrame(() => {
            if (terminalRef.current && term) {
                try {
                    term.open(terminalRef.current);
                    
                    // Small delay to ensure the container is sized
                    setTimeout(() => {
                        if (fitAddon && term && !term._disposed) {
                            fitAddon.fit();
                        }
                    }, 0);
                } catch (e) {
                    console.warn('Terminal initialization failed:', e);
                }
            }
        });

        xtermRef.current = term;
        fitAddonRef.current = fitAddon;

        // Initial Banner
        term.writeln('\x1b[1;32m⚡ Terminal ready\x1b[0m');
        term.writeln('Waiting for active lab session...');

        // Connect to WebSocket if labId is provided and we are "connected" (lab running)
        if (isConnected && labId) {
            connectSocket(term);
        }

        // Cleanup
        return () => {
            if (socketRef.current) socketRef.current.disconnect();
            term.dispose();
        };
    }, [isConnected, labId, connectSocket]); // Re-run if connection status changes

    // Handle maximized state resize
    useEffect(() => {
        let timeoutId;
        if (fitAddonRef.current && xtermRef.current) {
            timeoutId = setTimeout(() => {
                // Defensive check to ensure terminal is still active and attached
                if (fitAddonRef.current && xtermRef.current) {
                    try {
                        fitAddonRef.current.fit();
                    } catch (e) {
                        console.warn('Terminal fit failed:', e);
                    }
                }
            }, 300); // Wait for transition
        }
        return () => {
            if (timeoutId) clearTimeout(timeoutId);
        };
    }, [isMaximized]);

    return (
        <div
            className={`
                flex flex-col bg-[#0a0a0a] border border-white/10 rounded-xl overflow-hidden shadow-2xl transition-all duration-500
                ${isMaximized ? 'fixed inset-4 z-50 h-auto' : `relative h-[${initialHeight}]`}
            `}
            style={{ height: isMaximized ? 'auto' : initialHeight }}
        >
            {/* Terminal Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/5">
                <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                    <TerminalIcon size={14} className="text-gray-400" />
                    <span className="text-xs font-mono font-bold text-gray-300 uppercase tracking-wider">
                        {title}
                    </span>
                </div>
                <div className="flex items-center gap-2">
                    <button
                        onClick={() => setIsMaximized(!isMaximized)}
                        className="p-1.5 text-gray-500 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
                    >
                        {isMaximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                    </button>
                    <button className="p-1.5 text-red-500 hover:bg-red-500/10 rounded-lg transition-colors">
                        <Power size={14} />
                    </button>
                </div>
            </div>

            {/* Terminal Body */}
            <div className="flex-1 p-1 relative bg-[#0a0a0a]">
                <div className="scanline pointer-events-none absolute inset-0 z-10 opacity-10"></div>
                <div ref={terminalRef} className="h-full w-full custom-scrollbar" />
            </div>

            {/* Status Bar */}
            <div className="px-4 py-1 bg-white/5 border-t border-white/5 flex items-center justify-between text-[10px] font-mono text-gray-500">
                <div className="flex items-center gap-4">
                    <span>STATUS: {isConnected ? 'ONLINE' : 'OFFLINE'}</span>
                    <span>MODE: {isConnected ? 'LIVE' : 'DEMO'}</span>
                </div>
                <div className="flex items-center gap-4">
                    <span>TRANSPORT: WebSocket</span>
                    <span>SESSION: {sessionId}</span>
                </div>
            </div>
        </div>
    );
};

export default CyberTerminal;
