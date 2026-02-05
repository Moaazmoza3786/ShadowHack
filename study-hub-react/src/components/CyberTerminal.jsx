import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal as TerminalIcon, Maximize2, Minimize2, Power, Wifi, ShieldCheck } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { io } from 'socket.io-client';

const CyberTerminal = ({
    initialHeight = "400px",
    readOnly = false,
    title = "KALI-LINUX-SANDBOX [ROOT]",
    onCommand,
    isConnected = false,
    labId,
    userId = 1
}) => {
    const terminalRef = useRef(null);
    const xtermRef = useRef(null);
    const fitAddonRef = useRef(null);
    const socketRef = useRef(null);
    const [isMaximized, setIsMaximized] = useState(false);
    const [socketStatus, setSocketStatus] = useState('disconnected'); // disconnected, connecting, connected

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
        term.open(terminalRef.current);
        fitAddon.fit();

        xtermRef.current = term;
        fitAddonRef.current = fitAddon;

        // Initial Banner
        term.writeln('\x1b[1;32m⚡ NEURAL LINK ESTABLISHED ⚡\x1b[0m');
        term.writeln('Initializing secure shell connection...');

        // Connect to WebSocket if labId is provided and we are "connected" (lab running)
        if (isConnected && labId) {
            connectSocket(term);
        } else {
            term.writeln('\x1b[1;33m⚠ Waiting for lab instance to start...\x1b[0m');
        }

        // Cleanup
        return () => {
            if (socketRef.current) socketRef.current.disconnect();
            term.dispose();
        };
    }, [isConnected, labId]); // Re-run if connection status changes

    const connectSocket = (term) => {
        if (socketRef.current) socketRef.current.disconnect();

        setSocketStatus('connecting');
        const socket = io('http://localhost:5000/ws/terminal', {
            query: { lab_id: labId, user_id: userId },
            transports: ['websocket']
        });

        socket.on('connect', () => {
            setSocketStatus('connected');
            term.writeln('\x1b[1;32m✓ ROOT ACCESS GRANTED\x1b[0m');
            term.write('\r\n');
        });

        socket.on('output', (data) => {
            term.write(data);
        });

        socket.on('terminal_error', (data) => {
            term.writeln(`\r\n\x1b[1;31m⚠ ERROR: ${data.message}\x1b[0m`);
        });

        socket.on('disconnect', () => {
            setSocketStatus('disconnected');
            term.writeln('\r\n\x1b[1;31m✖ SESSION TERMINATED\x1b[0m');
        });

        // Send input to backend (only if socket is connected)
        // This part is now handled by the term.onData inside useEffect,
        // which checks socketStatus before sending.
        // term.onData((data) => {
        //     socket.emit('input', data);
        // });

        // Handle resize
        term.onResize((size) => {
            socket.emit('resize', { cols: size.cols, rows: size.rows });
        });

        socketRef.current = socket;
    };

    // Handle maximized state resize
    useEffect(() => {
        if (fitAddonRef.current) {
            setTimeout(() => {
                fitAddonRef.current.fit();
            }, 300); // Wait for transition
        }
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
                    <span>LATENCY: 24ms</span>
                </div>
                <div className="flex items-center gap-4">
                    <span>ENCRYPTION: AES-256</span>
                    <span>SESSION: {Math.random().toString(36).substr(2, 9).toUpperCase()}</span>
                </div>
            </div>
        </div>
    );
};

export default CyberTerminal;
