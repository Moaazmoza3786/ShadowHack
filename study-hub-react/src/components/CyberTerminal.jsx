import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal as TerminalIcon, Maximize2, Minimize2, Power } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';

const CyberTerminal = ({
    initialHeight = "400px",
    readOnly = false,
    title = "KALI-LINUX-SANDBOX [ROOT]",
    onCommand,
    isConnected = false
}) => {
    const terminalRef = useRef(null);
    const xtermRef = useRef(null);
    const fitAddonRef = useRef(null);
    const [isMaximized, setIsMaximized] = useState(false);

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

        // Initial Greeting
        term.writeln('\x1b[1;32m┌──────────────────────────────────────────────────┐\x1b[0m');
        term.writeln('\x1b[1;32m│  SHADOWHACK PRO [NEURAL TERMINAL V3.0]           │\x1b[0m');
        term.writeln('\x1b[1;32m│  SECURE CONNECTION ESTABLISHED...                │\x1b[0m');
        term.writeln('\x1b[1;32m└──────────────────────────────────────────────────┘\x1b[0m');
        term.writeln('');

        if (!isConnected) {
            term.writeln('\x1b[1;33m[!] LIVE CONNECTION NOT DETECTED\x1b[0m');
            term.writeln('\x1b[0;37mRunning in local emulation mode. Connect to Codespace to access full Kali tools.\x1b[0m');
            term.writeln('');
        }

        term.write('\x1b[1;32moperator@shadowhack:~# \x1b[0m');

        // Simple Local Echo / Command Handling
        let currentLine = '';
        term.onData(e => {
            if (readOnly) return;

            const printable = !e.altKey && !e.altGraphKey && !e.ctrlKey && !e.metaKey;

            // Enter key
            if (e === '\r') {
                term.write('\r\n');
                if (currentLine.trim().length > 0) {
                    if (onCommand) {
                        // Support async onCommand
                        (async () => {
                            const result = await onCommand(currentLine);
                            if (result) {
                                term.writeln(result);
                            }
                            term.write('\x1b[1;32moperator@shadowhack:~# \x1b[0m');
                        })();
                    } else {
                        // Echo generic response if no handler
                        if (currentLine === 'help') {
                            term.writeln('Available commands: help, clear, connect, whoami');
                        } else if (currentLine === 'clear') {
                            term.clear();
                        } else if (currentLine === 'whoami') {
                            term.writeln('root');
                        } else if (currentLine === 'connect') {
                            term.writeln('\x1b[1;33mInitiating secure handshake with GitHub Codespaces...\x1b[0m');
                        } else {
                            term.writeln(`\x1b[1;31mCommand not found: ${currentLine}\x1b[0m`);
                        }
                        term.write('\x1b[1;32moperator@shadowhack:~# \x1b[0m');
                    }
                } else {
                    term.write('\x1b[1;32moperator@shadowhack:~# \x1b[0m');
                }
                currentLine = '';
            }
            // Backspace
            else if (e === '\x7F') {
                if (currentLine.length > 0) {
                    term.write('\b \b');
                    currentLine = currentLine.slice(0, -1);
                }
            }
            // Normal typing
            else if (printable) {
                currentLine += e;
                term.write(e);
            }
        });

        // Resize observer
        const resizeObserver = new ResizeObserver(() => {
            fitAddon.fit();
        });
        resizeObserver.observe(terminalRef.current);

        return () => {
            term.dispose();
            resizeObserver.disconnect();
        };
    }, []);

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
            <div className="flex-1 p-1 relative">
                <div className="scanline pointer-events-none absolute inset-0 z-10 opacity-10"></div>
                <div ref={terminalRef} className="h-full w-full custom-scrollbar" />
            </div>

            {/* Status Bar */}
            <div className="px-4 py-1 bg-white/5 border-t border-white/5 text-[10px] font-mono text-gray-500 flex justify-between">
                <span>SSH: {isConnected ? 'CONNECTED (22)' : 'DISCONNECTED'}</span>
                <span>LATENCY: {isConnected ? '45ms' : 'N/A'}</span>
                <span>UPLINK: SECURE</span>
            </div>
        </div>
    );
};

export default CyberTerminal;
