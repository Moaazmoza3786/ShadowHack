import React, { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Network, ArrowRight, Copy, Check, Calculator, Wifi, Server, Hash } from 'lucide-react';

const SubnetCalculator = () => {
    const [ipAddress, setIpAddress] = useState('192.168.1.0');
    const [cidr, setCidr] = useState(24);
    const [copied, setCopied] = useState('');

    const calculateSubnet = useMemo(() => {
        try {
            const octets = ipAddress.split('.').map(Number);
            if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
                return null;
            }

            // Calculate subnet mask
            const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
            const maskOctets = [
                (mask >>> 24) & 0xFF,
                (mask >>> 16) & 0xFF,
                (mask >>> 8) & 0xFF,
                mask & 0xFF
            ];

            // Calculate network address
            const ipBinary = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
            const networkBinary = (ipBinary & mask) >>> 0;
            const networkOctets = [
                (networkBinary >>> 24) & 0xFF,
                (networkBinary >>> 16) & 0xFF,
                (networkBinary >>> 8) & 0xFF,
                networkBinary & 0xFF
            ];

            // Calculate broadcast address
            const wildcardMask = (~mask) >>> 0;
            const broadcastBinary = (networkBinary | wildcardMask) >>> 0;
            const broadcastOctets = [
                (broadcastBinary >>> 24) & 0xFF,
                (broadcastBinary >>> 16) & 0xFF,
                (broadcastBinary >>> 8) & 0xFF,
                broadcastBinary & 0xFF
            ];

            // Calculate first and last usable host
            const totalHosts = Math.pow(2, 32 - cidr);
            const usableHosts = cidr >= 31 ? (cidr === 32 ? 1 : 2) : totalHosts - 2;

            const firstHostBinary = cidr >= 31 ? networkBinary : networkBinary + 1;
            const lastHostBinary = cidr >= 31 ? broadcastBinary : broadcastBinary - 1;

            const firstHostOctets = [
                (firstHostBinary >>> 24) & 0xFF,
                (firstHostBinary >>> 16) & 0xFF,
                (firstHostBinary >>> 8) & 0xFF,
                firstHostBinary & 0xFF
            ];

            const lastHostOctets = [
                (lastHostBinary >>> 24) & 0xFF,
                (lastHostBinary >>> 16) & 0xFF,
                (lastHostBinary >>> 8) & 0xFF,
                lastHostBinary & 0xFF
            ];

            // Wildcard mask
            const wildcardOctets = [
                255 - maskOctets[0],
                255 - maskOctets[1],
                255 - maskOctets[2],
                255 - maskOctets[3]
            ];

            // Binary representation
            const ipBinaryStr = octets.map(o => o.toString(2).padStart(8, '0')).join('.');
            const maskBinaryStr = maskOctets.map(o => o.toString(2).padStart(8, '0')).join('.');

            return {
                network: networkOctets.join('.'),
                broadcast: broadcastOctets.join('.'),
                subnetMask: maskOctets.join('.'),
                wildcardMask: wildcardOctets.join('.'),
                firstHost: firstHostOctets.join('.'),
                lastHost: lastHostOctets.join('.'),
                totalHosts: totalHosts.toLocaleString(),
                usableHosts: usableHosts.toLocaleString(),
                ipBinary: ipBinaryStr,
                maskBinary: maskBinaryStr,
                ipClass: octets[0] < 128 ? 'A' : octets[0] < 192 ? 'B' : octets[0] < 224 ? 'C' : octets[0] < 240 ? 'D' : 'E',
                cidrNotation: `${networkOctets.join('.')}/${cidr}`
            };
        } catch {
            return null;
        }
    }, [ipAddress, cidr]);

    const copyToClipboard = (text, key) => {
        navigator.clipboard.writeText(text);
        setCopied(key);
        setTimeout(() => setCopied(''), 2000);
    };

    const ResultRow = ({ label, value, copyKey }) => (
        <div className="flex items-center justify-between p-4 rounded-xl bg-white/5 hover:bg-white/10 transition-all group">
            <div>
                <div className="text-xs text-white/40 uppercase tracking-wider">{label}</div>
                <div className="font-mono text-lg text-cyan-400">{value}</div>
            </div>
            <button
                onClick={() => copyToClipboard(value, copyKey)}
                className="p-2 rounded-lg bg-white/5 opacity-0 group-hover:opacity-100 transition-all"
            >
                {copied === copyKey ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
            </button>
        </div>
    );

    return (
        <div className="max-w-5xl mx-auto space-y-12 animate-fade-in">
            {/* Header */}
            <div className="text-center space-y-4">
                <h1 className="text-5xl font-black italic tracking-tighter flex items-center justify-center gap-4 underline decoration-cyan-500/50 underline-offset-8">
                    <Network size={48} className="text-cyan-500" />
                    SUBNET CALCULATOR
                </h1>
                <p className="text-white/40 font-mono tracking-[0.3em] uppercase text-sm">CIDR ranges & network mask calculator</p>
            </div>

            {/* Input Section */}
            <div className="p-8 rounded-3xl bg-white/5 border border-white/10 space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                        <label className="text-xs text-white/40 uppercase tracking-wider flex items-center gap-2">
                            <Wifi size={14} /> IP Address
                        </label>
                        <input
                            type="text"
                            value={ipAddress}
                            onChange={(e) => setIpAddress(e.target.value)}
                            placeholder="192.168.1.0"
                            className="w-full p-4 bg-black/40 border border-white/10 rounded-xl font-mono text-xl text-cyan-400 focus:border-cyan-500/50 outline-none"
                        />
                    </div>
                    <div className="space-y-2">
                        <label className="text-xs text-white/40 uppercase tracking-wider flex items-center gap-2">
                            <Hash size={14} /> CIDR Prefix (/{cidr})
                        </label>
                        <input
                            type="range"
                            min="0"
                            max="32"
                            value={cidr}
                            onChange={(e) => setCidr(Number(e.target.value))}
                            className="w-full h-3 bg-white/10 rounded-lg appearance-none cursor-pointer accent-cyan-500"
                        />
                        <div className="flex justify-between text-xs text-white/30 font-mono">
                            <span>/0</span>
                            <span className="text-cyan-400 font-bold">/{cidr}</span>
                            <span>/32</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Results */}
            {calculateSubnet ? (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-8"
                >
                    {/* Quick Summary */}
                    <div className="p-6 rounded-2xl bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20">
                        <div className="flex items-center justify-between flex-wrap gap-4">
                            <div className="flex items-center gap-4">
                                <div className="p-4 rounded-xl bg-cyan-500/20">
                                    <Server size={32} className="text-cyan-400" />
                                </div>
                                <div>
                                    <div className="text-2xl font-black font-mono text-cyan-400">{calculateSubnet.cidrNotation}</div>
                                    <div className="text-xs text-white/40">Class {calculateSubnet.ipClass} Network</div>
                                </div>
                            </div>
                            <div className="text-right">
                                <div className="text-3xl font-black text-white">{calculateSubnet.usableHosts}</div>
                                <div className="text-xs text-white/40">Usable Hosts</div>
                            </div>
                        </div>
                    </div>

                    {/* Detailed Results */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <ResultRow label="Network Address" value={calculateSubnet.network} copyKey="network" />
                        <ResultRow label="Broadcast Address" value={calculateSubnet.broadcast} copyKey="broadcast" />
                        <ResultRow label="Subnet Mask" value={calculateSubnet.subnetMask} copyKey="mask" />
                        <ResultRow label="Wildcard Mask" value={calculateSubnet.wildcardMask} copyKey="wildcard" />
                        <ResultRow label="First Usable Host" value={calculateSubnet.firstHost} copyKey="first" />
                        <ResultRow label="Last Usable Host" value={calculateSubnet.lastHost} copyKey="last" />
                    </div>

                    {/* Binary Representation */}
                    <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                        <h3 className="text-sm font-black text-white/60 flex items-center gap-2">
                            <Calculator size={16} /> BINARY REPRESENTATION
                        </h3>
                        <div className="space-y-2 font-mono text-sm">
                            <div className="flex items-center gap-4">
                                <span className="text-white/40 w-20">IP:</span>
                                <span className="text-cyan-400">{calculateSubnet.ipBinary}</span>
                            </div>
                            <div className="flex items-center gap-4">
                                <span className="text-white/40 w-20">Mask:</span>
                                <span className="text-purple-400">{calculateSubnet.maskBinary}</span>
                            </div>
                        </div>
                    </div>

                    {/* Common Subnets Reference */}
                    <div className="p-6 rounded-2xl bg-white/5 border border-white/10 space-y-4">
                        <h3 className="text-sm font-black text-white/60">COMMON SUBNETS</h3>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                            {[
                                { cidr: '/8', mask: '255.0.0.0', hosts: '16M' },
                                { cidr: '/16', mask: '255.255.0.0', hosts: '65K' },
                                { cidr: '/24', mask: '255.255.255.0', hosts: '254' },
                                { cidr: '/25', mask: '255.255.255.128', hosts: '126' },
                                { cidr: '/26', mask: '255.255.255.192', hosts: '62' },
                                { cidr: '/27', mask: '255.255.255.224', hosts: '30' },
                                { cidr: '/28', mask: '255.255.255.240', hosts: '14' },
                                { cidr: '/30', mask: '255.255.255.252', hosts: '2' },
                            ].map(s => (
                                <button
                                    key={s.cidr}
                                    onClick={() => setCidr(parseInt(s.cidr.slice(1)))}
                                    className={`p-3 rounded-lg border transition-all ${cidr === parseInt(s.cidr.slice(1)) ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400' : 'bg-white/5 border-white/10 text-white/60 hover:border-white/30'}`}
                                >
                                    <div className="font-bold">{s.cidr}</div>
                                    <div className="text-[10px] opacity-60">{s.hosts} hosts</div>
                                </button>
                            ))}
                        </div>
                    </div>
                </motion.div>
            ) : (
                <div className="text-center py-16 text-red-400">
                    Invalid IP address format. Please enter a valid IPv4 address.
                </div>
            )}
        </div>
    );
};

export default SubnetCalculator;
