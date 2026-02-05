import re
import os

file_path = 'learn-section.js'

new_function = r"""function getSmartIcon3D(type, title) {
    const t = (title || '').toLowerCase();
    const basePath = 'assets/images/3d-icons/';
    
    // --- 0. Specific Path Matches (User Requested) ---
    if (t.includes('cyber security 101') || t.includes('intro')) return basePath + 'icon_cybersec_101_3d_1765924747485.png';
    if (t.includes('web fundamentals')) return basePath + 'icon_web_fund_3d_1765924768472.png';
    if (t.includes('linux fundamentals')) return basePath + 'icon_linux_fund_3d_1765924787847.png';
    if (t.includes('network fundamentals')) return basePath + 'icon_network_fund_3d_1765924824670.png';
    if (t.includes('soc level 1')) return basePath + 'icon_soc_level1_3d_1765924843102.png';
    if (t.includes('web application pentesting')) return basePath + 'icon_web_pentest_3d_1765924859618.png';
    if (t.includes('jr penetration tester') || t.includes('junior')) return basePath + 'icon_jr_pentester_3d_1765924888421.png';
    if (t.includes('offensive pentesting')) return basePath + 'icon_offensive_pentest_3d_1765924906299.png';
    if (t.includes('red teaming')) return basePath + 'icon_c2_3d_1765819311043.png';
    if (t.includes('exploit development')) return basePath + 'icon_exploit_dev_3d_1765819716830.png';

    // --- 1. Keyword Matching (Prioritized) ---
    /* Foundations & Pre-Sec */
    if (t.includes('pre security')) return basePath + 'icon_presec_3d_1765922821198.png';
    
    /* Core Domains */
    if (t.includes('web')) return basePath + 'icon_web_3d_1765817117593.png';
    if (t.includes('linux')) return basePath + 'icon_linux_3d_1765817009790.png';
    if (t.includes('network')) return basePath + 'icon_network_3d_1765817211308.png';
    if (t.includes('cloud')) return basePath + 'icon_cloud_sec_3d_1765922640275.png';
    if (t.includes('mobile') || t.includes('android') || t.includes('ios')) return basePath + 'icon_mobile_sec_3d_1765922679704.png';
    if (t.includes('iot') || t.includes('hardware') || t.includes('firmware')) return basePath + 'icon_iot_3d_1765922711003.png';
    
    /* Engineer & Architect */
    if (t.includes('engineer') || t.includes('architecture')) return basePath + 'icon_sec_eng_3d_1765923606392.png';
    
    /* Blue Team / SOC */
    if (t.includes('soc level 2') || t.includes('threat hunting') || t.includes('hunting')) return basePath + 'icon_hunt_3d_1765818898436.png';
    if (t.includes('soc') || t.includes('siem') || t.includes('splunk') || t.includes('log')) return basePath + 'icon_siem_3d_1765818657470.png';
    if (t.includes('incident') || t.includes('response')) return basePath + 'icon_ir_3d_1765818771664.png';
    if (t.includes('forensics') || t.includes('disk') || t.includes('memory')) return basePath + 'icon_forensics_3d_1765922362347.png';
    if (t.includes('grc') || t.includes('audit') || t.includes('compliance')) return basePath + 'icon_grc_3d_1765922791960.png';
    if (t.includes('blue') || t.includes('defens')) return basePath + 'icon_security_3d_1765817313667.png';
    if (t.includes('honeynet') || t.includes('honey')) return basePath + 'icon_honeynet_3d_1765818484701.png';
    
    /* Red Team / Offensive */
    if (t.includes('hacker') || t.includes('pentest')) return basePath + 'icon_access_3d_1765819070867.png';
    if (t.includes('offensive') || t.includes('red team') || t.includes('adversary')) return basePath + 'icon_c2_3d_1765819311043.png';
    if (t.includes('exploitation') || t.includes('exploit') || t.includes('buffer') || t.includes('development')) return basePath + 'icon_exploit_dev_3d_1765819716830.png';
    if (t.includes('metasploit') || t.includes('framework')) return basePath + 'icon_frameworks_3d_1765818576549.png';
    if (t.includes('evasion') || t.includes('bypass') || t.includes('amsi')) return basePath + 'icon_evasion_3d_1765819229136.png';
    if (t.includes('privilege') || t.includes('persistence') || t.includes('post')) return basePath + 'icon_post_3d_1765819141827.png';
    if (t.includes('phishing') || t.includes('osint') || t.includes('recon')) return basePath + 'icon_osint_3d_1765819003909.png';
    if (t.includes('malware') || t.includes('virus')) return basePath + 'icon_malware_3d_1765923577789.png';
    if (t.includes('bug bounty')) return basePath + 'icon_bug_bounty_3d_1765819664727.png';
    if (t.includes('crypto')) return basePath + 'icon_crypto_3d_1765922333633.png';
    
    /* DevOps */
    if (t.includes('devsecops') || t.includes('container') || t.includes('docker')) return basePath + 'icon_devsecops_3d_1765922752494.png';
    
    /* --- 2. Fallbacks based on Type --- */
    if (type === 'path') {
        return basePath + 'icon_learning_path_3d_1765922272083.png';
    }
    
    // Default Module
    return basePath + 'icon_modules_3d_1765922303520.png';
}"""

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern = r"function getSmartIcon3D\(type, title\) \{[\s\S]*?\}\s*(?=function renderPathCard)"
    
    match = re.search(pattern, content)
    if not match:
        print("Could not find getSmartIcon3D.")
        exit(1)
        
    new_content = re.sub(pattern, new_function + "\n\n", content, count=1)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
        
    print("Successfully updated getSmartIcon3D with new specific icons.")
    
except Exception as e:
    print(f"Error: {e}")
