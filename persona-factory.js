/* ==================== PERSONA FACTORY 🎭 ==================== */
/* Fake Identity Generator for Social Engineering Training */

window.PersonaFactory = {
    // === NAME DATABASES ===
    names: {
        us: {
            first: ['James', 'John', 'Robert', 'Michael', 'William', 'David', 'Richard', 'Joseph', 'Thomas', 'Christopher', 'Mary', 'Patricia', 'Jennifer', 'Linda', 'Elizabeth', 'Barbara', 'Susan', 'Jessica', 'Sarah', 'Karen'],
            last: ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Anderson', 'Taylor', 'Thomas', 'Moore', 'Jackson', 'Martin', 'Lee', 'Thompson', 'White', 'Harris']
        },
        uk: {
            first: ['Oliver', 'George', 'Harry', 'Jack', 'Charlie', 'Thomas', 'James', 'William', 'Arthur', 'Henry', 'Olivia', 'Emma', 'Sophia', 'Isabella', 'Charlotte', 'Amelia', 'Emily', 'Grace', 'Lily', 'Sophie'],
            last: ['Smith', 'Jones', 'Taylor', 'Brown', 'Williams', 'Wilson', 'Johnson', 'Davies', 'Robinson', 'Wright', 'Thompson', 'Evans', 'Walker', 'White', 'Roberts', 'Green', 'Hall', 'Wood', 'Jackson', 'Clarke']
        },
        arabic: {
            first: ['Ahmed', 'Mohammed', 'Ali', 'Omar', 'Youssef', 'Khaled', 'Hassan', 'Ibrahim', 'Mahmoud', 'Tariq', 'Fatima', 'Aisha', 'Maryam', 'Noor', 'Layla', 'Sara', 'Hana', 'Rania', 'Dina', 'Yasmin'],
            last: ['Al-Hassan', 'Al-Ahmad', 'Al-Mahmoud', 'Al-Salem', 'Al-Rashid', 'Al-Farsi', 'Al-Qasim', 'Al-Nasser', 'Al-Khalil', 'Al-Jabbar', 'El-Sayed', 'Mansour', 'Fadel', 'Khoury', 'Haddad']
        },
        german: {
            first: ['Lukas', 'Leon', 'Maximilian', 'Felix', 'Paul', 'Jonas', 'Tim', 'David', 'Niklas', 'Alexander', 'Emma', 'Hannah', 'Mia', 'Sophia', 'Anna', 'Marie', 'Lena', 'Leonie', 'Julia', 'Laura'],
            last: ['Müller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner', 'Becker', 'Schulz', 'Hoffmann', 'Koch', 'Richter', 'Klein', 'Wolf', 'Schröder']
        }
    },

    // === JOB TITLES ===
    jobs: {
        it: ['IT Administrator', 'Senior Developer', 'System Administrator', 'Network Engineer', 'DevOps Engineer', 'Security Analyst', 'IT Support Specialist', 'Cloud Architect', 'Database Administrator', 'Software Engineer', 'IT Manager', 'Help Desk Technician'],
        hr: ['HR Manager', 'Recruiter', 'HR Coordinator', 'Talent Acquisition Specialist', 'HR Business Partner', 'Compensation Analyst', 'Training Manager', 'People Operations Lead'],
        finance: ['Financial Analyst', 'Accountant', 'CFO', 'Controller', 'Accounts Payable Specialist', 'Finance Manager', 'Payroll Administrator', 'Treasury Analyst', 'Auditor'],
        executive: ['CEO', 'COO', 'CTO', 'CIO', 'CISO', 'VP of Operations', 'Managing Director', 'President', 'Chief Strategy Officer'],
        sales: ['Sales Manager', 'Account Executive', 'Business Development Rep', 'Sales Director', 'Regional Sales Manager', 'Inside Sales Rep'],
        marketing: ['Marketing Manager', 'Content Strategist', 'Digital Marketing Specialist', 'Brand Manager', 'CMO', 'Social Media Manager'],
        admin: ['Executive Assistant', 'Office Manager', 'Administrative Coordinator', 'Receptionist', 'Operations Coordinator']
    },

    // === COMPANY NAME PARTS ===
    companies: {
        prefixes: ['Tech', 'Cyber', 'Global', 'Advanced', 'Secure', 'Digital', 'Cloud', 'Core', 'Net', 'Data', 'Info', 'Smart', 'Prime', 'Alpha', 'Nova', 'Apex', 'Elite', 'Pro', 'First', 'United'],
        suffixes: ['Solutions', 'Systems', 'Technologies', 'Corp', 'Inc', 'Group', 'Labs', 'Networks', 'Services', 'Dynamics', 'Innovations', 'Partners', 'Holdings', 'Industries', 'Enterprises'],
        domains: ['.com', '.io', '.co', '.net', '.tech', '.cloud']
    },

    // === SKILLS BY DEPARTMENT ===
    skills: {
        it: ['Active Directory', 'Azure', 'AWS', 'VMware', 'Linux', 'Windows Server', 'Python', 'PowerShell', 'Docker', 'Kubernetes', 'Cisco', 'Networking', 'Security+', 'CCNA', 'MCSE'],
        hr: ['Workday', 'SAP SuccessFactors', 'ADP', 'Recruiting', 'Employee Relations', 'HRIS', 'Benefits Administration', 'Performance Management'],
        finance: ['SAP', 'Oracle', 'QuickBooks', 'Excel', 'Financial Modeling', 'GAAP', 'Auditing', 'Budgeting', 'Tax Compliance'],
        executive: ['Strategic Planning', 'P&L Management', 'Board Presentations', 'M&A', 'Investor Relations', 'Change Management'],
        sales: ['Salesforce', 'HubSpot', 'CRM', 'Negotiation', 'Pipeline Management', 'B2B Sales', 'Enterprise Sales'],
        marketing: ['Google Analytics', 'SEO/SEM', 'Content Marketing', 'Social Media', 'Branding', 'Adobe Creative Suite', 'Marketing Automation']
    },

    // === UNIVERSITIES ===
    universities: [
        'MIT', 'Stanford University', 'Harvard University', 'UC Berkeley', 'Yale University', 'Columbia University', 'University of Michigan', 'UCLA', 'NYU', 'Cornell University', 'Princeton University', 'University of Texas', 'Georgia Tech', 'Carnegie Mellon', 'University of Washington', 'Oxford University', 'Cambridge University', 'Imperial College London', 'University of Toronto', 'ETH Zurich'
    ],

    // === BIO TEMPLATES ===
    bioTemplates: [
        '{years}+ years of experience in {field}. Previously worked at {prevCompany}. Passionate about {interest}.',
        'Results-driven {role} with expertise in {skill1} and {skill2}. Strong background in {field}.',
        'Experienced professional specializing in {skill1}, {skill2}, and {skill3}. {degree} from {university}.',
        'Dynamic {role} with {years}+ years driving {achievement}. Expert in {skill1} and {skill2}.',
        'Dedicated {role} focused on {interest}. Proven track record in {skill1} and {skill2}. {degree} graduate.'
    ],

    // === STATE ===
    currentPersona: null,
    savedPersonas: JSON.parse(localStorage.getItem('saved_personas') || '[]'),
    settings: {
        nationality: 'us',
        department: 'it',
        gender: 'random'
    },

    // === GENERATE PERSONA ===
    generate() {
        const nat = this.settings.nationality;
        const dept = this.settings.department;

        // Determine gender
        const gender = this.settings.gender === 'random'
            ? (Math.random() > 0.5 ? 'male' : 'female')
            : this.settings.gender;

        // Generate name
        const firstNames = this.names[nat].first;
        const lastNames = this.names[nat].last;
        const firstName = gender === 'male'
            ? firstNames.slice(0, 10)[Math.floor(Math.random() * 10)]
            : firstNames.slice(10)[Math.floor(Math.random() * 10)];
        const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];

        // Generate job
        const jobList = this.jobs[dept];
        const jobTitle = jobList[Math.floor(Math.random() * jobList.length)];

        // Generate company
        const companyName = this.generateCompanyName();
        const companyDomain = companyName.toLowerCase().replace(/[^a-z]/g, '') +
            this.companies.domains[Math.floor(Math.random() * this.companies.domains.length)];

        // Generate email
        const emailFormats = [
            `${firstName.toLowerCase()}.${lastName.toLowerCase()}`,
            `${firstName[0].toLowerCase()}${lastName.toLowerCase()}`,
            `${firstName.toLowerCase()}${lastName[0].toLowerCase()}`,
            `${firstName.toLowerCase()}_${lastName.toLowerCase()}`
        ];
        const email = emailFormats[Math.floor(Math.random() * emailFormats.length)] + '@' + companyDomain;

        // Generate phone
        const phone = this.generatePhone(nat);

        // Generate social handles
        const linkedIn = this.generateLinkedIn(firstName, lastName, jobTitle);
        const twitter = this.generateTwitter(firstName, lastName);

        // Generate skills
        const deptSkills = this.skills[dept] || this.skills.it;
        const personaSkills = this.shuffleArray([...deptSkills]).slice(0, 4);

        // Generate education
        const university = this.universities[Math.floor(Math.random() * this.universities.length)];
        const degrees = ['B.S.', 'B.A.', 'M.S.', 'MBA', 'M.A.'];
        const degree = degrees[Math.floor(Math.random() * degrees.length)];
        const majors = {
            it: ['Computer Science', 'Information Technology', 'Cybersecurity', 'Computer Engineering'],
            hr: ['Human Resources', 'Business Administration', 'Psychology', 'Organizational Behavior'],
            finance: ['Finance', 'Accounting', 'Economics', 'Business Administration'],
            executive: ['Business Administration', 'MBA', 'Economics', 'Strategic Management'],
            sales: ['Business', 'Marketing', 'Communications'],
            marketing: ['Marketing', 'Communications', 'Digital Media', 'Business'],
            admin: ['Business Administration', 'Office Management']
        };
        const major = (majors[dept] || majors.it)[Math.floor(Math.random() * majors[dept]?.length || 4)];

        // Generate bio
        const years = 5 + Math.floor(Math.random() * 15);
        const bio = this.generateBio(jobTitle, personaSkills, years, degree, major, university);

        // Generate avatar seed
        const avatarSeed = `${firstName}${lastName}${Date.now()}`;

        this.currentPersona = {
            id: Date.now(),
            firstName,
            lastName,
            fullName: `${firstName} ${lastName}`,
            gender,
            nationality: nat,
            jobTitle,
            department: dept,
            company: companyName,
            companyDomain,
            email,
            phone,
            linkedIn,
            twitter,
            skills: personaSkills,
            education: {
                degree,
                major,
                university
            },
            yearsExperience: years,
            bio,
            avatarSeed,
            createdAt: new Date().toISOString()
        };

        this.refresh();
        return this.currentPersona;
    },

    generateCompanyName() {
        const prefix = this.companies.prefixes[Math.floor(Math.random() * this.companies.prefixes.length)];
        const suffix = this.companies.suffixes[Math.floor(Math.random() * this.companies.suffixes.length)];
        return `${prefix}${suffix}`;
    },

    generatePhone(nat) {
        const formats = {
            us: () => `+1 (${this.rand(200, 999)}) ${this.rand(200, 999)}-${this.rand(1000, 9999)}`,
            uk: () => `+44 ${this.rand(1000, 9999)} ${this.rand(100000, 999999)}`,
            arabic: () => `+971 ${this.rand(50, 59)} ${this.rand(100, 999)} ${this.rand(1000, 9999)}`,
            german: () => `+49 ${this.rand(100, 999)} ${this.rand(1000000, 9999999)}`
        };
        return (formats[nat] || formats.us)();
    },

    generateLinkedIn(first, last, job) {
        const formats = [
            `${first.toLowerCase()}-${last.toLowerCase()}`,
            `${first.toLowerCase()}${last.toLowerCase()}`,
            `${first.toLowerCase()}-${last.toLowerCase()}-${this.rand(10, 99)}`
        ];
        return `linkedin.com/in/${formats[Math.floor(Math.random() * formats.length)]}`;
    },

    generateTwitter(first, last) {
        const formats = [
            `@${first.toLowerCase()}${last.toLowerCase()}`,
            `@${first.toLowerCase()}_${last[0].toLowerCase()}`,
            `@${first[0].toLowerCase()}${last.toLowerCase()}${this.rand(1, 99)}`,
            `@${first.toLowerCase()}${this.rand(100, 999)}`
        ];
        return formats[Math.floor(Math.random() * formats.length)];
    },

    generateBio(role, skills, years, degree, major, university) {
        const template = this.bioTemplates[Math.floor(Math.random() * this.bioTemplates.length)];
        const prevCompanies = ['Google', 'Microsoft', 'Amazon', 'IBM', 'Oracle', 'Cisco', 'Dell', 'HP', 'Accenture', 'Deloitte'];
        const interests = ['digital transformation', 'innovation', 'team leadership', 'process optimization', 'emerging technologies', 'strategic growth'];
        const achievements = ['business growth', 'operational excellence', 'digital initiatives', 'team performance', 'revenue growth'];

        return template
            .replace('{years}', years)
            .replace('{role}', role)
            .replace('{field}', major)
            .replace('{skill1}', skills[0] || 'technology')
            .replace('{skill2}', skills[1] || 'management')
            .replace('{skill3}', skills[2] || 'strategy')
            .replace('{prevCompany}', prevCompanies[Math.floor(Math.random() * prevCompanies.length)])
            .replace('{interest}', interests[Math.floor(Math.random() * interests.length)])
            .replace('{degree}', `${degree} ${major}`)
            .replace('{university}', university)
            .replace('{achievement}', achievements[Math.floor(Math.random() * achievements.length)]);
    },

    rand(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    },

    shuffleArray(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    },

    // === RENDER ===
    render() {
        return `
        <style>${this.getStyles()}</style>
        <div class="persona-container">
            ${this.renderHeader()}
            <div class="persona-content">
                <div class="persona-controls">
                    ${this.renderControls()}
                </div>
                <div class="persona-display">
                    ${this.currentPersona ? this.renderPersona() : this.renderEmpty()}
                </div>
                <div class="persona-sidebar">
                    ${this.renderSaved()}
                </div>
            </div>
        </div>`;
    },

    renderHeader() {
        return `
        <div class="persona-header">
            <div class="persona-title">
                <i class="fas fa-user-secret"></i>
                <span>Persona <span class="accent">Factory</span></span>
                <span class="subtitle">مصنع الهويات - Social Engineering</span>
            </div>
            <button class="generate-btn" onclick="PersonaFactory.generate()">
                <i class="fas fa-magic"></i> Generate New Persona
            </button>
        </div>`;
    },

    renderControls() {
        return `
        <div class="controls-section">
            <h3><i class="fas fa-sliders-h"></i> Configuration</h3>
            
            <div class="control-group">
                <label>Nationality</label>
                <select id="nationality-select" onchange="PersonaFactory.updateSetting('nationality', this.value)">
                    <option value="us" ${this.settings.nationality === 'us' ? 'selected' : ''}>🇺🇸 United States</option>
                    <option value="uk" ${this.settings.nationality === 'uk' ? 'selected' : ''}>🇬🇧 United Kingdom</option>
                    <option value="arabic" ${this.settings.nationality === 'arabic' ? 'selected' : ''}>🇦🇪 Arabic</option>
                    <option value="german" ${this.settings.nationality === 'german' ? 'selected' : ''}>🇩🇪 German</option>
                </select>
            </div>
            
            <div class="control-group">
                <label>Department</label>
                <select id="department-select" onchange="PersonaFactory.updateSetting('department', this.value)">
                    <option value="it" ${this.settings.department === 'it' ? 'selected' : ''}>💻 IT / Tech</option>
                    <option value="hr" ${this.settings.department === 'hr' ? 'selected' : ''}>👥 Human Resources</option>
                    <option value="finance" ${this.settings.department === 'finance' ? 'selected' : ''}>💰 Finance</option>
                    <option value="executive" ${this.settings.department === 'executive' ? 'selected' : ''}>👔 Executive</option>
                    <option value="sales" ${this.settings.department === 'sales' ? 'selected' : ''}>📈 Sales</option>
                    <option value="marketing" ${this.settings.department === 'marketing' ? 'selected' : ''}>📣 Marketing</option>
                    <option value="admin" ${this.settings.department === 'admin' ? 'selected' : ''}>📋 Admin</option>
                </select>
            </div>
            
            <div class="control-group">
                <label>Gender</label>
                <select id="gender-select" onchange="PersonaFactory.updateSetting('gender', this.value)">
                    <option value="random" ${this.settings.gender === 'random' ? 'selected' : ''}>🎲 Random</option>
                    <option value="male" ${this.settings.gender === 'male' ? 'selected' : ''}>♂️ Male</option>
                    <option value="female" ${this.settings.gender === 'female' ? 'selected' : ''}>♀️ Female</option>
                </select>
            </div>
            
            <div class="quick-actions">
                <button class="quick-btn" onclick="PersonaFactory.generate()">
                    <i class="fas fa-sync"></i> Regenerate
                </button>
            </div>
        </div>`;
    },

    renderEmpty() {
        return `
        <div class="empty-state">
            <i class="fas fa-user-secret"></i>
            <h3>No Persona Generated</h3>
            <p>Click "Generate New Persona" to create a fake identity</p>
            <button onclick="PersonaFactory.generate()" class="generate-cta">
                <i class="fas fa-magic"></i> Generate First Persona
            </button>
        </div>`;
    },

    renderPersona() {
        const p = this.currentPersona;
        return `
        <div class="persona-card">
            <div class="persona-card-header">
                <div class="avatar">
                    <img src="https://api.dicebear.com/7.x/personas/svg?seed=${p.avatarSeed}" alt="Avatar">
                </div>
                <div class="persona-identity">
                    <h2>${p.fullName}</h2>
                    <p class="job-title">${p.jobTitle}</p>
                    <p class="company"><i class="fas fa-building"></i> ${p.company}</p>
                </div>
                <div class="persona-actions">
                    <button onclick="PersonaFactory.savePersona()" title="Save"><i class="fas fa-save"></i></button>
                    <button onclick="PersonaFactory.copyAll()" title="Copy All"><i class="fas fa-copy"></i></button>
                    <button onclick="PersonaFactory.exportJSON()" title="Export JSON"><i class="fas fa-download"></i></button>
                </div>
            </div>
            
            <div class="persona-details">
                <div class="detail-section">
                    <h4><i class="fas fa-address-card"></i> Contact Information</h4>
                    <div class="detail-grid">
                        <div class="detail-item" onclick="PersonaFactory.copy('${p.email}')">
                            <span class="label"><i class="fas fa-envelope"></i> Email</span>
                            <span class="value">${p.email}</span>
                        </div>
                        <div class="detail-item" onclick="PersonaFactory.copy('${p.phone}')">
                            <span class="label"><i class="fas fa-phone"></i> Phone</span>
                            <span class="value">${p.phone}</span>
                        </div>
                        <div class="detail-item" onclick="PersonaFactory.copy('${p.linkedIn}')">
                            <span class="label"><i class="fab fa-linkedin"></i> LinkedIn</span>
                            <span class="value">${p.linkedIn}</span>
                        </div>
                        <div class="detail-item" onclick="PersonaFactory.copy('${p.twitter}')">
                            <span class="label"><i class="fab fa-twitter"></i> Twitter</span>
                            <span class="value">${p.twitter}</span>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-user-tie"></i> Professional Background</h4>
                    <div class="bio-text">${p.bio}</div>
                    <div class="experience-badge">
                        <i class="fas fa-briefcase"></i> ${p.yearsExperience} years experience
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-graduation-cap"></i> Education</h4>
                    <div class="education-info">
                        <span class="degree">${p.education.degree} in ${p.education.major}</span>
                        <span class="university"><i class="fas fa-university"></i> ${p.education.university}</span>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4><i class="fas fa-tools"></i> Skills</h4>
                    <div class="skills-tags">
                        ${p.skills.map(s => `<span class="skill-tag">${s}</span>`).join('')}
                    </div>
                </div>
            </div>
        </div>`;
    },

    renderSaved() {
        return `
        <div class="saved-section">
            <h3><i class="fas fa-users"></i> Saved Personas (${this.savedPersonas.length})</h3>
            ${this.savedPersonas.length === 0 ? `
                <p class="no-saved">No saved personas yet</p>
            ` : `
                <div class="saved-list">
                    ${this.savedPersonas.map((p, i) => `
                        <div class="saved-item" onclick="PersonaFactory.loadPersona(${i})">
                            <img src="https://api.dicebear.com/7.x/personas/svg?seed=${p.avatarSeed}" class="mini-avatar">
                            <div class="saved-info">
                                <span class="saved-name">${p.fullName}</span>
                                <span class="saved-job">${p.jobTitle}</span>
                            </div>
                            <button class="delete-btn" onclick="event.stopPropagation(); PersonaFactory.deleteSaved(${i})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    `).join('')}
                </div>
            `}
        </div>`;
    },

    // === ACTIONS ===
    updateSetting(key, value) {
        this.settings[key] = value;
    },

    savePersona() {
        if (!this.currentPersona) return;
        this.savedPersonas.push(this.currentPersona);
        localStorage.setItem('saved_personas', JSON.stringify(this.savedPersonas));
        this.showNotification('Persona saved!', 'success');
        this.refresh();
    },

    loadPersona(index) {
        this.currentPersona = this.savedPersonas[index];
        this.refresh();
    },

    deleteSaved(index) {
        this.savedPersonas.splice(index, 1);
        localStorage.setItem('saved_personas', JSON.stringify(this.savedPersonas));
        this.refresh();
    },

    copy(text) {
        navigator.clipboard.writeText(text);
        this.showNotification('Copied!', 'success');
    },

    copyAll() {
        if (!this.currentPersona) return;
        const p = this.currentPersona;
        const text = `
Name: ${p.fullName}
Job: ${p.jobTitle}
Company: ${p.company}
Email: ${p.email}
Phone: ${p.phone}
LinkedIn: ${p.linkedIn}
Twitter: ${p.twitter}
Education: ${p.education.degree} ${p.education.major}, ${p.education.university}
Bio: ${p.bio}
Skills: ${p.skills.join(', ')}
        `.trim();
        navigator.clipboard.writeText(text);
        this.showNotification('All details copied!', 'success');
    },

    exportJSON() {
        if (!this.currentPersona) return;
        const json = JSON.stringify(this.currentPersona, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `persona_${this.currentPersona.firstName}_${this.currentPersona.lastName}.json`;
        a.click();
        URL.revokeObjectURL(url);
    },

    refresh() {
        const container = document.querySelector('.persona-container');
        if (container) {
            container.outerHTML = this.render();
        }
    },

    showNotification(msg, type = 'info') {
        const notif = document.createElement('div');
        notif.className = `persona-notif ${type}`;
        notif.innerHTML = `<i class="fas fa-check-circle"></i> ${msg}`;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 2000);
    },

    // === STYLES ===
    getStyles() {
        return `
        .persona-container { min-height: 100vh; background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%); color: #fff; font-family: 'Rajdhani', sans-serif; padding: 20px; }
        
        .persona-header { display: flex; justify-content: space-between; align-items: center; padding: 20px 30px; background: rgba(0,0,0,0.4); border-radius: 15px; margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }
        .persona-title { display: flex; align-items: center; gap: 15px; font-size: 1.8rem; font-weight: 700; }
        .persona-title i { color: #e91e63; font-size: 2rem; }
        .persona-title .accent { color: #e91e63; }
        .persona-title .subtitle { font-size: 0.9rem; color: rgba(255,255,255,0.5); margin-left: 15px; }
        
        .generate-btn { background: linear-gradient(135deg, #e91e63, #9c27b0); border: none; color: #fff; padding: 15px 30px; border-radius: 10px; font-size: 1.1rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: all 0.3s; }
        .generate-btn:hover { transform: scale(1.05); box-shadow: 0 10px 30px rgba(233,30,99,0.3); }
        
        .persona-content { display: grid; grid-template-columns: 280px 1fr 280px; gap: 25px; }
        @media (max-width: 1200px) { .persona-content { grid-template-columns: 1fr; } }
        
        /* Controls */
        .controls-section { background: rgba(0,0,0,0.4); padding: 25px; border-radius: 15px; }
        .controls-section h3 { margin: 0 0 20px; display: flex; align-items: center; gap: 10px; font-size: 1.1rem; }
        .control-group { margin-bottom: 20px; }
        .control-group label { display: block; margin-bottom: 8px; color: rgba(255,255,255,0.7); font-size: 0.9rem; }
        .control-group select { width: 100%; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 12px; color: #fff; cursor: pointer; }
        .control-group select:focus { outline: none; border-color: #e91e63; }
        
        .quick-actions { display: flex; gap: 10px; margin-top: 20px; }
        .quick-btn { flex: 1; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 10px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.2s; }
        .quick-btn:hover { background: rgba(255,255,255,0.1); }
        
        /* Empty State */
        .empty-state { background: rgba(0,0,0,0.4); border: 2px dashed rgba(255,255,255,0.1); border-radius: 20px; padding: 80px 40px; text-align: center; }
        .empty-state i { font-size: 5rem; color: rgba(255,255,255,0.2); margin-bottom: 20px; }
        .empty-state h3 { margin: 0 0 10px; }
        .empty-state p { color: rgba(255,255,255,0.5); margin-bottom: 30px; }
        .generate-cta { background: linear-gradient(135deg, #e91e63, #9c27b0); border: none; color: #fff; padding: 15px 30px; border-radius: 10px; font-size: 1rem; cursor: pointer; }
        
        /* Persona Card */
        .persona-card { background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); border-radius: 20px; overflow: hidden; }
        .persona-card-header { display: flex; gap: 20px; padding: 30px; background: linear-gradient(135deg, rgba(233,30,99,0.2), rgba(156,39,176,0.2)); align-items: center; }
        .avatar { width: 100px; height: 100px; border-radius: 50%; overflow: hidden; border: 3px solid #e91e63; }
        .avatar img { width: 100%; height: 100%; object-fit: cover; }
        .persona-identity { flex: 1; }
        .persona-identity h2 { margin: 0 0 5px; font-size: 1.8rem; }
        .persona-identity .job-title { color: #e91e63; font-size: 1.1rem; margin: 0 0 5px; }
        .persona-identity .company { color: rgba(255,255,255,0.6); margin: 0; }
        .persona-actions { display: flex; gap: 10px; }
        .persona-actions button { background: rgba(255,255,255,0.1); border: none; color: #fff; width: 40px; height: 40px; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
        .persona-actions button:hover { background: #e91e63; }
        
        .persona-details { padding: 25px; }
        .detail-section { margin-bottom: 25px; }
        .detail-section h4 { display: flex; align-items: center; gap: 10px; margin: 0 0 15px; color: #e91e63; font-size: 1rem; }
        
        .detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
        @media (max-width: 600px) { .detail-grid { grid-template-columns: 1fr; } }
        .detail-item { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; cursor: pointer; transition: all 0.2s; }
        .detail-item:hover { background: rgba(255,255,255,0.1); }
        .detail-item .label { display: flex; align-items: center; gap: 8px; color: rgba(255,255,255,0.5); font-size: 0.85rem; margin-bottom: 5px; }
        .detail-item .value { font-size: 0.95rem; word-break: break-all; }
        
        .bio-text { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; line-height: 1.6; color: rgba(255,255,255,0.8); margin-bottom: 15px; }
        .experience-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(233,30,99,0.2); color: #e91e63; padding: 8px 15px; border-radius: 20px; font-size: 0.9rem; }
        
        .education-info { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; }
        .education-info .degree { display: block; font-size: 1rem; margin-bottom: 5px; }
        .education-info .university { color: rgba(255,255,255,0.6); display: flex; align-items: center; gap: 8px; }
        
        .skills-tags { display: flex; flex-wrap: wrap; gap: 10px; }
        .skill-tag { background: rgba(0,255,136,0.15); color: #00ff88; padding: 6px 12px; border-radius: 5px; font-size: 0.85rem; }
        
        /* Saved Section */
        .saved-section { background: rgba(0,0,0,0.4); padding: 25px; border-radius: 15px; }
        .saved-section h3 { margin: 0 0 20px; display: flex; align-items: center; gap: 10px; font-size: 1.1rem; }
        .no-saved { color: rgba(255,255,255,0.4); text-align: center; padding: 20px; }
        .saved-list { display: flex; flex-direction: column; gap: 10px; max-height: 500px; overflow-y: auto; }
        .saved-item { display: flex; align-items: center; gap: 12px; background: rgba(255,255,255,0.05); padding: 12px; border-radius: 10px; cursor: pointer; transition: all 0.2s; }
        .saved-item:hover { background: rgba(255,255,255,0.1); }
        .mini-avatar { width: 40px; height: 40px; border-radius: 50%; }
        .saved-info { flex: 1; }
        .saved-name { display: block; font-weight: 600; font-size: 0.95rem; }
        .saved-job { color: rgba(255,255,255,0.5); font-size: 0.8rem; }
        .delete-btn { background: rgba(239,68,68,0.2); border: none; color: #ef4444; padding: 8px; border-radius: 5px; cursor: pointer; }
        
        .persona-notif { position: fixed; top: 20px; right: 20px; padding: 15px 25px; background: rgba(34,197,94,0.9); color: #fff; border-radius: 8px; z-index: 10000; animation: slideIn 0.3s; font-weight: 600; display: flex; align-items: center; gap: 10px; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        `;
    }
};

// Page function
function pagePersonaFactory() {
    return PersonaFactory.render();
}
window.pagePersonaFactory = pagePersonaFactory;
