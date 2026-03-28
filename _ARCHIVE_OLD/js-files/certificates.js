// ==================== CERTIFICATES SYSTEM ====================

const certificates = {
    // State
    myCertificates: [],

    // Initialization
    init() {
        this.loadCertificates();
    },

    // Load User Certificates
    loadCertificates() {
        const saved = localStorage.getItem('studyHub_certificates');
        this.myCertificates = saved ? JSON.parse(saved) : [];
    },

    // Issue a Certificate
    issueCertificate(certId) {
        // Check if already owned
        if (this.myCertificates.find(c => c.id === certId)) return;

        const certDef = certificatesData.available.find(c => c.id === certId);
        if (!certDef) return;

        const newCert = {
            ...certDef,
            issueDate: new Date().toISOString(),
            studentName: 'Student', // In a real app, this would be the user's name
            certificateId: 'SH-' + Math.random().toString(36).substr(2, 9).toUpperCase()
        };

        this.myCertificates.push(newCert);
        this.saveCertificates();

        // Notify user
        if (typeof gamification !== 'undefined') {
            gamification.showNotification(`🎓 Certificate Earned: ${newCert.name}`, 'success');
        }
    },

    saveCertificates() {
        localStorage.setItem('studyHub_certificates', JSON.stringify(this.myCertificates));
    },

    // Generate HTML for Certificate View
    getCertificateHTML(cert) {
        const typeDef = certificatesData.types[cert.type];
        const date = new Date(cert.issueDate).toLocaleDateString('en-US', {
            year: 'numeric', month: 'long', day: 'numeric'
        });

        return `
      <div class="certificate-container" id="certificate-view-${cert.certificateId}" style="
        width: 800px; 
        height: 600px; 
        padding: 40px; 
        background: #fff; 
        color: #333; 
        font-family: 'Tajawal', sans-serif; 
        border: 10px solid ${typeDef.color}; 
        position: relative;
        margin: 0 auto;
        text-align: center;
        box-shadow: 0 0 20px rgba(0,0,0,0.1);
      ">
        <div style="
          border: 2px solid #eee; 
          height: 100%; 
          padding: 40px; 
          display: flex; 
          flex-direction: column; 
          justify-content: center; 
          align-items: center;
        ">
          <!-- Header -->
          <div style="margin-bottom: 30px;">
            <i class="fa-solid fa-${typeDef.icon}" style="font-size: 60px; color: ${typeDef.color}; margin-bottom: 20px;"></i>
            <h1 style="font-size: 48px; margin: 0; color: ${typeDef.color}; text-transform: uppercase; letter-spacing: 2px;">${typeDef.title}</h1>
            <p style="font-size: 18px; color: #666; margin-top: 10px;">Study Hub Web Pentesting Platform</p>
          </div>

          <!-- Body -->
          <div style="margin-bottom: 40px;">
            <p style="font-size: 20px; margin: 0;">This is to certify that</p>
            <h2 style="font-size: 42px; margin: 20px 0; color: #2c3e50; border-bottom: 2px solid #eee; display: inline-block; padding-bottom: 10px; min-width: 400px;">${cert.studentName}</h2>
            <p style="font-size: 20px; margin: 0;">has successfully completed the requirements for</p>
            <h3 style="font-size: 32px; margin: 20px 0; color: ${typeDef.color};">${cert.name}</h3>
            <p style="font-size: 16px; color: #777; max-width: 600px; margin: 0 auto;">${cert.description}</p>
          </div>

          <!-- Footer -->
          <div style="display: flex; justify-content: space-between; width: 100%; margin-top: auto; padding-top: 20px; border-top: 1px solid #eee;">
            <div style="text-align: left;">
              <p style="margin: 0; font-weight: bold;">Date Issued</p>
              <p style="margin: 5px 0 0;">${date}</p>
            </div>
            <div style="text-align: right;">
              <p style="margin: 0; font-weight: bold;">Certificate ID</p>
              <p style="margin: 5px 0 0; font-family: monospace;">${cert.certificateId}</p>
            </div>
          </div>
        </div>
        
        <!-- Watermark -->
        <div style="
          position: absolute; 
          top: 50%; 
          left: 50%; 
          transform: translate(-50%, -50%) rotate(-45deg); 
          font-size: 120px; 
          color: rgba(0,0,0,0.03); 
          z-index: 0; 
          pointer-events: none; 
          white-space: nowrap;
        ">STUDY HUB</div>
      </div>
    `;
    },

    // Download as PDF
    downloadPDF(certId) {
        const cert = this.myCertificates.find(c => c.certificateId === certId);
        if (!cert) return;

        // Create a temporary container for the PDF generation
        const container = document.createElement('div');
        container.innerHTML = this.getCertificateHTML(cert);
        document.body.appendChild(container);

        const element = container.firstElementChild;

        const opt = {
            margin: 0,
            filename: `Certificate-${cert.certificateId}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2 },
            jsPDF: { unit: 'px', format: [800, 600], orientation: 'landscape' }
        };

        html2pdf().set(opt).from(element).save().then(() => {
            document.body.removeChild(container);
        });
    },

    // Share on LinkedIn
    shareLinkedIn(certId) {
        const cert = this.myCertificates.find(c => c.certificateId === certId);
        if (!cert) return;

        // In a real app, this would point to a public URL of the certificate
        // For this local demo, we'll share the platform URL and certificate details
        const url = encodeURIComponent('https://studyhub-platform.com'); // Placeholder
        const title = encodeURIComponent(`I just earned the ${cert.name} certificate on Study Hub!`);
        const summary = encodeURIComponent(`Check out my achievement: ${cert.description}`);

        const linkedinUrl = `https://www.linkedin.com/shareArticle?mini=true&url=${url}&title=${title}&summary=${summary}&source=StudyHub`;

        window.open(linkedinUrl, '_blank');
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    certificates.init();
});
