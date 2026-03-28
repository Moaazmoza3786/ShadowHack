
// Force override the getOwaspCards function to ensure the buttons appear
console.log("OWASP Cards Fix Loaded");

if (typeof window.getOwaspCards !== 'undefined') {
    window.getOwaspCards = function () {
        const owasp = [
            { id: 'A01', title: 'Broken Access Control', icon: 'lock-open', color: 'danger' },
            { id: 'A02', title: 'Cryptographic Failures', icon: 'key', color: 'warning' },
            { id: 'A03', title: 'Injection', icon: 'syringe', color: 'danger' },
            { id: 'A04', title: 'Insecure Design', icon: 'pencil-ruler', color: 'info' },
            { id: 'A05', title: 'Security Misconfiguration', icon: 'gears', color: 'warning' },
            { id: 'A06', title: 'Vulnerable and Outdated Components', icon: 'box-archive', color: 'secondary' },
            { id: 'A07', title: 'Identification and Authentication Failures', icon: 'id-card', color: 'dark' },
            { id: 'A08', title: 'Software and Data Integrity Failures', icon: 'code-branch', color: 'info' },
            { id: 'A09', title: 'Security Logging and Monitoring Failures', icon: 'file-waveform', color: 'primary' },
            { id: 'A10', title: 'Server-Side Request Forgery', icon: 'server', color: 'danger' }
        ];

        return owasp.map(item => `
        <div class="col-md-4 col-sm-6">
          <div class="card h-100 text-center p-3 shadow-sm border-${item.color}">
            <div class="card-body">
              <div class="display-4 text-${item.color} mb-3">
                <i class="fa-solid fa-${item.icon}"></i>
              </div>
              <h5 class="card-title">${item.id}: ${item.title}</h5>
              <div class="d-flex gap-2 justify-content-center mt-3">
                <button class="btn btn-primary btn-sm flex-grow-1" onclick="startOwaspLearn('${item.id}')">
                  <i class="fa-solid fa-book-open me-1"></i> ${txt('تعلم', 'Learn')}
                </button>
                <button class="btn btn-outline-${item.color} btn-sm flex-grow-1" onclick="startOwaspPractice('${item.id}')">
                  <i class="fa-solid fa-gamepad me-1"></i> ${txt('تدريب', 'Practice')}
                </button>
              </div>
            </div>
          </div>
        </div>
      `).join('');
    };
    console.log("OWASP Cards Function Overridden");
}
