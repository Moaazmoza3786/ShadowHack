/* ============================================================
   CODE BLOCK ENHANCER - BreachLabs
   Adds copy to clipboard and syntax highlighting to code blocks
   ============================================================ */

const CodeBlockEnhancer = {
    // Initialize enhancer on the page
    init() {
        // Add CSS for enhanced code blocks
        this.injectStyles();

        // Process code blocks after short delay to ensure DOM is ready
        setTimeout(() => this.enhanceAllCodeBlocks(), 100);

        // Set up mutation observer to enhance dynamically added code blocks
        this.observeDOM();
    },

    // Inject CSS styles for code blocks
    injectStyles() {
        if (document.getElementById('code-enhancer-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'code-enhancer-styles';
        styles.textContent = `
            /* Enhanced Code Block Container */
            .enhanced-code-block {
                position: relative;
                margin: 16px 0;
                border-radius: 8px;
                overflow: hidden;
                background: #1e1e2e;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            
            /* Code Block Header */
            .code-block-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 8px 12px;
                background: #313244;
                border-bottom: 1px solid #45475a;
            }
            
            .code-block-language {
                font-size: 12px;
                font-weight: 600;
                color: #cdd6f4;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .code-copy-btn {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 4px 10px;
                background: #45475a;
                border: none;
                border-radius: 4px;
                color: #cdd6f4;
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s ease;
            }
            
            .code-copy-btn:hover {
                background: #585b70;
            }
            
            .code-copy-btn.copied {
                background: #a6e3a1;
                color: #1e1e2e;
            }
            
            /* Code Block Content */
            .enhanced-code-block pre {
                margin: 0;
                padding: 16px;
                overflow-x: auto;
                background: transparent !important;
                border: none !important;
            }
            
            .enhanced-code-block code {
                font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
                font-size: 13px;
                line-height: 1.6;
                color: #cdd6f4;
                background: transparent !important;
            }
            
            /* Syntax Highlighting - Catppuccin Theme */
            .enhanced-code-block .keyword { color: #cba6f7; }
            .enhanced-code-block .string { color: #a6e3a1; }
            .enhanced-code-block .number { color: #fab387; }
            .enhanced-code-block .comment { color: #6c7086; font-style: italic; }
            .enhanced-code-block .function { color: #89b4fa; }
            .enhanced-code-block .variable { color: #f5e0dc; }
            .enhanced-code-block .operator { color: #89dceb; }
            .enhanced-code-block .property { color: #f9e2af; }
            
            /* Line Numbers (optional) */
            .code-with-lines {
                counter-reset: line;
            }
            
            .code-with-lines .code-line {
                display: block;
                position: relative;
                padding-left: 40px;
            }
            
            .code-with-lines .code-line::before {
                counter-increment: line;
                content: counter(line);
                position: absolute;
                left: 0;
                width: 30px;
                text-align: right;
                color: #6c7086;
                padding-right: 10px;
                border-right: 1px solid #45475a;
                margin-right: 10px;
            }
            
            /* Inline code styling */
            .prose code:not(pre code) {
                background: #e2e8f0;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 0.9em;
                color: #1e293b;
            }
        `;
        document.head.appendChild(styles);
    },

    // Enhance all code blocks on the page
    enhanceAllCodeBlocks() {
        const codeBlocks = document.querySelectorAll('pre code:not(.enhanced)');
        codeBlocks.forEach(block => this.enhanceCodeBlock(block));
    },

    // Enhance a single code block
    enhanceCodeBlock(codeElement) {
        if (codeElement.classList.contains('enhanced')) return;
        codeElement.classList.add('enhanced');

        const preElement = codeElement.parentElement;
        if (!preElement || preElement.tagName !== 'PRE') return;

        // Skip if already wrapped
        if (preElement.parentElement?.classList.contains('enhanced-code-block')) return;

        // Detect language from class
        const langClass = Array.from(codeElement.classList).find(c => c.startsWith('language-'));
        const language = langClass ? langClass.replace('language-', '') : 'text';

        // Create wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'enhanced-code-block';

        // Create header
        const header = document.createElement('div');
        header.className = 'code-block-header';
        header.innerHTML = `
            <span class="code-block-language">${this.getLanguageLabel(language)}</span>
            <button class="code-copy-btn" onclick="CodeBlockEnhancer.copyCode(this)">
                <i class="fa-regular fa-copy"></i>
                <span>Copy</span>
            </button>
        `;

        // Apply syntax highlighting
        this.applySyntaxHighlighting(codeElement, language);

        // Wrap the pre element
        preElement.parentNode.insertBefore(wrapper, preElement);
        wrapper.appendChild(header);
        wrapper.appendChild(preElement);
    },

    // Get display label for language
    getLanguageLabel(lang) {
        const labels = {
            'js': 'JavaScript',
            'javascript': 'JavaScript',
            'ts': 'TypeScript',
            'typescript': 'TypeScript',
            'py': 'Python',
            'python': 'Python',
            'bash': 'Bash',
            'sh': 'Shell',
            'shell': 'Shell',
            'cmd': 'Command Prompt',
            'powershell': 'PowerShell',
            'ps1': 'PowerShell',
            'sql': 'SQL',
            'html': 'HTML',
            'css': 'CSS',
            'json': 'JSON',
            'xml': 'XML',
            'yaml': 'YAML',
            'yml': 'YAML',
            'http': 'HTTP',
            'spl': 'Splunk SPL',
            'yara': 'YARA',
            'text': 'Text',
            '': 'Code'
        };
        return labels[lang.toLowerCase()] || lang.toUpperCase();
    },

    // Apply basic syntax highlighting
    applySyntaxHighlighting(codeElement, language) {
        let code = codeElement.innerHTML;

        // Skip if it's plain text or already has highlighting
        if (!language || language === 'text' || language === '') return;

        // Define patterns for different elements
        const patterns = {
            // Comments
            comment: /(#[^\n]*|\/\/[^\n]*|\/\*[\s\S]*?\*\/)/g,
            // Strings
            string: /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g,
            // Numbers
            number: /\b(\d+\.?\d*)\b/g,
            // Keywords (for common languages)
            keyword: /\b(function|const|let|var|if|else|for|while|return|import|export|from|class|def|print|echo|sudo|grep|cat|ls|cd|pwd|chmod|chown|apt|pip|npm|git|docker|kubectl)\b/g,
            // Operators
            operator: /([=+\-*/<>!&|]+)/g,
        };

        // Apply highlighting (order matters - do comments and strings first)
        code = code.replace(patterns.comment, '<span class="comment">$1</span>');
        code = code.replace(patterns.string, '<span class="string">$1</span>');
        code = code.replace(patterns.number, '<span class="number">$1</span>');
        code = code.replace(patterns.keyword, '<span class="keyword">$1</span>');

        codeElement.innerHTML = code;
    },

    // Copy code to clipboard
    async copyCode(button) {
        const wrapper = button.closest('.enhanced-code-block');
        const codeElement = wrapper.querySelector('code');

        if (!codeElement) return;

        // Get text content (without HTML tags)
        const text = codeElement.textContent;

        try {
            await navigator.clipboard.writeText(text);

            // Update button state
            const icon = button.querySelector('i');
            const label = button.querySelector('span');

            button.classList.add('copied');
            icon.className = 'fa-solid fa-check';
            label.textContent = 'Copied!';

            // Reset after 2 seconds
            setTimeout(() => {
                button.classList.remove('copied');
                icon.className = 'fa-regular fa-copy';
                label.textContent = 'Copy';
            }, 2000);

            // Show toast if available
            if (typeof showToast === 'function') {
                showToast('Code copied to clipboard!', 'success', 2000);
            }
        } catch (err) {
            console.error('Failed to copy code:', err);
            if (typeof showToast === 'function') {
                showToast('Failed to copy code', 'error');
            }
        }
    },

    // Observe DOM for dynamically added content
    observeDOM() {
        const observer = new MutationObserver((mutations) => {
            let hasNewContent = false;
            mutations.forEach(mutation => {
                if (mutation.addedNodes.length > 0) {
                    hasNewContent = true;
                }
            });

            if (hasNewContent) {
                // Debounce the enhancement
                clearTimeout(this.enhanceTimeout);
                this.enhanceTimeout = setTimeout(() => this.enhanceAllCodeBlocks(), 200);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    CodeBlockEnhancer.init();
});

// Also init if DOM is already loaded
if (document.readyState !== 'loading') {
    CodeBlockEnhancer.init();
}

// Export globally
window.CodeBlockEnhancer = CodeBlockEnhancer;
