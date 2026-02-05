
import http.server
import ssl
import os
import sys

# Default port
PORT = 8080

# Get the directory of the script (root of project)
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        # Override to colorize or simplify logs if needed
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format%args))

print(f"[*] Initializing Secure Frontend Server...")
print(f"[*] Root Directory: {DIRECTORY}")

# Create server
httpd = http.server.HTTPServer(('0.0.0.0', PORT), Handler)

cert_file = 'localhost.pem'
key_file = 'localhost-key.pem'

ssl_enabled = False
if os.path.exists(cert_file) and os.path.exists(key_file):
    print(f"[*] Loading SSL Certificates: {cert_file}")
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    # Wrap the socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    ssl_enabled = True
    print(f"[+] HTTPS Enabled! Secure connection ready.")
else:
    print(f"[!] Warning: Certificates not found ({cert_file}). Falling back to HTTP.")

protocol = "https" if ssl_enabled else "http"
print(f"\n==============================================")
print(f"   FRONTEND RUNNING at {protocol}://localhost:{PORT}")
print(f"==============================================\n")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\n[!] Stopping server.")
    httpd.server_close()
