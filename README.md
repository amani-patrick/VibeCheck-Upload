                                VibeCheck-Upload 🚀
                          

 <img width="775" height="242" alt="image" src="https://github.com/user-attachments/assets/9b485915-2251-46a6-8db1-36042b6b8948" />
Automated File Upload Arsenal & Polyglot Research Lab
VibeCheck-Upload is a security research toolkit and proof-of-concept (PoC) environment designed to exploit file upload vulnerabilities in "Vibe-Coded" applications.

    What is Vibe-Coding? As AI agents (Cursor, Lovable, Replit) allow developers to build apps at lightning speed, deep security audits are often skipped. This tool targets the common "blind spots" found in AI-generated file upload logic.

    <img width="1001" height="542" alt="image" src="https://github.com/user-attachments/assets/5066d8af-1c76-45ee-81d3-b49e90813112" />

<img width="1012" height="413" alt="image" src="https://github.com/user-attachments/assets/d8240fd8-fbbc-4825-bb58-f56ecf0182ee" />
<img width="1001" height="542" alt="image" src="https://github.com/user-attachments/assets/515f70c2-89cf-42e5-bf19-c88ffa703d4e" />



🔍 Vulnerabilities Covered
This arsenal automates the discovery of:

    Polyglot Bypasses: Using JPEG Magic Bytes (JFIF) to bypass getimagesize() and other server-side image validation.
    Extension Blacklist Bypasses: Testing variations like .phtml, .php5, and .phar.
    Double Extension Attacks: Exploiting Apache misconfigurations via shell.php.jpg.
    Configuration Overrides: Uploading a malicious .htaccess to reconfigure the server to execute images as PHP.
    MIME-Type Spoofing: Automating Content-Type header manipulation.

🛠️ Features

    Modular Scanner (vibecheck.py): A Python3 fuzzer that handles polyglot generation and multi-vector upload attempts.
    Auth Support: Built-in session handling for authenticated endpoints.
    Built-in Lab: A Dockerized environment featuring a vulnerable PHP backend to test your payloads safely.

    ![Uploading image.png…]()


🚀 Getting Started
1. Setup the Research Lab
Requirements: Docker and Docker-Compose
bash

git clone https://github.com
cd VibeCheck-Upload/lab
sudo docker-compose up -d
sudo docker exec -it upload-lab-vulnerable-app-1 chmod 777 /var/www/html/uploads

Use code with caution.
The lab is now live at http://localhost:8080.
2. Run the Arsenal
bash

python3 vibecheck.py -u http://localhost:8080/index.php -p upload

Use code with caution.
3. Achieve RCE (Remote Code Execution)
Once the tool uploads the .htaccess and vibecheck.php.jpg polyglot, trigger your shell:
bash

curl "http://localhost:8080/uploads/vibecheck.php.jpg?cmd=id" --output -

Use code with caution.
📁 Repository Structure
text

├── vibecheck.py        # The main Python automation tool
├── vibecheck_v2.py     # The improved version of vibecheck 
├── lab/
│   ├── index.php       # Vulnerable "Vibe-Coded" PHP script
│   ├── Dockerfile      # Lab environment configuration
│   └── docker-compose.yml
└── payloads/           # Generated polyglots and .htaccess files

Use code with caution.
🛡️ Mitigation Advice
To protect apps from these attacks:

    Rename Files: Strip original filenames and use UUIDs (e.g., a1b2-c3d4.dat).
    Disable Overrides: Ensure AllowOverride None is set in Apache configuration to block .htaccess uploads.
    Store Outside Webroot: Uploaded files should never be directly accessible via a URL.
    Re-encode Images: Use libraries like GD or Imagick to strip metadata and re-generate the image on the server.

⚖️ Disclaimer
This tool is for educational and ethical security research purposes only. Only use it against systems you have explicit permission to test (e.g., your own lab or an authorized Bug Bounty program). Unauthorized access to computer systems is illegal.
Author: Your Name / Amani Patrick
Research Niche: AI-Generated App Security & File Upload Vulnerabilities
