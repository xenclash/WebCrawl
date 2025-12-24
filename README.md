# WebCrawl
A tool that crawls websites and scans them for vulnerabilities, such as common misconfigurations or outdated software versions in HTTP headers.

# WebCrawl: Automated Web Vulnerability Crawler
This Rust script crawls websites and scans for common misconfigurations or outdated software in HTTP headers. It’s designed for ethical hacking, bug bounty, and security research.

Prerequisites
Rust (install with the command below)
Internet access
Install Rust (copy and paste):

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Usage
Run the crawler with a target URL and crawl depth (copy and paste):

cargo run -- --url https://example.com --depth 2

Replace https://example.com with your target website.
Adjust --depth for how deep you want to crawl (default is 2).

# Features

Checks for missing security headers (e.g., X-Content-Type-Options, Strict-Transport-Security, Content-Security-Policy)
Detects outdated server software in HTTP headers
Recursively crawls links found on each page
Limits concurrent requests to avoid overwhelming target sites

# Notes
Some websites may block automated requests or require additional handling.
You can extend the script to scan for more vulnerabilities or log results.

⚖️ Ethical Use Notice

This project is intended for educational and authorized penetration testing purposes only. Before scanning any website, you must obtain explicit permission from the owner.

Unauthorized scanning of public websites or servers is illegal in many jurisdictions and strictly prohibited. Use responsibly — the goal is to improve security, not exploit vulnerabilities.
