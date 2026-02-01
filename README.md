# 👁️ TheWatcher

**TheWatcher** is a modular cybersecurity reconnaissance tool designed to automate network service discovery and vulnerability scanning.

---

## Purpose

The goal of **TheWatcher** is to streamline the initial phase of a penetration test or security audit. Instead of manually cross-referencing service versions with vulnerability databases, The Watcher does the heavy lifting, providing a structured data output (JSON) ready for analysis or visualization.

## Key Features

* **Service Fingerprinting:** Deep-scan network targets to identify running services and exact version numbers using `python-nmap`.
* **Automated CVE Mapping:** Real-time lookup of identified services against the **National Vulnerability Database (NVD)**.
* **Severity Scoring:** Pulls CVSS scores to help prioritize which vulnerabilities require immediate attention.
* **Structured Export:** Generates clean, machine-readable JSON reports for integration with other security tools.

## Technical Architecture

To support a future UI, **TheWatcher** follows a modular design:

* `core/engine.py`: Handles the Nmap scanning.
* `core/engine.py`: Handles the vulnerability lookup for each service of each target host.
* `utils/data_handler.py`: Parses raw data into clean JSON objects.
* `main.py`: The starting point where everything merges together.

## Getting Started

### Prerequisites

* Python 3.8+
* [Nmap](https://nmap.org/download.html) installed on your host system.

### Installation

```bash
    # Clone the repository
    git clone https://github.com/ToubiSalmane/TheWatcher.git

    # Navigate to the directory
    cd TheWatcher

    # Install dependencies
    pip install -r requirements.txt
```

### Basic Usage

* Network scanning
```bash
    python main.py --target 192.168.1.0/24
```
* Single target scanning
Make sure you specify the subnet mask as **"/32"** for single targets. 
```bash
    python main.py --target 192.168.1.10/32
```

## ⚖️ License

This project is licensed under the MIT License - see the [LICENSE] file for details.

## ⚠️ Disclaimer

*This tool is for educational and ethical security testing purposes only. Only run **TheWatcher** against systems you have explicit permission to scan. The author is not responsible for any misuse or damage caused by this tool.*