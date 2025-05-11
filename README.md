<div align="center">
  <h1>Nexus Port Scanner v2.0</h1>
  <p>Advanced port scanner with multiple scanning techniques and service detection.</p>
  
  ![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)

</div>

##  Features

- Multiple scan types (TCP, SYN, UDP)
- Service and version detection
- Banner grabbing
- Multi-threaded scanning
- Rate limiting
- Multiple output formats (text, JSON, CSV)
- Common port scanning
- Top port scanning
- Verbose output
- Progress tracking
- Error handling and reporting

##  Installation

```bash
# Clone the repository
git clone https://github.com/quantumvortex369/nexus-port-scanner.git
cd nexus-port-scanner

# Install dependencies
pip install -r requirements.txt
```

> **Note:** On Linux, you might need to install additional packages:
> ```bash
> # For Debian/Ubuntu
> sudo apt-get install python3-pip python3-scapy
> 
> # For CentOS/RHEL
> sudo yum install python3-pip
> ```

##  Usage

Basic usage:
```bash
python scanner.py <target> [options]
```

###  Examples

```bash
# Basic TCP scan of common ports
python scanner.py example.com

# Scan specific ports
python scanner.py example.com -p 80,443,8080

# Scan a range of ports
python scanner.py example.com -p 1-1024

# Scan top 1000 common ports
python scanner.py example.com --top-ports 1000

# Use SYN scan (requires root/Admin)
sudo python scanner.py example.com -sS

# Save results to a file
python scanner.py example.com -o scan_results

# Save results in JSON format
python scanner.py example.com --format json -o results

# Enable verbose output
python scanner.py example.com -vv
```

###  Options

```
positional arguments:
  target                Target IP address or hostname

optional arguments:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        Ports to scan (e.g., 80,443 or 1-1000)
  --top-ports TOP_PORTS
                        Scan top N most common ports
  -t THREADS, --threads THREADS
                        Number of threads to use (default: 100)
  --timeout TIMEOUT     Connection timeout in seconds (default: 1.0)
  -r RATE_LIMIT, --rate-limit RATE_LIMIT
                        Maximum requests per second (0 for unlimited)
  -o OUTPUT, --output OUTPUT
                        Output file
  --format {text,json,csv}
                        Output format (default: text)
  -sS, --syn-scan      TCP SYN scan (requires root)
  -sT, --tcp-scan      TCP connect scan (default)
  -sU, --udp-scan      UDP scan
  -v, --verbose         Increase verbosity level (-v, -vv, -vvv)
  --banner              Attempt to grab service banners
  --version             show program's version number and exit
```

## Output Formats

### Text Format
```
PORT     STATE  SERVICE
80/tcp   open   http
443/tcp  open   https
22/tcp   open   ssh
```

### JSON Format
```json
[
  {
    "port": 80,
    "state": "open",
    "service": "http",
    "banner": "Apache/2.4.41 (Ubuntu)",
    "protocol": "tcp"
  },
  ...
]
```

### CSV Format
```csv
port,state,service,banner,protocol
80,open,http,Apache/2.4.41 (Ubuntu),tcp
443,open,https,nginx/1.18.0 (Ubuntu),tcp
22,open,ssh,OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0),tcp
```

##  Disclaimer

This tool is for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any network or system.

##  Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
