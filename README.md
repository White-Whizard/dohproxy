# DNS-over-HTTPS Proxy

A robust Python-based DNS-over-HTTPS proxy that receives standard DNS queries and forwards them to a DoH provider.

Repository: [https://github.com/White-Whizard/dohproxy.git](https://github.com/White-Whizard/dohproxy.git)

## Features

- Supports both UDP and TCP DNS queries
- Configurable DoH endpoint
- Comprehensive logging with response details
- Docker support
- Systemd service support
- Support for all DNS record types (A, AAAA, MX, CNAME, TXT, etc.)

## Requirements

- Python 3.6+
- pip packages:
  - requests
  - pyyaml
  - dnspython

## Installation

### Manual Installation

1. Clone or download this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Edit `config.yaml` as needed
4. Run the proxy:
   ```
   python dohproxy.py
   ```

### Docker Installation

1. Build the image:
   ```
   docker build -t dohproxy .
   ```
2. Run using docker-compose:
   ```
   docker-compose up -d
   ```

### Systemd Service Installation (Linux only)

For a more permanent installation on Linux systems with systemd:

1. Run the installation script as root:
   ```
   sudo ./install_service.sh
   ```

This will:
- Create an installation directory at `/opt/dohproxy/`
- Set up a dedicated Python virtual environment
- Copy necessary files
- Install required dependencies in the virtual environment
- Set appropriate permissions
- Set up and enable a systemd service
- Start the service

After installation, you can manage the service with:
```
sudo systemctl start dohproxy
sudo systemctl stop dohproxy
sudo systemctl restart dohproxy
sudo systemctl status dohproxy
```

View logs with:
```
sudo journalctl -u dohproxy
```

## Configuration

Edit `config.yaml` to change:

- Listen address and ports
- DoH provider URL
- Logging level and format
- Timeout settings

## Usage

Set your DNS server to the IP address and port where the proxy is running (default: 127.0.0.1:5300).

For example, querying Google's DNS using the proxy:
```
dig @127.0.0.1 -p 5300 google.com
```

## Testing

Run the test suite with:
```
python -m unittest test_dohproxy.py
```