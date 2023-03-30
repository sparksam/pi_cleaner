# USB Cleaner

This project is a simple script to clean up USB drives on Linux. It is intended to be run every time a USB drive is plugged in.
The current implementation works works with a Raspberry Pi 4 running Raspbian.

## Installation
```bash
git clone github.com/sparksam/pi_cleaner
cd pi_cleaner
python3.10 -m venv venv --upgrade-deps
source venv/bin/activate
pip install -r requirements.txt
python main.py --help
```

## Usage
```bash

usage: main.py [-h] [--provider {orion,virus_total}] [--key KEY] [--scan] [--path PATH]
               [--tls-certificate TLS_CERTIFICATE] [--visibility {public,group,private}] [--format] [--delete-malwares]

USB Cleaner - A tool to clean USB devices from malware The current version support the VirusTotal API, and Orion to scan
the files. Follow me on Github: @sparksam

options:
  -h, --help            show this help message and exit
  --provider {orion,virus_total}
                        Specify the Malware scanner to use: orion or virus_total
  --key KEY             API key to use for provider
  --scan                Scan the files for malware
  --path PATH           Path of the directory/file to scan
  --tls-certificate TLS_CERTIFICATE
                        Path to the TLS CA certificate bunde. eg: tls-certificate.pem
  --visibility {public,group,private}
                        Visibility of generated task(s)
  --format              Format the device
  --delete-malwares     Delete malicious files

```

## Author
- @sparksam ☕️