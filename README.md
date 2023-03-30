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

## Author
( Samuel Klutse ) [ https://samuelklutse.com ] ☕️