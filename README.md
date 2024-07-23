# gravis-password-manager

# This is my first project on github. Just a command-line Password Manager written in Python. It allows you to create, modify, delete, and view password entries, as well as save them to and load them from an encrypted JSON file. Additionally, it supports generating Time-based One-Time Passwords (TOTP) for entries with OTP secrets.

## Features

- **Create New Entry**: Add a new password entry with title, username, password, URL, OTP seed, and notes.
- **Delete Entry**: Remove an existing password entry.
- **Modify Entry**: Update the details of an existing password entry.
- **View Entries**: List all saved password entries.
- **Access Entry Details**: View the full details of a specific password entry.
- **View OTP**: Generate and display the current TOTP for an entry with an OTP seed.
- **Save to JSON**: Encrypt and save all password entries to a JSON file.
- **Load from JSON**: Load and decrypt password entries from a JSON file.

## Installation

### Prerequisites

- Python 3.x
- `pip` (Python package installer)

### Required Libraries

Install the required libraries using `pip`:

```sh
pip install cryptography pyotp argon2-cffi
