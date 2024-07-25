# windows - pip install cryptography pyotp argon2-cffi
# on android, termux - run 'pkg install build-essential python' first, then 'pip install cryptography pyotp argon2-cffi'
# on linux, 'sudo apt install python3 python3-pip' where 'apt' is the package manager for any Debian based distros

import json
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from getpass import getpass
import pyotp
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
import secrets

class PasswordManager:
    def __init__(self):
        self.entries = []
        self.key = None
        self.password_hasher = PasswordHasher()

    def derive_key(self, password, salt): # Derive a key from the password using Argon2.
        password_bytes = password.encode()
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=2,
            memory_cost=512,
            parallelism=2,
            hash_len=32,
            type=Type.I
        )
        return key

    def set_encryption_key(self, password): # Set the encryption key using the derived key.
        self.salt = secrets.token_bytes(16)  # Generate a random salt
        self.hashed_password = self.password_hasher.hash(password)  # Store hashed password
        self.key = self.derive_key(password, self.salt)

    def verify_password(self, password): # Verify the provided password against the stored hash.
        try:
            self.password_hasher.verify(self.hashed_password, password)
            return True
        except ValueError:
            return False

    def encrypt(self, data): # Encrypt data using AES-256 in GCM mode.
        if self.key:
            iv = secrets.token_bytes(12)  # Generate a random IV
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            data_bytes = data.encode()
            encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
            return base64.urlsafe_b64encode(iv + encryptor.tag + encrypted_data).decode()
        return data

    def decrypt(self, encrypted_data): # Decrypt data using AES-256 in GCM mode.
        if self.key:
            encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            iv = encrypted_data_bytes[:12]
            tag = encrypted_data_bytes[12:28]
            encrypted_data_bytes = encrypted_data_bytes[28:]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            try:
                decrypted_data = decryptor.update(encrypted_data_bytes) + decryptor.finalize()
                return decrypted_data.decode()
            except Exception as e:
                print(f"Decryption failed: {e}")
                return None
        return encrypted_data

    def create_new_entry(self): # Create a new entry and add it to the list.
        title = input("Enter entry title: ")
        username = input("Enter username: ")

        while True:
            password = getpass("Enter password: ")
            password_confirm = getpass("Confirm password: ")
            if password == password_confirm:
                break
            else:
                print("Passwords do not match. Please try again.")

        url = input("Enter URL (optional): ")
        otp_secret = input("Enter OTP seed (or press Enter if none): ")
        notes = input("Enter notes (optional): ")

        salt = secrets.token_bytes(16)
        encrypted_password = self.encrypt(password)
        encrypted_otp_secret = self.encrypt(otp_secret) if otp_secret else ""

        entry = {
            "title": title,
            "username": username,
            "password": encrypted_password,
            "url": url,
            "otp_secret": encrypted_otp_secret,
            "notes": notes,
            "salt": base64.urlsafe_b64encode(salt).decode()
        }
        self.entries.append(entry)
        print("Entry created successfully.")
        self.prompt_to_menu()

    def delete_entry(self): # Delete an entry from the list.
        self.view_entries()
        try:
            index = int(input("Enter entry number to delete: ")) - 1
        except ValueError:
            print("Invalid input. Please enter a number.")
            self.prompt_to_menu()
            return
        if 0 <= index < len(self.entries):
            del self.entries[index]
            print("Entry deleted successfully.")
        else:
            print("Invalid entry number.")
        self.prompt_to_menu()

    def modify_entry(self): # Modify an existing entry.
        self.view_entries()
        try:
            index = int(input("Enter entry number to modify: ")) - 1
        except ValueError:
            print("Invalid input. Please enter a number.")
            self.prompt_to_menu()
            return
        if 0 <= index < len(self.entries):
            entry = self.entries[index]
            title = entry['title']
            username = entry['username']
            password = entry['password']
            url = entry['url']
            otp_secret = entry['otp_secret']
            notes = entry['notes']

            new_title = input(f"Enter new title (leave empty to keep '{title}'): ")
            if new_title:
                entry['title'] = new_title

            new_username = input(f"Enter new username (leave empty to keep '{username}'): ")
            if new_username:
                entry['username'] = new_username

            while True:
                new_password = getpass("Enter new password (leave empty to keep current): ")
                if not new_password:
                    break
                password_confirm = getpass("Confirm new password: ")
                if new_password == password_confirm:
                    entry['password'] = new_password
                    break
                else:
                    print("Passwords do not match. Please try again.")

            new_url = input(f"Enter new URL (leave empty to keep '{url}'): ")
            if new_url:
                entry['url'] = new_url

            new_otp_secret = input(f"Enter new OTP seed (leave empty to keep current): ")
            if new_otp_secret:
                entry['otp_secret'] = new_otp_secret

            new_notes = input(f"Enter new notes (leave empty to keep current): ")
            if new_notes:
                entry['notes'] = new_notes

            self.entries[index] = entry
            print("Entry modified successfully.")
        else:
            print("Invalid entry number.")
        self.prompt_to_menu()

    def view_entries(self): # View the list of entries.
        if not self.entries:
            print("No entries available.")
            return

        for index, entry in enumerate(self.entries):
            print(f"{index + 1}. {entry['title']}")

    def access_entry(self): # Access details of a specific entry.
        self.view_entries()
        try:
            index = int(input("Enter entry number to view details: ")) - 1
        except ValueError:
            print("Invalid input. Please enter a number.")
            self.prompt_to_menu()
            return
        if 0 <= index < len(self.entries):
            entry = self.entries[index]
            print(f"Title: {entry['title']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            print(f"URL: {entry['url']}")
            print(f"OTP Seed: {entry['otp_secret']}")
            print(f"Notes: {entry['notes']}")
        else:
            print("Invalid entry number.")
        self.prompt_to_menu()

    def view_otp(self): # View OTP for a specific entry.
        self.view_entries()
        try:
            index = int(input("Enter entry number to view OTP: ")) - 1
        except ValueError:
            print("Invalid input. Please enter a number.")
            self.prompt_to_menu()
            return
        if 0 <= index < len(self.entries):
            entry = self.entries[index]
            otp_secret = entry['otp_secret']
            if otp_secret:
                totp = pyotp.TOTP(otp_secret)
                print(f"Current OTP for {entry['title']}: {totp.now()}")
            else:
                print("No OTP seed found for this entry.")
        else:
            print("Invalid entry number.")
        self.prompt_to_menu()

    def save_to_json(self, filepath): # Save entries to a JSON file with encryption.
        if not self.key:
            password = getpass("Enter encryption password: ")
            self.set_encryption_key(password)
            
        while True:
            password_confirm = getpass("Confirm encryption password: ")
            if password == password_confirm:
                break
            else:
                print("Passwords do not match. Please try again.")
        
        encrypted_entries = {
            "entries": [
                {
                    "title": self.encrypt(entry['title']),
                    "username": self.encrypt(entry['username']),
                    "password": self.encrypt(entry['password']),
                    "url": self.encrypt(entry['url']),
                    "otp_secret": self.encrypt(entry['otp_secret']) if entry['otp_secret'] else "",
                    "notes": self.encrypt(entry['notes']) if entry['notes'] else ""
                }
                for entry in self.entries
            ],
            "salt": base64.urlsafe_b64encode(self.salt).decode()
        }

        with open(filepath, 'w') as f:
            json.dump(encrypted_entries, f)
        print(f"Entries saved to {filepath}.")

    def load_from_json(self, filepath): # Load entries from a JSON file with decryption.
        with open(filepath, 'r') as f:
            encrypted_data = json.load(f)

        salt = base64.urlsafe_b64decode(encrypted_data["salt"])
        password = getpass("Enter decryption password: ")
        
        if not self.key:
            self.set_encryption_key(password)
        if not self.verify_password(password):
            print("Incorrect password. Failed to load entries.")
            self.prompt_to_menu()
            return

        self.key = self.derive_key(password, salt)

        decrypted_entries = [
            {
                "title": self.decrypt(entry['title']),
                "username": self.decrypt(entry['username']),
                "password": self.decrypt(entry['password']),
                "url": self.decrypt(entry['url']),
                "otp_secret": self.decrypt(entry['otp_secret']) if entry['otp_secret'] else "",
                "notes": self.decrypt(entry['notes']) if entry['notes'] else ""
            }
            for entry in encrypted_data["entries"]
        ]
        self.entries = decrypted_entries
        print("Entries loaded successfully.")

    def prompt_to_menu(self):
        input("\nPress Enter to return to the menu...")

def main_menu():
    manager = PasswordManager()
    while True:
        print("\ngravi-ctrl Password Manager")
        print("==========================+")
        print("1. Create new entry")
        print("2. Delete entry")
        print("3. Modify entry")
        print("4. View entries")
        print("5. Access entry")
        print("6. View OTP")
        print("7. Save to JSON")
        print("8. Load from JSON")
        print("9. Exit")
        print("")
        print("Created by Ahmed Abdelrahman")
        print("")
        choice = input("Enter your choice: ")
        print("")
        if choice == '1':
            manager.create_new_entry()
        elif choice == '2':
            manager.delete_entry()
        elif choice == '3':
            manager.modify_entry()
        elif choice == '4':
            manager.view_entries()
        elif choice == '5':
            manager.access_entry()
        elif choice == '6':
            manager.view_otp()
        elif choice == '7':
            filepath = input("Enter the file path to save JSON: ")
            manager.save_to_json(filepath)
        elif choice == '8':
            filepath = input("Enter the file path to load JSON: ")
            manager.load_from_json(filepath)
        elif choice == '9':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
