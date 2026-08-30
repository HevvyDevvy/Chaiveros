import socket
import base64

def start_server(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen()
        print(f"Listening on {ip}:{port}...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                key = base64.b64decode(data)
                print(f"Received key: {key}")

if __name__ == "__main__":
    start_server('192.168.1.100', 12345)  
# Replace with your IP and port