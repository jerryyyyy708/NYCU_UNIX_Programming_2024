from pwn import *
import warnings

warnings.filterwarnings("ignore")
context.log_level = 'critical'

if __name__ == "__main__":
    conn = remote('ipinfo.io', 80)
    
    # Send a simple HTTP GET request
    conn.send(f"GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n")
    
    # Receive the response
    response = conn.recvall()
    
    # Close the connection
    conn.close()
    
    # Decode response and extract IP
    response = response.decode()
    ip_address = response.split('\r\n\r\n')[1].strip()
    
    print(ip_address)
