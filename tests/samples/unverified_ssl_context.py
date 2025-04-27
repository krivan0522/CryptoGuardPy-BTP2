import ssl
import socket

def create_insecure_context():
    # Vulnerable: Creating an insecure SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def connect_insecure(host, port):
    # Vulnerable: Using insecure SSL connection
    sock = socket.create_connection((host, port))
    context = create_insecure_context()
    ssl_sock = context.wrap_socket(sock, server_hostname=host)
    return ssl_sock

# Example usage
try:
    connection = connect_insecure('example.com', 443)
except:
    pass 