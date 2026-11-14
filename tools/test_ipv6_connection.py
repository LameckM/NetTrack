
import socket
import threading
import time
import subprocess
import sys

server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("::1", 0))
server.listen(1)

port = server.getsockname()[1]

def accept_connection():
    connection, address = server.accept()
    print("Server accepted:", address)

    data = connection.recv(1024)
    print("Server received:", data.decode())

    connection.sendall(b"IPv6 test successful")

    # Keep the connection open for inspection.
    time.sleep(10)

    connection.close()

thread = threading.Thread(target=accept_connection)
thread.start()

client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("::1", port))

client.sendall(b"Hello IPv6")
print("Client received:", client.recv(1024).decode())

print("\nRun the following command in another terminal NOW:")
print("python .\\tools\\test_ipv6_states.py")

time.sleep(10)

client.close()
server.close()
thread.join()

print("IPv6 connection test completed.")
