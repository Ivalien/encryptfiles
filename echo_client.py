import socket
import tqdm
import os
from Crypto.Cipher import AES
import nacl.bindings
from nacl import encoding
from Crypto import Random
# Se crea el socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Espaciador para separar la trama del archivo
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096  # 4KB

# Se inidica el nombre y puerto del host del servidor
server_address = ('localhost', 5001)
print('Conexion a: {} puerto: {}'.format(*server_address))
sock.connect(server_address)
#Se indica el archivo que se va enviar por medio del socket
filename="SecretText"
filesize=os.path.getsize(filename)
# Envia el archivo mediante el socket
sock.send(f"{filename}{SEPARATOR}{filesize}".encode())
# Barra de progreso
progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(filename, "rb") as f:
    while True:
        # Se lee la cantidad de bytes del archivo
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
        # Se verifica que la informacion haya sido enviada por el socket
        sock.sendall(bytes_read)
        # Actualiza el progreso de la barra
        progress.update(len(bytes_read))

sock.close()
