import os
import socket
import tqdm
import nacl.bindings
from nacl import encoding
from Crypto.Cipher import AES
from Crypto import Random
# Generacion de la semilla con numeros random de acuerdo a los datos del sistema operativo
def random(size: int = 32) -> bytes:
    return os.urandom(size)
# De acuerdo al tmaño requerido de bytes de los numeros y la semilla del sistema operativo
# La funcion randombytes_deterministic regresa un valor en raw de bytes
def randombytes_deterministic(
        size: int, seed: bytes, encoder: encoding.Encoder = encoding.RawEncoder) -> bytes:
    raw_data = nacl.bindings.randombytes_buf_deterministic(size, seed)
    return encoder.encode(raw_data)
#Tamaño de llave de 32 bytes para AES-256
key = randombytes_deterministic(32, bytes(random(32)))
# Se crea un socket TCP/IP
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Se une el socket creado a puerto local 10000
server_address = ('localhost', 5001)
sock.bind(server_address)
# Recibe 4096 bytes
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
# El servidor se mantiene a la escucha de una solicutd de conexion
sock.listen(1)
#Esperando la conexion mientras que no cambie el calor a 0
print('Esperando Conexion entrante')
connection, client_address = sock.accept()
print('Conexion desde: ', client_address)
# Se recibe la informacion del archivo entrante por medio del socket del cliente
received = connection.recv(BUFFER_SIZE).decode()
filename, filesize = received.split(SEPARATOR)
filename = os.path.basename(filename)
#Convierte el tamaño de archivo a entero
filesize = int(filesize)
#Barra de progreso que indica cuanta informacion se ha obtenido
progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(filename, "wb") as f:
    while True:
        # Lee el valor del buffer que esta recibiendo
        bytes_read = connection.recv(BUFFER_SIZE)
        if not bytes_read:
            break
        # Cuando termina de leer el budder escribe en un archivo los datos
        f.write(bytes_read)
        # Actualiza la barra de profreso
        progress.update(len(bytes_read))


#Se cierra la conexion cuando termina de recibir informacion
connection.close()
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)
encrypt_file(filename,key)