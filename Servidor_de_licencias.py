from socket import *
from select import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import traceback

# Config
puerto_servidor = 5001 
s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind(('', puerto_servidor))
s.listen(5)

potential_readers = [s]
base_de_datos = "Base_de_datos"
ruta_licencias = "Base_de_datos/licencias_cifrado.txt"

# Claves de licencia
key_mensajes = b'o\x93\x9d\x0c\xe6\xcc\xd8n\xdef\xfbY\xe7\x0f\xaa\xc8'
iv_mensajes = b'\x16\x1b\xf1\xec\xc5\xba\r\xe8h\xd7\xaa\xcb\xe7Z\xe4C'
aesCipher_mensajes = Cipher(algorithms.AES(key_mensajes), modes.CBC(iv_mensajes))

# Claves para leer el fichero 
iv_licencias = b'l\x84\x1e\xa0\n\x91\xb1?9\x00\x85/\x9b\x1b\xbai'
key_licencias = b'\xd7zX\x83\xaa\xed\xfd\xba\x11\xb28>WG\xf4\xb1'
aesCipher_licencias = Cipher(algorithms.AES(key_licencias), modes.CBC(iv_licencias))

# RSA 
n_app = 24612088649047423503904606469104207964706624100241589279917355153716964082916793223787741779645313593204330948569708594643158141989008915533485720411233532401683831404011414898177953280441079380628699425008445898391027207826897457587786430945244794094833016449615151908913726951063074409173850674585881252086102170024697336557217972496696720344274294178745781478517304981597797850861234804795978312693031047556002187210456107923751956132578991258252700662206865817242406824385161708171469023037026930416849625729015959540814187086447545745827288666476270597008813349043854679207427203478932113253688322938615960951901
e_app = 65537

C_key = pow(int.from_bytes(key_mensajes, 'big'), e_app, n_app)
C_iv = pow(int.from_bytes(iv_mensajes, 'big'), e_app, n_app)

def encriptador_simetrico(data, aes_cipher):
    encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()

def desencriptador_simetrico(data, aes_cipher):
    decryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        decrypted = decryptor.update(data) + decryptor.finalize()
        return unpadder.update(decrypted) + unpadder.finalize()
    except: return data 

def buscar_licencia(id_fichero):
    print(os.path.exists(ruta_licencias))
    if not os.path.exists(ruta_licencias): return None
    with open(ruta_licencias, 'rb') as f:
        datos_cifrados = f.read()
    
    licencias_raw = desencriptador_simetrico(datos_cifrados, aesCipher_licencias).decode()
    for linea in licencias_raw.split('\n'):
        if linea.strip():
            partes = linea.split(' ')
            if partes[0] == id_fichero:
                return partes[1] # Retorna la clave 
    return None

print("Servidor de Licencias activo...")

while True:
    # El select gestiona todo: nuevas conexiones y mensajes de clientes existentes
    ready_to_read, _, _ = select(potential_readers, [], [])
    
    for sock in ready_to_read:
        if sock is s:
            # Nueva conexión
            nuevo_cliente, addr = s.accept()
            print(f"Nuevo cliente conectado desde {addr}")
            potential_readers.append(nuevo_cliente)
        else:
            # Mensaje de un cliente
            try:
                data = sock.recv(4096)
                if not data: 
                    raise ConnectionResetError
                
                # Intentar decodificar mensaje (Handshake es texto plano, resto es cifrado)
                try:
                    mensaje_dec = data.decode()
                except:
                    mensaje_dec = ""

                if mensaje_dec == "CLIENTE":
                    sock.sendall(b"200 BIENVENIDO")
                elif mensaje_dec == "IV":
                    sock.sendall(str(C_iv).encode())
                elif mensaje_dec == "KEY":
                    sock.sendall(str(C_key).encode())
                else:
                    # Mensajes cifrados
                    msg_limpio = desencriptador_simetrico(data, aesCipher_mensajes).decode()
                    comando = msg_limpio.split(' ')
                    print(msg_limpio)
                    if comando[0] == 'CIFRADO':
                        id_buscado = comando[1].split('||')
                        id_buscado = id_buscado[0]
                        print(f"Buscando licencia para: {id_buscado}")
                        key_mandar = buscar_licencia(id_buscado)
                        
                        if key_mandar:
                            # Enviamos la clave encontrada
                            header = f"201 LONGITUD KEY: {len(key_mandar)}\n"
                            sock.sendall(encriptador_simetrico(header.encode(), aesCipher_mensajes))
                            sock.sendall(encriptador_simetrico(key_mandar.encode(), aesCipher_mensajes))
                            print("Licencia enviada correctamente.")
                        else:
                            sock.sendall(encriptador_simetrico(b"404 NOT FOUND", aesCipher_mensajes))

                    elif comando[0] == 'QUIT':
                        print("Cliente solicitó cerrar.")
                        potential_readers.remove(sock)
                        sock.close()

            except Exception as error:
                print(error)
                # Si hay error o el cliente cierra, limpiamos
                if sock in potential_readers:
                    potential_readers.remove(sock)
                sock.close()
                print("Conexión cerrada con un cliente.")