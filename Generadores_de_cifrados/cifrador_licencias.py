"""Cifrador de fichero licencias"""


"""YA EJECUTADO SOLO SE EJECUTA UNA VEZ"""

"""A menos que se añada ficheros cifrados y se haya actualizado
el fichero licencias, entonces hay que cambiar el key_licencias
del servidor de licencias"""


#Importamos los paquetes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

base_de_datos="Base_de_datos"
# Nombre del archivo de entrada y salida

fichero_salida = "Base_de_datos\licencias_cifrado.txt"
ruta_licencias="Base_de_datos\licencias.txt"
# Encontramos el fichero y cogemos su contenido para ver de cuantos bytes hacemos la llave
with open(ruta_licencias, 'rb') as cman:
    contenido = cman.read()

# Clave AES de 16 bytes (puedes usar una aleatoria o fija)
key = os.urandom(16) #Creamos una clave para inicializar el algoritmo AES
print("\n",key)

iv = os.urandom(16) #Creamos una clave para inicializar el algoritmo AES
print("\n",iv)


#Ya lo hemos generado y han salido estas

iv = b'l\x84\x1e\xa0\n\x91\xb1?9\x00\x85/\x9b\x1b\xbai'
key=b'\xd7zX\x83\xaa\xed\xfd\xba\x11\xb28>WG\xf4\xb1'

aesCipher_licencias = Cipher(algorithms.AES(key), modes.CBC(iv))
aesDecryptor_licencias = aesCipher_licencias.decryptor()


def encriptador_simétrico(data,aes_cipher):
    aesEcryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)+padder.finalize()
    contenido_cifrado = aesEcryptor.update(padded_data) +aesEcryptor.finalize()
    return contenido_cifrado

def desencriptador_simétrico(data,aes_cipher):
    aesDecryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    texto_descifrado = aesDecryptor.update(data) + aesDecryptor.finalize()
    data_des = unpadder.update(texto_descifrado)+unpadder.finalize()
    return data_des

contenido_cifrado=encriptador_simétrico(contenido,aesCipher_licencias)

with open(fichero_salida, 'wb') as archivo:
    archivo.write(contenido_cifrado)
print(contenido_cifrado)