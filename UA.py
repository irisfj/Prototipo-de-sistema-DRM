from socket import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import ast
import os
import time

#Funciones

#Encriptador simétrico 
def encriptador_simetrico(data, aes_cipher): #Encriptador simetrico
    encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def desencriptador_simetrico(data, aes_cipher, modo='CBC'): #desencriptados simetrico
    decryptor = aes_cipher.decryptor()
    if modo == 'CBC':
        unpadder = padding.PKCS7(128).unpadder()
        try:
            decrypted_padded = decryptor.update(data) + decryptor.finalize()
            return unpadder.update(decrypted_padded) + unpadder.finalize()
        except ValueError:
            # Fallback si el padding falla o ya estaba limpio
            return decryptor.update(data) + decryptor.finalize()
    else:
        return decryptor.update(data) + decryptor.finalize()

# Función auxiliar para leer exactamente N bytes (Maneja fragmentación TCP)
def recv_exact(sock, n_bytes):
    data = b''
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            return None
        data += packet
    return data



# CONEXIONES

#conectarse al servdor de contenidos
s_cont = socket(AF_INET, SOCK_STREAM) 
s_cont.connect(('127.0.0.1', 6001))

#conectarse al servidor de licencias
s_lic = socket(AF_INET, SOCK_STREAM)
s_lic.connect(('127.0.0.1', 5001))

#conectarse al cmd
s_cdm = socket(AF_INET, SOCK_STREAM)
s_cdm.connect(('127.0.0.1', 7001))

print("Conectado a todos los servicios.")

# HANDSHAKE
USER = b'CLIENTE' #Envía el mensaje cliente a los servidores para conectarse
s_cont.sendall(USER)
s_lic.sendall(USER)
s_cont.recv(1024) 
s_lic.recv(1024)


n_app = 24612088649047423503904606469104207964706624100241589279917355153716964082916793223787741779645313593204330948569708594643158141989008915533485720411233532401683831404011414898177953280441079380628699425008445898391027207826897457587786430945244794094833016449615151908913726951063074409173850674585881252086102170024697336557217972496696720344274294178745781478517304981597797850861234804795978312693031047556002187210456107923751956132578991258252700662206865817242406824385161708171469023037026930416849625729015959540814187086447545745827288666476270597008813349043854679207427203478932113253688322938615960951901
d_app = 3393987383703344521667727863108309496636039417518857486873874257315975142276279334726669153814555466356167370305304506219197426007074905383735556986382090255584137606447551186997928693287551381699373957512761185387016622529801269099129039621399359547004797078953826622775040165406297739794447037117504643418607642617685737844226305176949263038220161889983889732902949298883439745410668978181940779522244426725202671299893831170389643678494592865915866242853856454332937163390898800750106043645112316636962214392376226958128426937209288674519485494033274795392401091535053723493723561346753407902675920276451065171323

#Mandamos las claves que se van a usar con rsa para poder hablar cifradamente con el servidor de licencias
s_lic.sendall(b"IV") 
C_iv = int(s_lic.recv(1024).decode()) 
dec_iv = pow(C_iv, d_app, n_app) 
len_iv = (dec_iv.bit_length() + 7) // 8
iv_mensajes_lic = dec_iv.to_bytes(len_iv, byteorder='big')

s_lic.sendall(b"KEY")
C_key = int(s_lic.recv(1024).decode())
dec_key = pow(C_key, d_app, n_app)
len_key = (dec_key.bit_length() + 7) // 8
key_mensajes_lic = dec_key.to_bytes(len_key, byteorder='big')

aesCipher_lic = Cipher(algorithms.AES(key_mensajes_lic), modes.CBC(iv_mensajes_lic))

s_cdm.sendall(b"IV") 
C_iv_cdm = int(s_cdm.recv(1024).decode()) 
dec_iv_cdm = pow(C_iv_cdm, d_app, n_app) 
len_iv_cdm = (dec_iv_cdm.bit_length() + 7) // 8
iv_ua_cdm = dec_iv_cdm.to_bytes(len_iv_cdm, byteorder='big')

s_cdm.sendall(b"KEY")
C_key_cdm = int(s_cdm.recv(1024).decode())
dec_key_cdm = pow(C_key_cdm, d_app, n_app)
len_key_cdm = (dec_key_cdm.bit_length() + 7) // 8
key_ua_cdm = dec_key_cdm.to_bytes(len_key, byteorder='big')

aesCipher_ua_cdm = Cipher(algorithms.AES(key_ua_cdm), modes.CBC(iv_ua_cdm))
print("Sesión segura establecida.")

cerrar_sesion = True #Empieza el flujo principal
while cerrar_sesion:
    comando = input('\n¿Qué quieres hacer?\n\t1. Solicitar lista de archivos\n\t2. Obtener archivo\n\t3. Cerrar sesión\nOpción: ') #PReguntamos al usuario qué quiere hacer
    
    if comando == '1': #Ha elegido el listado de ficheros
        extension = input('\n ¿Quiere alguna extensión? (s/n): ') #Preguntamos si quiere alguna extensión en especifico
        if extension == 'n': #Si no pedimos todos
            s_cont.sendall(b'LIST ALL')
        else: # si si pedimos los que tengan esa extension
            ext_list = input('\n ¿Cual? (ej: .png) : ')
            mensaje_extension = f'LIST {ext_list}'
            s_cont.sendall(mensaje_extension.encode())
        # Leer buffer inicial para ver si es 200 o 201
        resp = s_cont.recv(4096).decode()
        if resp.startswith('200'): # Recibimos la lista
            print('\nFicheros disponibles:')
            if 'INICIO ENVIO LISTADO' in resp:
                partes = resp.split('INICIO ENVIO LISTADO')
                if len(partes) > 1 and partes[1]:
                    print(partes[1].replace('201 FIN ENVIO LISTADO', ''))
            
            # Seguir leyendo hasta encontrar el fin
            while '201 FIN ENVIO LISTADO' not in resp:
                chunk = s_cont.recv(4096).decode()
                resp += chunk
                print(chunk.replace('201 FIN ENVIO LISTADO', ''))
            
    elif comando == '2': #Pedimos obtener un archivo
        nombre = input("\nNombre del archivo: ") #Pedimos el nombre del archivo junto a la extension
        s_cont.sendall(f'GET {nombre}'.encode()) #Mandamos el mensaje de que queremos un archivo al servidor de contenidos
        
        # Leer el buffer inicial (puede contener cabecera + cuerpo)
        buffer_rx = s_cont.recv(4096).decode()
        
        # Separar cabecera de cuerpo usando salto de línea
        if buffer_rx[:3] == '201': #Obtenemos larespuesta del servidor
            size_total = int(buffer_rx.split()[3]) #Quitamis todo lo que no sea el largo del manifiesto
            contenido_manifiesto= s_cont.recv(size_total) #obtenemos el contenido del manifiesto
            # Guardar manifiesto
            nombre_guardar = input('Nombre para guardar (ej: video.mp4): ')
            nombre_base = os.path.splitext(nombre_guardar)[0]
            ruta_manifiesto = os.path.abspath(f"manifiesto_{nombre_base}.txt")
                
            with open(ruta_manifiesto, 'wb') as f: f.write(contenido_manifiesto) #DEscargamos el manifiesto
            man_data = ast.literal_eval(contenido_manifiesto.decode())
                
            if "'cifrado':'no'" in str(man_data) or man_data.get('cifrado') == 'no': #No está cifrado
                s_cont.sendall(b'NEXT') 
                # Descarga no cifrado
                head_buffer = s_cont.recv(4096).decode()
                size_cont = int(head_buffer.split()[3])
                contenido = s_cont.recv(size_cont)
                with open(nombre_guardar, 'wb') as f: f.write(contenido) #Descargamos el archivo
                print("Descarga completa (Sin cifrar).")

            else: #Está cifrado
                    
                    print("Contenido cifrado. Contactando CDM...")
                    msg_sol = f"CIFRADO {man_data['keyID']}"  #preparamos el mensaje para mandar a la cmd
                    print(msg_sol)
                    # 1. Firmar
                    s_cdm.sendall(encriptador_simetrico(f"FIRMAR {msg_sol}".encode(), aesCipher_ua_cdm)) #Pedimos que nos firme un mensaje para enviar al servidor de licencias
                    firma_cifrada = s_cdm.recv(4096)
                    msg_firmado = desencriptador_simetrico(firma_cifrada, aesCipher_ua_cdm, 'CBC')
                    #Hemos recibido el mensaje firmado
                    
                    # 2. Licencia
                    s_lic.sendall(encriptador_simetrico(msg_firmado, aesCipher_lic))
                    resp_lic = desencriptador_simetrico(s_lic.recv(2048), aesCipher_lic).decode() #recibimos cuanto mide la licencia
                    if resp_lic.startswith('201'):
                        key_fichero_raw = desencriptador_simetrico(s_lic.recv(2048), aesCipher_lic) #recibimos la licencia
                        iv_fichero_raw = bytes.fromhex(man_data['iv'])
                    
                        # 3. Descargar contenido cifrado
                        s_cont.sendall(b'NEXT')
                        head_buffer = s_cont.recv(4096).decode()
                        size_cont = int(head_buffer.split()[3])
                        contenido_cifrado = s_cont.recv(size_cont)
                        
                        # 4. CDM Descifra
                        s_cdm.sendall(encriptador_simetrico(b"DESCIFRAR", aesCipher_ua_cdm))
                        s_cdm.recv(1024)
                        s_cdm.sendall(encriptador_simetrico(key_fichero_raw, aesCipher_ua_cdm))
                        s_cdm.recv(1024)
                        s_cdm.sendall(encriptador_simetrico(iv_fichero_raw, aesCipher_ua_cdm))
                        s_cdm.recv(1024)
                        s_cdm.sendall(encriptador_simetrico(man_data['modo'].encode(), aesCipher_ua_cdm))
                        s_cdm.recv(1024)

                        payload_enc = encriptador_simetrico(contenido_cifrado, aesCipher_ua_cdm)

                        s_cdm.sendall(encriptador_simetrico(f"SIZE:{len(payload_enc)}".encode(),aesCipher_ua_cdm))

                        s_cdm.sendall(payload_enc)
                        
                        # 5. Guardar
                        header_rx = desencriptador_simetrico(s_cdm.recv(2048), aesCipher_ua_cdm, 'CBC').decode()
                        size_rx = int(header_rx.split(':')[1])
                        s_cdm.sendall(encriptador_simetrico(b'ACK', aesCipher_ua_cdm))
                            
                        raw_data = recv_exact(s_cdm, size_rx)
                        if not raw_data: raw_data = b'' # Evitar crash si vacío
                            
                        contenido_final = desencriptador_simetrico(raw_data, aesCipher_ua_cdm, 'CBC')
                        
    
        
                        with open(nombre_guardar, 'wb') as f: f.write(contenido_final)
                        print("Archivo descifrado y guardado.")
        else:
            print("Error: Respuesta vacía o formato incorrecto")

    elif comando == '3':
        try:
            s_cont.sendall(b'QUIT')
            s_lic.sendall(encriptador_simetrico(b'QUIT', aesCipher_lic))
            s_cdm.sendall(encriptador_simetrico(b'QUIT', aesCipher_ua_cdm))
        except: pass
        cerrar_sesion = False

s_cont.close()
s_lic.close()
s_cdm.close()