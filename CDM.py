from socket import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import ast
import traceback


IP_CDM = '127.0.0.1'
PUERTO_CDM = 7001

# Claves rsa
n_app = 24612088649047423503904606469104207964706624100241589279917355153716964082916793223787741779645313593204330948569708594643158141989008915533485720411233532401683831404011414898177953280441079380628699425008445898391027207826897457587786430945244794094833016449615151908913726951063074409173850674585881252086102170024697336557217972496696720344274294178745781478517304981597797850861234804795978312693031047556002187210456107923751956132578991258252700662206865817242406824385161708171469023037026930416849625729015959540814187086447545745827288666476270597008813349043854679207427203478932113253688322938615960951901
d_app = 3393987383703344521667727863108309496636039417518857486873874257315975142276279334726669153814555466356167370305304506219197426007074905383735556986382090255584137606447551186997928693287551381699373957512761185387016622529801269099129039621399359547004797078953826622775040165406297739794447037117504643418607642617685737844226305176949263038220161889983889732902949298883439745410668978181940779522244426725202671299893831170389643678494592865915866242853856454332937163390898800750106043645112316636962214392376226958128426937209288674519485494033274795392401091535053723493723561346753407902675920276451065171323
e_app = 65537
#claves cifrado mensajes
key_ua_cdm = b'o\x93\x9d\x0c\xe6\xcc\xd8n\xdef\xfbY\xe7\x0f\xaa\xc8'
iv_ua_cdm  = b'\x16\x1b\xf1\xec\xc5\xba\r\xe8h\xd7\xaa\xcb\xe7Z\xe4C'
cipher_tunel = Cipher(algorithms.AES(key_ua_cdm), modes.CBC(iv_ua_cdm))

C_key = pow(int.from_bytes(key_ua_cdm, 'big'), e_app, n_app)
C_iv = pow(int.from_bytes(iv_ua_cdm, 'big'), e_app, n_app)

def encriptador_simetrico(data, aes_cipher):
    encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()

def desencriptador_simetrico(data, aes_cipher, modo='CBC'):
    decryptor = aes_cipher.decryptor()
    if modo == 'CBC':
        unpadder = padding.PKCS7(128).unpadder()
        padded = decryptor.update(data) + decryptor.finalize()
        return unpadder.update(padded) + unpadder.finalize()
    return decryptor.update(data) + decryptor.finalize()

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk: return None
        data += chunk
    return data

#socket cdm
s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind((IP_CDM, PUERTO_CDM))
s.listen(1)
print(f"CDM escuchando en puerto {PUERTO_CDM}...")

while True:
    conn, addr = s.accept()
    print("conectado")
    try:
        while True:
            data = conn.recv(4096)
            if not data: break
            try:
                mensaje_dec = data.decode()
            except:
                mensaje_dec = ""
            #enviado claves
            if mensaje_dec == "CLIENTE":
                conn.sendall(b"200 BIENVENIDO")
            elif mensaje_dec == "IV":
                conn.sendall(str(C_iv).encode())
            elif mensaje_dec == "KEY":
                conn.sendall(str(C_key).encode())
            
            else: #recibir claves
                mensaje = desencriptador_simetrico(data, cipher_tunel).decode()
                comando = mensaje.split(' ', 1)
                print('recibido mensaje')
                print(mensaje)
                if comando[0] == 'FIRMAR': #firmado mensaje de licencias
                    mensaje_bytes = comando[1].encode()
                    mensaje_int = int.from_bytes(mensaje_bytes, 'big')
                    firma = pow(mensaje_int, d_app, n_app) # RSA con pow()
                    paquete = mensaje_bytes + b'||' + str(firma).encode() #mensaje + la firma
                    conn.sendall(encriptador_simetrico(paquete, cipher_tunel))

                elif comando[0] == 'DESCIFRAR':
                    conn.sendall(b'ACK_START')
                
                    # 1. Recibir metadatos (Modo, Key, IV)
                    key_f = desencriptador_simetrico(conn.recv(2048), cipher_tunel)
                    key_f=ast.literal_eval(key_f.decode())
                    conn.sendall(encriptador_simetrico(b'ACK_META', cipher_tunel))
                
                    print(key_f)
                    # 2. Recibir tamaño y contenido cifrado
                    iv_f= desencriptador_simetrico(conn.recv(1024), cipher_tunel)
                    conn.sendall(encriptador_simetrico(b'ACK_MODE', cipher_tunel))

                    modo_f= desencriptador_simetrico(conn.recv(1024), cipher_tunel).decode()
                    print(modo_f)
                    conn.sendall(encriptador_simetrico(b'ACK_SIZE', cipher_tunel))
                
                    tam_total= desencriptador_simetrico(conn.recv(1024), cipher_tunel).decode()
                    print(tam_total)
                    tam_total=tam_total.split(':', 1)
                    tam_total=int(tam_total[1])
                
                    data_enc = recv_exact(conn, tam_total)
                    contenido_cifrado= desencriptador_simetrico(data_enc, cipher_tunel)                
                    if modo_f == 'CTR':
                        aes_f = Cipher(algorithms.AES(key_f), modes.CTR(iv_f))
                    else:
                        aes_f = Cipher(algorithms.AES(key_f), modes.CBC(iv_f))

                    # Usamos la función con el modo del archivo
                    contenido_limpio = desencriptador_simetrico(contenido_cifrado, aes_f, modo_f)
                    print('he descifrado')
                    # 4. Devolver a UA
                    resp_final = encriptador_simetrico(contenido_limpio, cipher_tunel)
                    header = f"SIZE:{len(resp_final)}".encode()
                    conn.sendall(encriptador_simetrico(header, cipher_tunel))
                    print('enviado el header')
                    conn.recv(1024) # Esperar ACK de la UA
                    print('recibido ACK')
                    conn.sendall(resp_final)
                    print(f">> Archivo descifrado enviado en modo {modo_f}")

                elif comando[0] == 'QUIT':
                    break
    except Exception:
        traceback.print_exc()
        
    finally:
        conn.close()