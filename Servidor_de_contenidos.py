from socket import *
from select import *
import os
from PIL import Image, ImageDraw, ImageFont
import io

#Config
dir_IP_servidor = '' 
puerto_servidor = 6001 
dir_socket_servidor = (dir_IP_servidor, puerto_servidor)
base_de_datos = "Base_de_datos"  # Nombre de la carpeta

s = socket(AF_INET, SOCK_STREAM)
s.bind(dir_socket_servidor)
s.listen(5)

potential_readers = [s]
potential_writers = []
potential_errs = []

def imagen_con_marca_agua(ruta_imagen, texto_marca):
    try:
        img = Image.open(ruta_imagen).convert("RGBA")
        draw = ImageDraw.Draw(img)
        #Cargar fuente por defecto si no hay otra
        try:
            font = ImageFont.truetype("arial.ttf", 36)
        except:
            font = ImageFont.load_default()
            
        ancho, alto = img.size
        # Posición de la marca de agua
        draw.text((20, alto - 50), texto_marca, fill=(255, 0, 0, 180), font=font)
        
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()
    except Exception as e:
        print(f"Error procesando imagen: {e}") #Por si está cifrada
        return None

def parte_cliente(sock):
    try:
        mensaje_rx = sock.recv(2048).decode()
        if not mensaje_rx: return # Cliente cerró
        
        comando = mensaje_rx.split(' ')

        if comando[0] == 'LIST':
            directorios = os.listdir(base_de_datos)
            if len(directorios) > 0:
                sock.sendall('200 INICIO ENVIO LISTADO'.encode())
                archivos = []
                for archivo in directorios:
                    # Ignoramos archivos ocultos de Mac (.DS_Store) y manifiestos
                    if archivo.startswith('.') or archivo.startswith("manifiesto") or archivo.startswith("licencias"):
                        continue
                        
                    if len(comando) > 1 and comando[1] != 'ALL':
                        if archivo.endswith(comando[1]):
                            archivos.append(archivo)
                    else:
                        archivos.append(archivo)
                        
                for i in archivos:
                    sock.sendall((i + '\n').encode())
                sock.sendall('201 FIN ENVIO LISTADO'.encode())
            else:
                sock.sendall('201 NO HAY FICHEROS?'.encode())

        elif comando[0] == 'GET':
            nombre_solicitado = comando[1]
            ruta_fichero = os.path.join(base_de_datos, nombre_solicitado) #ruta del archivo
            
            # Buscamos el manifiesto
            nombre_base = os.path.splitext(nombre_solicitado)[0]
            ruta_manifiesto = os.path.join(base_de_datos, f"manifiesto_{nombre_base}.txt")

            if os.path.exists(ruta_fichero) and os.path.exists(ruta_manifiesto): #Exiten los ficheros
                # 1. Enviar Manifiesto
                with open(ruta_manifiesto, 'rb') as cman:
                    contenido_manifiesto = cman.read() #Obtenemos el contenido del manifiesto
                
                sock.sendall(f'201 LONGITUD MANIFIESTO: {len(contenido_manifiesto)}\n'.encode())
                sock.sendall(contenido_manifiesto)
                print(f"Manifiesto de {nombre_solicitado} enviado.")
                
                # Esperar confirmación
                confirmacion = sock.recv(2048).decode()
                if confirmacion == "NEXT":
                    # 2. Enviar Fichero (con o sin marca de agua)
                    contenido = None
                    
                    # Marca de agua si es imagen
                    if nombre_solicitado.lower().endswith(('.png', '.jpg', '.jpeg')):
                        ip_usuario = sock.getpeername()[0]
                        contenido = imagen_con_marca_agua(ruta_fichero, f"Usuario: {ip_usuario}")
                    
                    # Si no es imagen o falló la marca de agua, leer normal
                    if contenido is None:
                        with open(ruta_fichero, 'rb') as fhand:
                            contenido = fhand.read()

                    sock.sendall(f'200 LONGITUD CONTENIDO: {len(contenido)}\n'.encode())
                    sock.sendall(contenido)
                    print(f"Contenido {nombre_solicitado} enviado.")
            else:
                print(f"No encontrado: {ruta_fichero}")
                sock.sendall('401 FICHERO NO ENCONTRADO'.encode())

        elif comando[0] == 'QUIT':
            sock.close()
            return

    except Exception as e:
        print(f"Error en cliente: {e}")
        sock.close()
        return

print(f"Servidor de Contenidos escuchando en puerto {puerto_servidor}...")
pasa = True
while pasa:
    ready_to_read, ready_to_write, in_error = select(potential_readers, potential_writers, potential_errs)
    for cliente in ready_to_read:
        if cliente is s:
            nuevo_cliente, direc = s.accept()
            print(f"Conexión aceptada de {direc}")
            potential_readers.append(nuevo_cliente)
        else:
            try:
                mensaje_rx = cliente.recv(2048)
                if mensaje_rx == b"CLIENTE":
                    usuario = cliente
                    usuario.sendall("200 BIENVENIDO".encode())
                    pasa = False # Salir del bucle de espera y pasar a atender
            except:
                potential_readers.remove(cliente)

# Bucle de atención dedicado al usuario conectado
recibiendo = True
while recibiendo:
    try:
        ready = select([usuario], [], [], 1)
        if ready[0]:
            parte_cliente(usuario)
    except Exception as e:
        print("Usuario desconectado:", e)
        recibiendo = False
        usuario.close()