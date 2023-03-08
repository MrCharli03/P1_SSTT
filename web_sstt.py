# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors  # https://docs.python.org/3/library/selectors.html
import select
import types        # Para definir el tipo de datos data
import argparse     # Leer parametros de ejecución
import os           # Obtener ruta y extension
from datetime import datetime, timedelta  # Fechas de los mensajes HTTP
import time         # Timeout conexión
import sys          # sys.exit
import re           # Analizador sintáctico
import logging      # Para imprimir logs


BUFSIZE = 8192  # Tamaño máximo del buffer que se puede utilizar
# Timout para la conexión persistente //cambiar a 5 seconds para hacer pruebas
TIMEOUT_CONNECTION = 31
MAX_ACCESOS = 10
BACKLOG = 64
MAX_AGE = 10



# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif": "image/gif", "jpg": "image/jpg", "jpeg": "image/jpeg", "png": "image/png", "htm": "text/htm",
             "html": "text/html", "css": "text/css", "js": "text/js", "ico":"image/jpg"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    return cs.send(data) 


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    datos = cs.recv(BUFSIZE)
    return datos.decode()

# cs.shutdown podria ser nesario


def cerrar_conexion(cs):
    cs.close()
    pass 

#Esta funcion envia una pagina de error hacia el cliente.
def send_error(ruta, msg, sckt):
    
    size = os.stat(ruta).st_size
    extension = ruta.split(".")[1]
    
    file=os.path.basename(ruta).split(".")  
    file = file[len(file)-1]
    
    respuesta = msg + "\r\n"
    respuesta += "Date: {}\r\n".format(datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
    respuesta += "Server: servidor.nombreorganizacion8427\r\n"
    respuesta += "Content-Length: {}\r\n".format(size)
    respuesta += "Content-Type: {}\r\n".format(filetypes.get(extension))
    respuesta += "Connection: close\r\n\r\n"
    
    with open(ruta, "rb") as f:
        buff = f.read() 
        contenido = respuesta.encode() + buff 
        enviar_mensaje(sckt, contenido)


def process_cookies(headers):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """

    cookie_value_key = ''
    cookie_value = -1
    
    if "Cookie" in headers:
        cookie_value_key = headers["Cookie"]
        cookie_value = int(cookie_value_key.split("=")[1])
        if cookie_value is None:
            return 1
        elif cookie_value >= MAX_ACCESOS:
            return MAX_ACCESOS
        elif cookie_value < MAX_ACCESOS:
            cookie_value += 1
            return cookie_value
    else:
        print("\n\nEstableciendo cookie...") 
        if cookie_value >= MAX_ACCESOS:
            return MAX_ACCESOS
        else:
            cookie_value += 1
            return cookie_value

def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)
    """
    rlist = [cs]
    wlist = []
    xlist = []
    cookie_counter = 0
    persistencia = 0
    # Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()
    while (True):
        # Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
        # sin recibir ningún mensaje o hay datos. Se utiliza select.select
        rsublist, wsublist, xsublist = select.select(rlist, wlist, xlist, TIMEOUT_CONNECTION)
        

        print("Cliente: " + str(cs.getsockname()[0])+" : "+str(cs.getsockname()[1])) 
        # * Si no es por timeout y hay datos en el socket cs.
        if rsublist:
            # * Leer los datos con recv.
            print("\n\nPETICION RECIBIDA: ")
            data = recibir_mensaje(cs)

            if not data:
                break
            print(data) 
            # * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
            # * Devuelve una lista con los atributos de las cabeceras.
            lines = data.split("\r\n")
            content_atributes = lines[0].split(" ")
            
            if len(content_atributes) != 3:
                send_error("./errores/400.html", "HTTP/1.1 400 Bad Request", cs) 
                print("Motivo: Error 400 Bad Request") 
                break

            # * Comprobar si la versión de HTTP es 1.1
            if content_atributes[2] != "HTTP/1.1":
                send_error("./errores/505.html", "HTTP/1.1 505 HTTP Version Not Supported", cs) 
                print("Motivo: Error 505 HTTP Version Not Supported")
                break

            # * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
            if content_atributes[0] != "GET" and content_atributes[0] != "POST":
                send_error("./errores/405.html", "HTTP/1.1 405 Method Not Allowed", cs)
                print("Motivo: Error 405 Method Not Allowed")    
                break

            if content_atributes[0] == "GET":
               # * Leer URL y eliminar parámetros si los hubiera
                url = content_atributes[1].split("?")[0]

                # * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                if url == "/":
                    url = "/index.html"

                # * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                abs_route = webroot + url
                # * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                
                if not os.path.isfile(abs_route):
                    send_error("./errores/404.html", "HTTP/1.1 404 Not Found", cs)
                    print("Motivo: Error 404 Not Found") 
                    break
                    
                # * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                #  el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                
                cabeceras = {}
                for line in lines[1:]:
                    if not line:
                        break
                    cabecera = line.split(": ")
                    cabeceras[cabecera[0]] = cabecera[1]

                #Si no se ha incluido la cabecera Host devolver un Error 400 Bad Request

                if not "Host":
                    send_error("./errores/400.html", "HTTP/1.1 400 Bad Request", cs) 
                    print("Motivo: Error 400 Bad Request") 
                    break
                persistencia = persistencia + 1
                #aumentamos las cookies cada vez que se accede al index.html
                if (url == "/index.html"):
                    cookie_counter = process_cookies(cabeceras)
                            
                #  Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                if (cookie_counter >= MAX_ACCESOS) or (persistencia >= MAX_ACCESOS):   
                    send_error("./errores/403.html", "HTTP/1.1 403 Forbidden", cs)
                    print("Motivo: Error 403 Forbidden")    
                    break


                # * Obtener el tamaño del recurso en bytes.
                size = os.stat(abs_route).st_size
                # * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                extension = abs_route.split(".")[1]
                # * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                # las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                # Content-Length y Content-Type.
                
                respuesta = "HTTP/1.1 200 OK\r\n"
                respuesta += "Date: {}\r\n".format(datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
                respuesta += "Server: servidor.nombreorganizacion8427\r\n"
                respuesta += "Connection: keep-alive\r\n"           
                respuesta += "Set-Cookie: cookie_counter_8427={}; Max-Age={}\r\n".format(cookie_counter, MAX_AGE)
                respuesta += "Content-Length: {}\r\n".format(size)
                respuesta += "Keep-Alive: timeout={}, max={}\r\n".format(TIMEOUT_CONNECTION, MAX_ACCESOS)
                respuesta += "Content-Type: {}\r\n".format(filetypes.get(extension))
                respuesta += "Connection: keep-alive\r\n"

                respuesta += "\r\n"
                
                # * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                # * Se abre el fichero en modo lectura y modo binario
                # * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                # * Cuando ya no hay más información para leer, se corta el bucle
                with open(abs_route, "rb") as f:
                    if (os.stat(abs_route).st_size + len(respuesta) > BUFSIZE):
                    #Envio con fragmentacion
                        enviar_mensaje(cs, respuesta.encode())
                        while (True):
                            buff = f.read(BUFSIZE)
                            if(not buff):
                                break
                            enviar_mensaje(cs, buff)
                    else:
                    #Envio normal   
                        buff = f.read() 
                        contenido = respuesta.encode() + buff 
                        enviar_mensaje(cs, contenido) 
                print("\n\nRespuesta enviada: ")
                print(respuesta) 
            else:
                cabeceras = {}
                datos = {}
                for line in lines[1:]:
                    if not line:
                        break
                    cabecera = line.split(": ")
                    cabeceras[cabecera[0]] = cabecera[1]
                tail = lines[-1]
                lista_datos = tail.split("&")
                for dato in lista_datos:
                    if not dato:
                        break
                    n = dato.split("=")
                    datos[n[0]] = n[1]

                #Compruebo que es del dominio um.es y el valor de la clave email no esta vacio y actua el servidor en consecuencia
                if (len(datos["email"])!=0):
                    if("um.es" in datos["email"]):
                        ruta="./accion_form.html"
                        size = os.stat(ruta).st_size
                        extension = ruta.split(".")[1]
                        respuesta = "HTTP/1.1 200 OK\r\n"
                        respuesta += "Content-Type: text/html\r\n"
                        respuesta += "Connection: keep-alive\r\n"
                        respuesta += "Content-Length: {}\r\n".format(size)
                        respuesta += "Keep-Alive: timeout={}, max={}\r\n\r\n".format(TIMEOUT_CONNECTION, MAX_ACCESOS)
                        with open(ruta, "rb") as f:
                            buff = f.read() 
                            contenido = respuesta.encode() + buff 
                            enviar_mensaje(cs, contenido)
                        print("\n\nRespuesta enviada: ")
                        print(respuesta+"\n") 
                        
                    else:
                        send_error("./errores/401.html", "HTTP/1.1 401 Unauthorized", cs) 
                        print("\nMotivo: Error 401 Unauthorized")
                        break 
                      
                else:
                    send_error("./errores/400.html", "HTTP/1.1 400 Bad Request", cs) 
                    print("Motivo: Error 400 Bad Request") 
                    break    
        # * Si es por timeout, se cierra el socket tras el período de persistencia.
        else:
            # * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
            print("\n\nHa salto el Timeout.")
            break

def main():
    """ Función principal del servidor
    """
    try:

        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument(
            "-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument(
            "-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true',
                            help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()

        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(
            args.host, args.port))

        logger.info("Serving files from {}".format(args.webroot))

        # Funcionalidad a realizar
        # Crea un socket TCP (SOCK_STREAM)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sckt:

            # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
            sckt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Vinculamos el socket a una IP y puerto elegidos
            sckt.bind((args.host, args.port))

            # Escucha conexiones entrantes
         
            sckt.listen(BACKLOG)
            print("Socket now listening\n\n")   

            # Bucle infinito para mantener el servidor activo indefinidamente
            # - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()
            # - Si es el proceso padre cerrar el socket que gestiona el hijo.
            while (True):

                client_shocket, client_addr = sckt.accept()
                
                pid=os.fork()   
                if pid == 0:
                    cerrar_conexion(sckt)   
                    process_web_request(client_shocket, args.webroot)
                    print("\n\nSocket del Cliente cerrado: " + str(client_shocket.getsockname()[0])+" : "+str(client_shocket.getsockname()[1]))
                    cerrar_conexion(client_shocket)    
                    sys.exit(-1)          
                else:
                    cerrar_conexion(client_shocket)

    except KeyboardInterrupt:
        True

if __name__ == "__main__":
    main()
