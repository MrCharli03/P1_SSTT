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
TIMEOUT_CONNECTION = 20
MAX_ACCESOS = 10

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif": "image/gif", "jpg": "image/jpg", "jpeg": "image/jpeg", "png": "image/png", "htm": "text/htm",
             "html": "text/html", "css": "text/css", "js": "text/js"}

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
    print("Cerrando socket")
    pass

# Para que sirve cs en esta función


def process_cookies(headers):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """

    if "Cookie" in headers:
        cookie_counter = int(headers.split('=')[1])
        if not cookie_counter:
            return 1
        elif cookie_counter == MAX_ACCESOS:
            return MAX_ACCESOS
        elif (cookie_counter >= 1) & (cookie_counter < MAX_ACCESOS):
            cookie_counter += 1
            return cookie_counter
    pass


def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)
    """
    rlist = [cs]
    wlist = []
    xlist = []

    # Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()
    while (True):
        # Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
        # sin recibir ningún mensaje o hay datos. Se utiliza select.select
        rsublist, wsublist, xsublist = select.select(
            rlist, wlist, xlist, TIMEOUT_CONNECTION)

        # * Si no es por timeout y hay datos en el socket cs.
        if rsublist:
            # * Leer los datos con recv.
            data = recibir_mensaje(cs)
            if not data:
                cerrar_conexion(cs)
                break

            # * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
            # * Devuelve una lista con los atributos de las cabeceras.
            lines = data.split("\r\n")
            content_atributes = lines[0].split(" ")

            # * Comprobar si la versión de HTTP es 1.1
            if content_atributes[2] != "HTTP/1.1":
                return "Error 505 HTTP Version Not Supported"

            # * Comprobar si es un método GET. Si no devolver un error Error 405 "Method Not Allowed".
            if content_atributes[0] != "GET":
                return "Error 405 Method Not Allowed"

            # * Leer URL y eliminar parámetros si los hubiera
            url = content_atributes[1].split("?")[0]

            # * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
            if url == "/":
                url = "/index.html"

            # * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
            abs_route = webroot + url
            # * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
            if not os.path.isfile(abs_route):
                return "Error 404: Not found"
                # * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                #  el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.

            for line in lines[1:]:
                if not line:
                    break
                cabecera = line.split(": ")
                cabeceras = {cabecera[0] : cabecera[1]}
            cookie_counter=0      
            if "Cookie" in cabeceras:
                cookie_counter = process_cookies(cabeceras)
                #  Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                if cookie_counter >= MAX_ACCESOS:
                    return "Error 403: Forbidden"
            
            # * Obtener el tamaño del recurso en bytes.
            size = os.stat(abs_route).st_size
            # * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
            extension = abs_route.split(".")[1]
            # * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
            # las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
            # Content-Length y Content-Type.
            respuesta = "HTTP/1.1 200 OK\r\n"
            respuesta += "Date: {}\r\n".format(datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
            respuesta += "Server:{}\r\n".format(os.name)
            respuesta += "Connection: close\r\n"
            respuesta += "Set-Cookie: cookie_counter={}\r\n".format(cookie_counter)
            respuesta += "Content-Length: {}\r\n".format(size)
            respuesta += "Content-Type: {}\r\n".format(filetypes.get(extension))
            respuesta += "\r\n"
            # * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
            # * Se abre el fichero en modo lectura y modo binario
            # * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
            # * Cuando ya no hay más información para leer, se corta el bucle
            
            with open(abs_route, 'rb') as f:
                while True:
                    data = f.read(BUFSIZE)
                    if not data:
                        break
                    contenido = respuesta.encode() + data 
                    enviar_mensaje(cs, contenido)

        # * Si es por timeout, se cierra el socket tras el período de persistencia.
        else:
            # * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
            cerrar_conexion(cs)
            break

    print("msg enviados")   

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

        print('hola')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sckt:

            # Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
            sckt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Vinculamos el socket a una IP y puerto elegidos
            sckt.bind((args.host, args.port))

            # Escucha conexiones entrantes
            # opcional backlog, probar con 64
            sckt.listen()

            # Bucle infinito para mantener el servidor activo indefinidamente

            # - Aceptamos la conexión

            # - Creamos un proceso hijo

            # - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()

            # - Si es el proceso padre cerrar el socket que gestiona el hijo.
            while (True):
                conn, addr = sckt.accept()
                '''if os.fork() == 0:
                    print('hijo')
                    cerrar_conexion(sckt, )
                    process_web_request(conn, args.webroot)

                else:
                    print('padre')
                    cerrar_conexion(conn)'''
                process_web_request(conn, args.webroot)

    except KeyboardInterrupt:
        True

if __name__ == "__main__":
    main()
