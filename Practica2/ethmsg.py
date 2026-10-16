'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from email.mime import message

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict
from datetime import datetime

ETHTYPE = 0x0AA0
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)




def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente así como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC>: <mensaje> 
                - En caso de que no exista retornar
            
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg. Los dos primeros bytes tienen la longitud del mensaje en orden de red. El resto de bytes son el mensaje en sí mismo.
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    longitud_mensaje = struct.unpack('!H', data[0:2])[0]
        
    # 2. Extraemos el mensaje real
    mensaje_texto = data[2:2+longitud_mensaje].decode('ascii', errors='ignore')

     # 3. Formateamos la dirección MAC (conviertiendo cada byte a HEX con dos dígitos)
    mac_formateada = ':'.join(['{:02X}'.format(b) for b in srcMac])

    # 4. Construimos la fecha y hora a partir del timestamp de la cabecera
    # El timestamp viene en header.ts.tv_sec (segundos UNIX) y tv_usec (microsegundos)
    timestamp_float = header.ts.tv_sec + (header.ts.tv_usec / 1000000.0)
    # Convertimos ese float a un objeto datetime
    dt_object = datetime.fromtimestamp(timestamp_float)
    # Formateamos la fecha con la estructura pedida: [aaaa/mm/dd hh:mm:ss.uuuuuu]
    fecha_formateada = dt_object.strftime("%Y/%m/%d %H:%M:%S.%f")
    
    # 5. Imprimimos por pantalla con el formato exacto del enunciado
    print(f"[{fecha_formateada}] {mac_formateada} ({longitud_mensaje} bytes): {mensaje_texto}")    




def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''
    registerEthCallback(process_ethMsg_frame, ETHTYPE)
    logging.info(f'Nivel EthMsg inicializado en la interfaz {interface}')
    return 0

def sendEthMsg(message:str, dstMac:bytes) -> int:

    message_bytes = message.encode('ascii', errors='ignore')
    longitud_bytes = struct.pack('!H', len(message_bytes))
    data = longitud_bytes + message_bytes
    
    # Cambiamos 'broadcast' por 'dstMac'
    retorno = sendEthernetFrame(data, len(message_bytes) + 2, ETHTYPE, dstMac)
    
    if retorno == 0:
        return len(data)
    else:
        return None
        
    # Añadimos dstMac como argumento
    '''
    def sendEthMsg(message:str, dstMac:bytes) -> int:

    (Comentarios)
    message_bytes = message.encode('ascii', errors='ignore')
    longitud_bytes = struct.pack('!H', len(message_bytes))
    data = longitud_bytes + message_bytes
    
    # Cambiamos 'broadcast' por 'dstMac'
    retorno = sendEthernetFrame(data, len(message_bytes) + 2, ETHTYPE, dstMac)
    
    if retorno == 0:
        return len(data)
    else:
        return None
    
    '''