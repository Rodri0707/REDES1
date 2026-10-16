'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''



from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

#Semáforo global 
globalLock =Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6

#Variable que alamacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que alamacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)



def getIP(interface:str) -> int:
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]

def printCache()->None:
    '''
        Nombre: printCache
        Descripción: Esta función imprime la caché ARP
        Argumentos: Ninguno
        Retorno: Ninguno
    '''
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))



def processARPRequest(data:bytes,MAC:bytes)->None:
    '''
        Nombre: processARPRequest
        Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                    -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    ''' 
    global myIP
    
    # 1. Extraer la MAC origen contenida en la petición ARP
    # La MAC origen (Sender MAC) está en los bytes del 8 al 13 de la cabecera específica (después del opcode)
    macOrigen_ARP = data[2:8]
    
    # 2. Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
    if macOrigen_ARP != MAC:
        return
        
    # 3. Extraer la IP origen contenida en la petición ARP
    # La IP origen (Sender IP) está en los bytes del 14 al 17
    ipOrigen_ARP = struct.unpack('!I', data[8:12])[0]
    
    # 4. Extraer la IP destino contenida en la petición ARP
    # La IP destino (Target IP) está en los bytes del 24 al 27
    ipDestino_ARP = struct.unpack('!I', data[18:22])[0]
    
    # 5. Comprobar si la IP destino de la petición ARP es la propia IP
    if ipDestino_ARP != myIP:
        return
        
    # 6. Si es la propia IP: Construir una respuesta ARP llamando a createARPReply
    respuesta_bytes = createARPReply(ipOrigen_ARP, macOrigen_ARP)
    
    # 7. Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
    # Como es un Reply y sabemos a quién va dirigido, la mandamos en Unicast (a la macOrigen_ARP), no a broadcast
    sendEthernetFrame(respuesta_bytes, len(respuesta_bytes), 0x0806, macOrigen_ARP)
    
def processARPReply(data:bytes,MAC:bytes)->None:
    '''
        Nombre: processARPReply
        Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la MAC destino contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                    -Copiar la MAC origen a la variable global resolvedMAC
                    -Añadir a la caché ARP la asociación MAC/IP.
                    -Cambiar el valor de la variable awaitingResponse a False
                    -Cambiar el valor de la variable requestedIP a None
        Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global requestedIP,resolvedMAC,awaitingResponse,cache

    if len(data) < 22:
        return
    
    macOrigen_ARP = data[2:8]
    if macOrigen_ARP != MAC:
        return
    ipOrigen_ARP = struct.unpack('!I', data[8:12])[0]
    macDestino_ARP = data[12:18]
    ipDestino_ARP = struct.unpack('!I', data[18:22])[0]

    if ipDestino_ARP != myIP:
        return

    with globalLock:
        if(ipOrigen_ARP != requestedIP):
            return
        resolvedMAC = macOrigen_ARP
        awaitingResponse = False
        requestedIP = None

    with cacheLock:
            cache[ipOrigen_ARP] = macOrigen_ARP
    


def createARPRequest(ip:int) -> bytes:
    '''
        Nombre: createARPRequest
        Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
        Argumentos: 
            -ip: dirección a resolver 
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP
    frame = bytes()
    frame = ARPHeader + struct.pack('!H', 0x0001) + myMAC + struct.pack('!I', myIP) + bytes([0x00]*6) + struct.pack('!I', ip)
    return frame

    
def createARPReply(IP:int ,MAC:bytes) -> bytes:
    '''
        Nombre: createARPReply
        Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
        Argumentos: 
            -IP: dirección IP a la que contestar
            -MAC: dirección MAC a la que contestar
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP
    frame = bytes()
    #El frame con la respuesta ARP se construye concatenando la cabecera común ARP, el opcode de respuesta (0x0002), la MAC e IP propias y la MAC e IP destino
    frame = ARPHeader + struct.pack('!H', 0x0002) + myMAC + struct.pack('!I', myIP) + MAC + struct.pack('!I', IP)

    return frame


def process_arp_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_arp_frame
        Descripción: Esta función procesa las tramas ARP. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP). 
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
                -Extraer el campo opcode
                -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
                -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
                -Si es otro opcode retornar de la función
                -En caso de que no exista retornar
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ARP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    if len(data) < 28 or data[0:ARP_HLEN] != ARPHeader:
        return
    
    opcode = struct.unpack('!H', data[6:8])[0]
    if opcode == 0x0001:
        processARPRequest(data[ARP_HLEN:], srcMac)
    elif opcode == 0x0002:
        processARPReply(data[ARP_HLEN:], srcMac)
    else:
        return
        




def initARP(interface:str) -> int:
    '''
        Nombre: initARP
        Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
            -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
            -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
            -Marcar la variable de nivel ARP inicializado a True
    '''
    global myIP, myMAC, arpInitialized, requestedIP
    
    # 1. Registrar la función del callback process_arp_frame con el Ethertype 0x0806
    registerEthCallback(process_arp_frame, 0x0806)
    
    # 2. Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
    myMAC = getHwAddr(interface)
    myIP = getIP(interface)
    
    # 3. Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada
    # Llamamos a ARPResolution preguntando por NUESTRA PROPIA IP
    # Como es un ARP gratuito, se espera que devuelva None (nadie la tiene)
    mac_resuelta = ARPResolution(myIP)

    if mac_resuelta is not None:
        logging.error("ARP Gratuito fallido: La IP ya está asignada a otra máquina en la red")
        return -1

    logging.info(f"Nivel ARP inicializado correctamente en {interface} con IP {myIP}")
        
    # 4. Marcar la variable de nivel ARP inicializado a True
    arpInitialized = True
    logging.info(f"Nivel ARP inicializado correctamente en {interface} con IP {myIP}")
    
    return 0

def ARPResolution(ip:int) -> bytes:
    '''
        Nombre: ARPResolution
        Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP 
            o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
                -Comprobar si la IP solicitada existe en la caché:
                -Si está en caché devolver la información de la caché
                -Si no está en la caché:
                    -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                    -Enviar dicha petición
                    -Comprobar si se ha recibido respuesta o no:
                        -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                        -Si se ha recibido respuesta devolver la dirección MAC
            Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
                -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
                -requestedIP: contiene la IP por la que se está preguntando
                -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
            Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    '''
    global requestedIP, awaitingResponse, resolvedMAC
    
    # 1. Comprobar si la IP solicitada existe en la caché
    # Usamos el cerrojo para proteger el acceso a la caché compartida
    with cacheLock:
        mac_en_cache = cache.get(ip)
        
    # Si está en caché devolver la información de la caché
    if mac_en_cache is not None:
        return mac_en_cache
        
    # 2. Si no está en la caché, preparamos la petición
    # Usamos globalLock para proteger las variables compartidas con la recepción
    with globalLock:
        requestedIP = ip
        awaitingResponse = True
        resolvedMAC = None
        
    # Construir una petición ARP llamando a la función createARPRequest
    trama_arp_request = createARPRequest(ip)
    
    # Bucle para enviar la petición hasta un máximo de 3 veces si no hay respuesta
    intentos = 0
    while intentos < 3:
        # Enviar dicha petición.
        # Recuerda que ARP se manda en difusión y usa el Ethertype 0x0806
        sendEthernetFrame(trama_arp_request, len(trama_arp_request), 0x0806, broadcastAddr)
        
        # Esperamos un tiempo prudencial (ej. 1 segundo) para dar tiempo a que llegue la respuesta
        # y que el hilo de recepción actualice awaitingResponse a False
        time.sleep(1)
        
        # Comprobar de forma segura si ya se ha recibido respuesta
        with globalLock:
            if not awaitingResponse:
                # Si hemos recibido respuesta, salimos del bucle de reintentos
                break
                
        intentos += 1
        
    # 3. Comprobar el resultado final
    with globalLock:
        if not awaitingResponse and resolvedMAC is not None:
            # Si se ha recibido respuesta, devolver la dirección MAC
            mac_final = resolvedMAC
            # Limpiamos las variables (opcional, pero buena práctica)
            requestedIP = None
            resolvedMAC = None
            return mac_final
        else:
            # Si tras 3 intentos no se ha recibido respuesta devolver None
            requestedIP = None
            awaitingResponse = False
            resolvedMAC = None
            return None

    return None

