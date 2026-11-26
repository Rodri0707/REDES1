'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    if len(data) < IP_MIN_HLEN:
        return

    version = data[0] >> 4
    ihl = data[0] & 0x0F
    ip_header_len = ihl * 4

    if version != 4 or ip_header_len < IP_MIN_HLEN or len(data) < ip_header_len:
        return

    # Comprobar checksum de la cabecera IP
    if chksum(data[0:ip_header_len]) != 0:
        logging.debug("Checksum IP erróneo")
        return

    tos = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    ipid = struct.unpack('!H', data[4:6])[0]
    flags_offset = struct.unpack('!H', data[6:8])[0]
    ttl = data[8]
    protocol = data[9]
    src_ip = struct.unpack('!I', data[12:16])[0]
    dst_ip = struct.unpack('!I', data[16:20])[0]

    # Extraer banderas DF y MF (bits 14 y 13) y el Offset (13 bits inferiores) usando máscaras
    df_flag = (flags_offset & 0x4000) >> 14
    mf_flag = (flags_offset & 0x2000) >> 13
    offset_bytes = (flags_offset & 0x1FFF) * 8

    # Convertimos las IPs a texto a.b.c.d
    src_ip_str = socket.inet_ntoa(data[12:16])
    dst_ip_str = socket.inet_ntoa(data[16:20])

    # Loggear todos los campos pedidos
    logging.debug(
        f"IP -> Longitud cabecera: {ip_header_len}, TOS: {tos}, IPID: {ipid}, "
        f"DF: {df_flag}, MF: {mf_flag}, Offset: {offset_bytes}, TTL: {ttl}, "
        f"Protocolo: {protocol}, Origen: {src_ip_str}, Destino: {dst_ip_str}"
    )

    # Si offset != 0 descartamos (no reensamblamos)
    if offset_bytes != 0:
        return

    # Si offset == 0 y el protocolo está registrado, pasamos el payload (sin cabecera IP)
    if protocol in protocols:
        payload = data[ip_header_len:total_length]
        protocols[protocol](us, header, payload, src_ip)



def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    global protocols
    protocols[protocol]= callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    if initARP(interface) == -1:
        return False
    
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)

    if opts is not None:
        if len(opts) > 40:
            logging.error("Opciones IP superan los 40 bytes máximos.")
            return False
        # Añadir padding con ceros si no es múltiplo de 4 bytes
        resto = len(opts) % 4
        if resto != 0:
            opts = opts + bytes([0] * (4 - resto))

    ipOpts = opts

    registerEthCallback(process_IP_datagram, 0x0800)

    IPID = 12

    return True

def sendIPDatagram(dstIP,data,protocol):
    global IPID
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
        
    '''

    if (dstIP & netmask) == (myIP & netmask):
    # Está en nuestra misma subred
        dstMac = ARPResolution(dstIP)
    else:
        # Está fuera de nuestra subred, lo mandamos al router (gateway)
        dstMac = ARPResolution(defaultGW)

    if dstMac is None:
        return False

    #Aqui cojo el IHL (tamaño de la cabecera)
    if ipOpts is not None:
        longitud_cabecera_bytes = 20 + len(ipOpts)
    else:
        longitud_cabecera_bytes = 20

    ihl = longitud_cabecera_bytes // 4

    max_datos = MTU - longitud_cabecera_bytes
    max = max_datos - (max_datos % 8)  # Ajustar a múltiplo de 8

    if len(data) == 0:
        num_fragmentos = 1
    else:
        num_fragmentos = len(data) // max
        if len(data) % max != 0:
            num_fragmentos += 1

    for i in range(num_fragmentos):
        # Recortar el trozo de datos de este fragmento
        inicio = i * max
        fin = min(inicio + max, len(data))
        datos_fragmento = data[inicio:fin]

        # Calcular Total Length, bandera MF y Offset
        total_length = longitud_cabecera_bytes + len(datos_fragmento)
        if(i < num_fragmentos - 1):
            mf = 1
        else:
            mf = 0

        offset = inicio // 8
        flags_y_offset = (mf << 13) | offset
        #No inicializo df ni reserved, porque están a 0

        # Empaquetar los 20 bytes fijos de cabecera (con checksum = 0 inicialmente)
        # Versión 4 en los 4 bits altos, IHL en los 4 bits bajos
        ver_ihl = (4 << 4) | ihl
        ip_header = struct.pack('!BBHHHBBHII',
                                ver_ihl,       # Version + IHL (1 byte)
                                1,             # TOS = 1 según enunciado (1 byte)
                                total_length,  # Total Length (2 bytes)
                                IPID,          # Identification (2 bytes)
                                flags_y_offset,# Flags + Fragment Offset (2 bytes)
                                40,            # TTL = 40 según enunciado (1 byte)
                                protocol,      # Protocolo superior: 17 UDP, 1 ICMP (1 byte)
                                0,             # Checksum provisional a 0 (2 bytes)
                                myIP,          # IP origen (4 bytes)
                                dstIP)         # IP destino (4 bytes)

        # Añadir opciones si existen
        if ipOpts is not None:
            ip_header += ipOpts

        # Calcular el checksum real y meterlo en los bytes 10 y 11
        # ¡OJO! chksum() ya devuelve el valor en orden de red, por eso struct.pack va sin !
        chk = chksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', chk) + ip_header[12:]

        # 6. Unir cabecera + datos y enviar por Ethernet (Ethertype 0x0800)
        datagrama_final = ip_header + datos_fragmento
        if sendEthernetFrame(datagrama_final, len(datagrama_final), 0x0800, dstMac) != 0:
            return False
    IPID = IPID + 1
    return True



