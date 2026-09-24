'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60
MAX_BYTES = 65535
 
def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper_ip, pdumper_noip, tiempo_primer_paquete, tiempo_ultimo_paquete

	# Guardar el tiempo del primer paquete y actualizar el del último en cada pasada
	tiempo_actual = header.ts.tv_sec + (header.ts.tv_usec / 1000000.0)
	if num_paquete == 0:
		tiempo_primer_paquete = tiempo_actual
	tiempo_ultimo_paquete = tiempo_actual

	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1

	# Imprimir los N primeros bytes en hexadecimaL
	for i in range(min(args.nbytes, header.caplen)):
		# {:02X} convierte a Hexadecimal, fuerza 2 dígitos y usa Mayúsculas.
        # end="" evita el salto de línea automático de print()
		print("{:02X} ".format(data[i]), end="")
		# Evaluar salto de línea cada 16 bytes (evaluamos i + 1 para evitar el 0)
		if (i + 1) % 16 == 0:
			print()
	print() # Salto de línea de cierre para separar este paquete del siguiente
			
		
	if args.interface:
		if len(data) >= 14:
			# Extraemos y comparamos los bytes 12 y 13
			if len(data) >= 14 and data[12] == 0x08 and data[13] == 0x06:
				# Coincide con 0x0806 (ARP). Lo enviamos a la traza NOIP
				if pdumper_noip is not None:
					pcap_dump(pdumper_noip, header, data)
			else:
				# Resto del tráfico (IP, etc.). Lo enviamos a la traza normal
				if pdumper_ip is not None:
					pcap_dump(pdumper_ip, header, data)
	
					
	
if __name__ == "__main__":
	global args,handle, dumper_mac
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=MAX_BYTES,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	# Añadir parametro del numero de paquetes
	parser.add_argument('--npkts', dest='npackets', type=int, default=-1,help='Número de paquetes a capturar')
	# Impresion de ayuda si no se especifica argumentos
	if len(sys.argv) == 1 :
		logging.error('No se ha especificado ningun argumento')
		parser.print_help()
		sys.exit(-1)
	#Le pasamos a args los argumentos de parser
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	pdumper_ip = None 
	pdumper_noip = None
	dumper_mac = None
	
	if args.interface: 
		# Si el usuario ha introducido --itf, abrimos la interfaz en vivo
		logging.info(f"Abriendo la interfaz {args.interface}...")
		handle = pcap_open_live(args.interface,ETH_FRAME_MAX,NO_PROMISC,TO_MS, errbuf)
		if handle is None:
			logging.error(f"Error al abrir la interfaz: {errbuf.decode('ascii', errors='ignore')}")
			sys.exit(-1)

		# 1. Obtener el tiempo UNIX actual (en segundos enteros)
		fecha = int(time.time())
        
        # 2. Abrir un descriptor "falso" para configurar el volcado (Ethernet, 1514 bytes)
		dumper_mac = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX)
        
        # 3. Formatear los nombres de los archivos según las reglas del enunciado
		nombre_noip = f"capturaNOIP.{args.interface}.{fecha}.pcap"
		nombre_ip = f"captura.{args.interface}.{fecha}.pcap"

		# 4. Crear físicamente los archivos y asignar los descriptores
		pdumper_noip = pcap_dump_open(dumper_mac, nombre_noip)
		pdumper_ip = pcap_dump_open(dumper_mac, nombre_ip)

	elif args.tracefile:
		# Si el usuario ha introducido --fie, abrimos el archivo
		logging.info(f"Abriendo el archivo de traza {args.tracefile}...")
		handle = pcap_open_offline(args.tracefile, errbuf)
		if handle is None:
			logging.error(f"Error al abrir la traza: {errbuf.decode('ascii', errors='ignore')}")
			sys.exit(-1)

	
	ret = pcap_loop(handle,args.npackets,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))
	
	if num_paquete >= 2 :
		logging.info('Tiempo entre primer y último paquete: {} segundos'.format(tiempo_ultimo_paquete - tiempo_primer_paquete))
	else :
		logging.info('Tiempo entre primer y último paquete: 0 segundos')

	if pdumper_noip is not None:
		pcap_dump_close(pdumper_noip)
	if pdumper_ip is not None:
		pcap_dump_close(pdumper_ip)
	if dumper_mac is not None: 
		pcap_close(dumper_mac)
	if handle is not None:
		pcap_close(handle)



	