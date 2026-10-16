'''
	practica2.py
	Programa principal que ejecuta resoluciones ARP. En este archivo No implementaremos nada.
	Autor: Javier Ramos <javier.ramos@uam.es> / Manuel Ruiz <manuel.ruiz.fernandez@uam.es >
	2020 EPS-UAM
'''

from ethernet import *
from arp import *
from ethmsg import *
import sys
import binascii
import signal
import argparse
import struct
from argparse import RawTextHelpFormatter
import time
import logging
import socket

def printHelp():
	print ( "Ayuda Consola:\n")
	print ( "\tm <mensaje> : Envia un mensaje utilizando protocolo Ethernet\n")
	print ( "\ta <direccionIP> : Solicita ARP Request sobre la IP indicada\n")
	print ( "\tp : Imprime cache ARP\n")
	print ( "\th : Muestra la ayuda\n")
	print ( "\tg : Envia un ARP gratuito para comprobar si la IP propia ya está asignada\n")
	print ( "\tq : Salir del programa\n")


if __name__ == "__main__":
	global pdumper,args,handle,el,stop
	parser = argparse.ArgumentParser(description='Esta práctica ejecuta resoluciones ARP. Dada una dirección IP devuelve cual es la MAC asociada en la LAN actual',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.interface is False:
		logging.error('No se ha especificado interfaz')
		parser.print_help()
		sys.exit(-1)

	
	
	#Inicializamos el nivel Ethernet en la interfaz especificada
	if (startEthernetLevel(args.interface) != 0):
		logging.error('Ethernet no inicializado')
		sys.exit(-1)
	
	#iniciar nivel EthMsg
	initEthMsg(args.interface)

	#Inicializamos ARP. Si no podemos inicializar salimos.
	if initARP(args.interface) == -1:
		logging.error('ARP no inicializado')
		stopEthernetLevel()
		sys.exit(-1)
		
	''' Bucle infinito que leerá las opciones por teclado y ejecutará las acciones correspondientes
		(resolver una dirección, imprimrir la caché o salir)
	'''

	print("Introduce la orden correspondiente:\n")
	
	while True:
		try:
			comando = input(">> ")
			if comando == "q":
					# Leer comando del usuario
				print("Saliendo de la consola.")
				break  # Salir del bucle y terminar la consola
			elif comando == 'p':
				printCache()
			elif comando == 'h':
				printHelp()
			elif comando.startswith("a "):
				ipstr = comando.split(" ")[1]
				print(f"Enviando solicitud ARP a {ipstr}...")
			# Aquí Se implementa la solicitud ARP
				try:
			#Convertimos la dirección IP en formato textual (X.X.X.X) a un entero de 32 bits.
					ip=struct.unpack('!I',socket.inet_aton(ipstr))[0]
			#Llamamos a la función de realizar resolución ARP con la IP que hemos leído
					ret = ARPResolution(ip)
			#Si hay respuesta imprimir la dirección MAC
					if ret is not None:
						print(':'.join(['{:02X}'.format(b) for b in ret]))
					else:
						print('Dirección no encontrada\n')
				except OSError:
				#Si ha fallado la conversión de IP, el formato es incorrecto.
					print('Formato de IP incorrecta\n')
			
			elif comando.startswith("m "):
				partes = comando.split(" ")
				if len(partes) < 3:
					print("Formato incorrecto. Uso: m <IP> <mensaje>\n")
					continue
					
				ipstr = partes[1]
				mensaje = " ".join(partes[2:])
				

				# 1. Convertimos la IP escrita a entero
				ip = struct.unpack('!I',socket.inet_aton(ipstr))[0]
					
				print(f"Buscando a {ipstr} en la red...")
					
				# 2. Llamamos a TU función ARP para descubrir su MAC física
				mac_destino = ARPResolution(ip)
					
				# 3. Si la encontramos, enviamos el mensaje directo (Unicast)
				if mac_destino is not None:
					mac_str = ':'.join(['{:02X}'.format(b) for b in mac_destino])
					print(f"MAC encontrada ({mac_str}). Enviando mensaje de {len(mensaje)} Bytes: {mensaje}")
						
					# Llamamos al envío pasándole el mensaje Y la MAC destino
					sendEthMsg(mensaje, mac_destino)
				else:
					print(f"Error: El equipo con IP {ipstr} no existe o no contesta.\n")

			elif comando == 'g':
				print("Ejecutando ARP Gratuito...")
				# Usamos la función getIP (importada de arp.py) para saber nuestra IP
				mi_ip = getIP(args.interface)
				# Llamamos a la resolución ARP preguntando por nosotros mismos
				ARPResolution(mi_ip)
			
			else:
				print("Comando no reconocido. 'h' para ayuda.\n")
		except KeyboardInterrupt:
			print('\n')
			break
	logging.info('Cerrando ....')
	#Paramos nivel ARP
	#Paramos nivel EthMsg
	#Paramos el nivel Ethernet
	if(stopEthernetLevel()!=0):
		logging.error('Parando nivel Ethernet')
		sys.exit(-1)


	'''
	elif comando.startswith("m "):
				partes = comando.split(" ")
				if len(partes) < 3:
					print("Formato incorrecto. Uso: m <IP> <mensaje>\n")
					continue
					
				ipstr = partes[1]
				mensaje = " ".join(partes[2:])
				

				# 1. Convertimos la IP escrita a entero
				ip = struct.unpack('!I',socket.inet_aton(ipstr))[0]
					
				print(f"Buscando a {ipstr} en la red...")
					
				# 2. Llamamos a TU función ARP para descubrir su MAC física
				mac_destino = ARPResolution(ip)
					
				# 3. Si la encontramos, enviamos el mensaje directo (Unicast)
				if mac_destino is not None:
					mac_str = ':'.join(['{:02X}'.format(b) for b in mac_destino])
					print(f"MAC encontrada ({mac_str}). Enviando mensaje de {len(mensaje)} Bytes: {mensaje}")
						
					# Llamamos al envío pasándole el mensaje Y la MAC destino
					sendEthMsg(mensaje, mac_destino)
				else:
					print(f"Error: El equipo con IP {ipstr} no existe o no contesta.\n")

	'''