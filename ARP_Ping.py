#!/usr/bin/env python

import sys
import optparse
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

conf.verb=0

usage = "usage: %prog [options] IP_destino"
parser = optparse.OptionParser(usage=usage)
parser.add_option('-d', '--device', dest='dev', help='Interfaz de entrada')
parser.add_option('-c', '--count', dest='cant', help='Cantidad de mensajes ARP a enviar')

(options, args) = parser.parse_args()
if len(args) == 1:
	try:
		if options.cant is None:
			options.cant = 0	
		if options.dev is None:
	    		print 'Error: Falta el argumento -d'	
			parser.print_help()

		get_if_hwaddr(options.dev)

		laIP = args[0]
		socket.inet_aton(laIP) 
		a = laIP.split('.')
		if(len(a) != 4):
			print 'Tu IP NO ES VALIDA! (', laIP , ')'
			exit(1)

		enviados = 0
		recibidos = 0
		if options.cant== 0:
			while 1 :
				ans = srp1( Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=laIP),timeout=1,inter=1,chainCC=1)
				if (ans is not None) :	
					print ans.sprintf(r"Respuesta de %ARP.psrc% [%Ether.src%]")
					recibidos = recibidos+1
				enviados = enviados+1
					
		else:
			for x in range( 0, int(options.cant) ):
				ans = srp1( Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=laIP),timeout=1)
				if (ans is not None) :	
					print ans.sprintf(r"Respuesta de %ARP.psrc% [%Ether.src%]")
					recibidos = recibidos+1
				enviados = enviados+1
			print '\n Enviadas ',str(enviados),' pruebas,',str(recibidos),' Respuestas recibidas'
						
	except socket.error:
		print 'Tu IP NO ES VALIDA! (', laIP , ')'
	except AttributeError:					
		print 'Tu IP no es valida o se encuentra fuera del dominio ARP (', laIP , ')'
	except IOError:
		print 'arping: Intefaz invalida'
	except KeyboardInterrupt:
		print '\n Enviadas ',str(enviados),' pruebas,',str(recibidos),' Respuestas recibidas'
		exit(1)
	except struct.error:
		print 'arping: Argumentos invalidos'	
		
	
else:
	print 'arping: Argumentos invalidos'	
	parser.print_help()



