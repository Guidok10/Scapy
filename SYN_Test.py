#!/usr/bin/env python

import sys
import optparse
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal

def exitCh(signum,frame):
	signal.signal(signal.SIGINT,oriSig)
	print '\n Enviadas ',str(enviados),' pruebas,',str(recibidos),' Respuestas recibidas'
	sys.exit(1)

conf.verb=0

usage = "usage: %prog [options] IP_destino"
parser = optparse.OptionParser(usage=usage)

parser.add_option('-p', '--port', dest='port', help='Puerto destino')
parser.add_option('-c', '--count', dest='cant', help='Cantidad de mensajes TCP SYN a enviar')
(options, args) = parser.parse_args()

if len(args) == 1:
	try:
		if options.cant is None:
			options.cant = 0	
		if options.port is None:
	    		options.port = 80

		laIP = args[0]
		socket.inet_aton(laIP) 
		a = laIP.split('.')
		if(len(a) != 4):
			print 'Tu IP NO ES VALIDA! (', laIP , ')'
			exit(1)

		enviados = 0
		recibidos = 0
		
		sport = random.randint(1024,65535)
		dport = int (options.port)
		print 'puerto origen: ',sport
		print 'puerto destino: ',dport
				
		ip=IP(dst=laIP)
		while 1 and options.cant== 0:
			SYN=TCP(sport=sport,dport=dport,flags='S')
			SYNACK=sr1(ip/SYN,timeout=1)
			if (SYNACK is not None) :	
				if(SYNACK.haslayer(TCP)):
					if(SYNACK.getlayer(TCP).flags == 0x12): #Recibi un SYN+ACK
						print 'Respuesta de ',laIP,',puerto ',dport,',Flags:SA'
						# Envio el mensaje de ACK
						ACK = TCP(sport=sport,dport=dport,flags="A")
						send_rst = sr(IP(dst=laIP)/ACK,timeout=1)
					elif (SYNACK.getlayer(TCP).flags == 0x14): #Recibi un RST+ACK
						print "Respuesta de ",laIP,",puerto ",dport,",Flags:RA"
				recibidos = recibidos+1
			else:
				print '<Mensaje no recibido>'			
			enviados = enviados+1
				
			if __name__=="__main__": #Para capturar CTRL+C
				oriSig = signal.getsignal(signal.SIGINT)
				signal.signal(signal.SIGINT,exitCh)
					
		else:	
			for x in range( 0, int(options.cant) ):
				SYN=TCP(sport=sport,dport=dport,flags='S')
				SYNACK=sr1(ip/SYN,timeout=1)
				if (SYNACK is not None):	
					if(SYNACK.haslayer(TCP)):
						if(SYNACK.getlayer(TCP).flags == 0x12): #Recibi un SYN+ACK
							print 'Respuesta de ',laIP,',puerto ',dport,',Flags:SA'
							# Envio el mensaje de ACK
							ACK = TCP(sport=sport,dport=dport,flags="A")
							send_rst = sr(IP(dst=laIP)/ACK,timeout=1)
						elif (SYNACK.getlayer(TCP).flags == 0x14): #Recibi un RST+ACK
							print "Respuesta de ",laIP,",puerto ",dport,",Flags:RA"
					recibidos = recibidos+1
				enviados = enviados+1
			print '\n Enviadas ',str(enviados),' pruebas,',str(recibidos),' Respuestas recibidas'
						
	except socket.error:
		print 'Tu IP NO ES VALIDA! (', laIP , ')'
	except AttributeError:					
		print 'Tu IP no es valida o se encuentra fuera del dominio ARP (', laIP , ')'
	except IOError:
		print 'SYN Test: Intefaz invalida'
	except struct.error:
		print 'SYN Test: Argumentos invalidos'
	except ValueError:
		print 'SYN Test:Los parametros -c y -p deben ser enteros!'
		parser.print_help()	
		
	
else:
	print 'SYN Test: Argumentos invalidos'	
	parser.print_help()
