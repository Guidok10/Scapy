#!/usr/bin/env python

import sys
import optparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import socket
import re


def imprimir(FQDN):
	answer = sr1(IP(dst=servidor)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=FQDN,qtype="NS")),verbose=0,timeout=2,retry=-5)
	if answer==None:
		exit("dnsTracer: Error. El servidor no responde. Intente de nuevo")
	for x in range(answer[DNS].ancount):
		dns=answer[DNS].an[x]
		consulta = sr1(IP(dst=servidor)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=answer[DNS].an[x].rdata,qtype="A")),verbose=0,timeout=2,retry=-5)
		if consulta==None:
			exit("dnsTracer: Error. El servidor no responde. Intente de nuevo")
		print '"' + dns.rrname + '"', '\t', dns.sprintf("%rclass%"), '\t', dns.sprintf("%type%"), '\t', dns.rdata, '\t\t', consulta[DNS].an[0].rdata


def obtenerDNSS():
	try:
		with open("/etc/resolv.conf","r") as readFile:
			servidores=[line.split(" ")[1].strip() for line in readFile.readlines() if line.startswith("nameserver")]
		if len(servidores)>0 :
			serv=servidores[0]
		else:
			serv="8.8.8.8"
		socket.inet_aton(serv) 
		a = serv.split('.')
		if(len(a) != 4):
			print 'La IP designada como servidor DNS, NO ES VALIDA (', serv , ')'
			exit(1)
		return serv
	except IOError:
		print "Error al leer el archivo resolv.conf"
	except socket.error:
		print 'Tu IP NO ES VALIDA! (', serv , ')'


usage = "usage: %prog FQDN_entrada"
parser = optparse.OptionParser(usage=usage)

(options, args) = parser.parse_args()
if len(args) == 1:
	try:
		FQDN = args[0]
		host=socket.gethostbyname(FQDN)
	except socket.gaierror:
		exit("dnsTracer: FQDN Invalido")
		
	#Luego controla que el FQDN sea una direccion valida y no un numero IP
	numeros=True;
	for elem in FQDN.split('.'):
		if (not elem.isdigit()):
			numeros=False
	if (numeros):
		exit('dnsTracer: FQDN Invalido')
	if FQDN.endswith(".."):
		exit('dnsTracer: FQDN Invalido')
	print "-".ljust(80,"-")
	
	#Intento usar el servidor dns configurado en resolv.conf
	servidor = obtenerDNSS()
	
	
	print "FQDN: ",FQDN, "| Servidor DNS:",servidor
	print "Trace ".ljust(80,"-")
	#A partir de aqui consultamos si el dns termina o no en punto para saber cuantas veces consultar por el punto
	if FQDN.endswith("."):
		FQDN=FQDN[:len(FQDN)-1]
	imprimir("")
	cantPuntos=FQDN.count('.')
	posPunto=len(FQDN) #Como no hay puntos arrancamos desde el ultimo caracter

	for i in range(cantPuntos):
		posPunto=FQDN.rfind('.',0,posPunto)
		dominioaCon=FQDN[posPunto+1:]
		print "-".ljust(80,"-")
		imprimir(dominioaCon)
	print "-".ljust(80,"-")
	answer=sr1(IP(dst=servidor)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=FQDN)),verbose=0,timeout=2,retry=-5)
	if answer==None:
		exit("dnsTracer: Error. El servidor no responde. Intente nuevamente.")
	for i in range(answer[DNS].ancount):
		dns=answer[DNS].an[i]
		print '"' + FQDN + '"', '\t\t', dns.sprintf("%rclass%"), '\t', dns.sprintf("%type%"), '\t', dns.rdata

	
else:
	print 'dnsTracer: Argumentos invalidos'	
	parser.print_help()
