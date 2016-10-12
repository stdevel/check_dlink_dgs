#!/usr/bin/python

# check_dlink_dgs.py - a script for checking
# D-Link DGS managed switches
#
# 2016 By Christian Stankowic
# <info at stankowic hyphen development dot net>
# https://github.com/stdevel
#

import logging
import pysnmp
import re
from optparse import OptionParser, OptionGroup
from pysnmp.entity import engine, config
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen



LOGGER = logging.getLogger('check_dlink_dgs')
my_ports={}
my_oids={"alias": "1.3.6.1.2.1.31.1.1.1.18.",	#interface alias (e.g. lipstick robot)
	"desc": "1.3.6.1.2.1.2.2.1.2.",		#interface description (e.g. D-Link Corporation DGS-1510-28X 1.30.B017 Port 24 on Unit 1)
	"device": "1.3.6.1.2.1.31.1.1.1.1.",	#device (e.g. eth/0/0/1)
	"state": "1.3.6.1.2.1.2.2.1.8.",	#status (1=up,2=down)
	"speed": "1.3.6.1.2.1.31.1.1.1.15.",	#speed (10/100/1000/10000)
	"inOct" : "1.3.6.1.2.1.31.1.1.1.6.",	#counter incoming octets
	"outOct": "1.3.6.1.2.1.31.1.1.1.10.",	#counter outgoing octets
	}
my_portinfo={}					#dict with gathered information
perfdata=" |"
#I like dirty coding
curr_query=""
curr_port=1



def explode_ports(port_str):
	#split port ranges and values
	LOGGER.debug("About to explode string '{0}'".format(port_str))
	ports = []
	for part in port_str.split(','):
		if '-' in part:
			a, b = part.split('-')
			a, b = int(a), int(b)
			ports.extend(range(a, b + 1))
		else:
			a = int(part)
			ports.append(a)
	return ports



def snmpHandler(sendRequestHandle,
          errorIndication, errorStatus, errorIndex,
          varBinds, cbCtx):
	global curr_query
	global curr_port
	#Error/response receiver
	if errorIndication:
		#print(errorIndication)
		LOGGER.debug(errorIndication)
	elif errorStatus:
		#print('%s at %s' % (
		LOGGER.debug('%s at %s' % (
			errorStatus.prettyPrint(),
			errorIndex and varBinds[int(errorIndex)-1][0] or '?'
			)
		)
	else:
		for oid, val in varBinds:
			#set request results
			my_portinfo[curr_port][curr_query] = val.prettyPrint()

def get_oid_result(cmd):
	#get result of OID query
	
	#create SNMP engine
	snmpEngine = engine.SnmpEngine()
	
	#SNMPv2c setup
	config.addV1System(snmpEngine, 'my-area', options.snmp_comm)
	# Specify security settings per SecurityName (SNMPv1 - 0, SNMPv2c - 1)
	config.addTargetParams(snmpEngine, 'my-creds', 'my-area', 'noAuthNoPriv', 1)
	
	# Setup transport endpoint and bind it with security settings yielding
	# a target name 
	config.addTransport(
	    snmpEngine,
	    udp.domainName,
	    udp.UdpSocketTransport().openClientMode()
	)
	config.addTargetAddr(
	    snmpEngine, 'my-switch',
	    udp.domainName, (options.host, options.snmp_port),
	    'my-creds',
	    timeout=300,  # in 1/100 sec
	    retryCount=5
	)
	
	cmdgen.GetCommandGenerator().sendReq(
		snmpEngine,
		'my-switch',
		( (cmd, None), ),
		snmpHandler
	)
	
	# Run I/O dispatcher which would send pending queries and process responses
	snmpEngine.transportDispatcher.runDispatcher()



def get_all_ports():
	#get amount of total ports
	
	global my_ports
	my_ports = [1]
	check_switch_ports(True)
	#lel, we're using the product name for getting this info
	prod_name = my_portinfo[1].get("desc")
	prod_name = prod_name[prod_name.find("DGS-"):]
	prod_name = prod_name[:prod_name.find(" ")]
	prod_ports = re.findall(r'\d+', prod_name[prod_name.rfind("-"):])
	LOGGER.debug("Seems like we have {0} ports on this switch ({1})".format(prod_ports[0], prod_name))
	my_ports = explode_ports("1-" + str(prod_ports[0]))



def get_active_ports():
	#get active ports
	
	global my_ports
	global my_portinfo
	#get all ports
	get_all_ports()
	check_switch_ports(True)
	#filter active
	my_ports = [port for port in my_portinfo if my_portinfo[port].get("state") == "1"]
	LOGGER.debug("New ports: {0}".format(my_ports))
	#re-create port infos
	my_portinfo={}
	check_switch_ports(True)



def check_switch_ports(skipChecks=False):
	#get port information
	
	global curr_query
	global curr_port
	global my_ports
	global my_portinfo
	global perfdata
	
	for port in my_ports:
		LOGGER.debug("Retrieving information about port '{0}'...".format(port))
		my_portinfo[int(port)] = {}
		#yep, I know that's not nice
		curr_port = int(port)
		for query in my_oids:
			OID = my_oids[query]+str(port)
			#again, not a nice thing
			curr_query = query
			LOGGER.debug("Requesting '{0}' ({1})...".format(OID, query))
			#my_portinfo[int(port)][query] = "lel"
			get_oid_result(OID)
	LOGGER.debug("my_ports: '{0}'".format(str(my_ports)))
	LOGGER.debug("my_portinfo: '{0}'".format(str(my_portinfo)))
	
	#perform checks
	if skipChecks == False:
		#get performance data
		if options.show_perfdata:
			for port in my_portinfo:
				#append performance data
				perfdata = "{0} 'inOct {1}'={2} 'outOct {3}'={4}".format(perfdata, my_portinfo[port].get("alias"), my_portinfo[port].get("inOct"), my_portinfo[port].get("alias"), my_portinfo[port].get("outOct"))
		
		#check for shut ports
		black_port_down = [port for port in my_portinfo if my_portinfo[port].get("state") == "2"]
		if len(black_port_down) > 0:
			print "CRITICAL: Disconnected port(s) {0}{1}".format(",".join(str(x) for x in black_port_down), perfdata)
			exit(2)
		else:
			print "OK: All specified ports connected{0}".format(perfdata)
			exit(0)



if __name__ == "__main__":
	#define description, version and load parser
	desc='''%prog is used to check D-Link DGS managed switch port states. It also returns package counter metrics.
	
	Checkout the GitHub page for updates: https://github.com/stdevel/check_dlink_dgs'''
	parser = OptionParser(description=desc,version="%prog version 0.5.0")
	
	gen_opts = OptionGroup(parser, "Generic options")
	host_opts = OptionGroup(parser, "Host options")
	port_opts = OptionGroup(parser, "Port options")
	parser.add_option_group(gen_opts)
	parser.add_option_group(host_opts)
	parser.add_option_group(port_opts)
	
	#-d / --debug
	gen_opts.add_option("-d", "--debug", dest="debug", default=False, action="store_true", help="enable debugging outputs (default: no)")
	
	#-e / --enable-perfdata
	gen_opts.add_option("-e", "--enable-perfdata", dest="show_perfdata", default=False, action="store_true", help="enables performance data (default: no)")
	
	#-H / --host
	host_opts.add_option("-H", "--host", dest="host", default="", action="store", metavar="HOST", help="defines the switch hostname or IP")
	
	#-c / --snmp-community
	host_opts.add_option("-c", "--snmp-community", dest="snmp_comm", default="public", action="store", metavar="COMMUNITY", help="defines the SNMP community (default: public)")
	
	#-V / --snmp-version
	host_opts.add_option("-V", "--snmp-version", dest="snmp_vers", default="2c", action="store", choices=["1","2c"], metavar="[1|2c]", help="defines the SNMP version (default: 2c)")
	
	#-p / --snmp-port
	host_opts.add_option("-p", "--snmp-port", dest="snmp_port", default=161, action="store", type=int, metavar="PORT", help="defines the SNMP port (default: 161)")
	
	#-P / --ports
	port_opts.add_option("-P", "--ports", dest="ports", action="append", metavar="PORT", help="defines one or more ports for monitoring")
	
	#-a / --all-ports
	port_opts.add_option("-a", "--all-ports", dest="all_ports", default=False, action="store_true", help="monitors all ports (default: no)")
	
	#-A / --active-ports
	port_opts.add_option("-A", "--active-ports", dest="act_ports", default=False, action="store_true", help="monitors all active ports (default: no)")
	
	
	#parse arguments
	(options, args) = parser.parse_args()
	
	#set loggin
	if options.debug:
		logging.basicConfig(level=logging.DEBUG)
		LOGGER.setLevel(logging.DEBUG)
	else:
		logging.basicConfig()
		LOGGER.setLevel(logging.INFO)
	
	#die in a fire if important information missing
	if not options.ports and options.all_ports is False and options.act_ports is False:
		LOGGER.error("Please specify ports to monitor! (see -h/--help)")
		exit(2)
	
	#expand ports
	if options.ports: my_ports = explode_ports(",".join(options.ports))
	
	#debug outputs
	LOGGER.debug("OPTIONS: {0}".format(options))
	LOGGER.debug("PORTS: {0}".format(my_ports))
	
	#get number of ports
	if options.all_ports: get_all_ports()
	elif options.act_ports: get_active_ports()
	
	#check switch
	check_switch_ports()
