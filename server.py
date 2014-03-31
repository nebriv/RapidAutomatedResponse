import socket               # Import socket module
import pickle


import collections
import csv
import datetime
import getpass
import os
import re
import sys
import time
import logging

# pylint: disable=unused-import,g-bad-import-order
from grr.lib import server_plugins
# pylint: enable=g-bad-import-order



from grr.lib import config_lib
from grr.lib import flags
from grr.lib import log
from grr.lib import registry
from grr.lib import stats


from grr import artifacts
from grr.lib import access_control
from grr.lib import aff4
from grr.lib import artifact
from grr.lib import artifact_lib
from grr.lib import config_lib
from grr.lib import data_store
from grr.lib import export_utils
from grr.lib import flags
from grr.lib import flow
from grr.lib import flow_runner
from grr.lib import flow_utils
from grr.lib import hunts
from grr.lib import ipshell
from grr.lib import maintenance_utils
from grr.lib import rdfvalue
from grr.lib import search
from grr.lib import startup

from grr.lib.aff4_objects import aff4_grr
from grr.lib.aff4_objects import reports

from grr.lib.flows import console
from grr.lib.flows.console import client_tests
from grr.lib.flows.console import debugging
from grr.lib.flows.general import memory

print "12"

def TheClients(query_str, token=None, limit=1000):
	"""Search indexes for clients. Returns list (client, hostname, os version)."""
	client_schema = aff4.AFF4Object.classes["VFSGRRClient"].SchemaCls
	results = []
	result_urns = search.SearchClients(query_str, max_results=limit, token=token)
	result_set = aff4.FACTORY.MultiOpen(result_urns, token=token)
	for result in result_set:
		results.append((result,
		                str(result.Get(client_schema.HOSTNAME)),
		                str(result.Get(client_schema.OS_VERSION)),
		                str(result.Get(client_schema.PING)),
		               ))
	return results

def main(unused_argv):
	print "15"
	# Add any config contexts you want here.
	#config_lib.CONFIG.AddContext("Commandline Context")

	# This initializes all the stuff - it also calls registry.Init() itself.
	startup.Init()
	token = access_control.ACLToken(username="Me", reason="Why")

	print "Hello"

	clientlist = TheClients(".", token)

	print len(clientlist)

if __name__ == "__main__":
	flags.StartMain(main)




#s = socket.socket()         # Create a socket object
# host = socket.gethostname() # Get local machine name
# port = 8081               # Reserve a port for your service.
# s.bind((host, port))        # Bind to the port

# s.listen(5)                 # Now wait for client connection.
# while True:
# 	try:
# 		while True:
# 			c, addr = s.accept()     # Establish connection with client.
# 			data = c.recv(4096)
# 			while "EOD" not in data:
# 				data += c.recv(4096)
# 			alert = data.split("*STARTALERT*")[1].split("*ENDALERT*")[0]
# 			print alert
# 	except KeyboardInterrupt:
# 		print "Quitting"
# 		c.close()
# 		break
# 	finally:
# 		c.send('Thank you for connecting')
# 		c.close()                # Close the connection

# 