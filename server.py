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

from grr.tools import console as theconsole

from grr.lib.flows import console
from grr.lib.flows.console import client_tests
from grr.lib.flows.console import debugging
from grr.lib.flows.general import memory

def main(unused_argv): 
    # Add any config contexts you want here. 
    config_lib.CONFIG.AddContext("--config /etc/grr/grr-server.yaml") 

    # This initializes all the stuff - it also calls registry.Init() itself. 
    startup.Init() 

    s = socket.socket()         # Create a socket object
    host = socket.gethostname() # Get local machine name
    port = 8081               # Reserve a port for your service.
    s.bind((host, port))        # Bind to the port
    s.listen(5)                 # Now wait for client connection.
    while True:
        try:
            while True:
                c, addr = s.accept()     # Establish connection with client.
                data = c.recv(4096)
                while "EOD" not in data:
                    data += c.recv(4096)
                alert = data.split("*STARTALERT*")[1].split("*ENDALERT*")[0]
		alert = alert.split("|")
		alert_time = str(alert[0])
		alert_direction = str(alert[1])
		alert_ip = str(alert[2])
		alert_mac = str(alert[3]).replace(":","")
		alert_type = str(alert[4])
		alert_priority = str(alert[5])
		results = theconsole.SearchClients(alert_mac)
		if len(results) > 0:
			if len(results) > 1:
				print "Too Many Results...? Fix this Later"
			else:
				computer = results[0]
				grrobject = computer[0]
				grr_IP =  grrobject.Get(grrobject.Schema.CLIENT_IP)
				grr_MAC = grrobject.Get(grrobject.Schema.MAC_ADDRESS)	
				#Testing to see if the alert if for the proper computer.
				if str(grr_IP) == alert_ip:
					grr_ID = str(computer[0]).split("aff4:/")[1].split(">")[0]
					hostname = computer[1]
					lastchecked = computer[3]
					print "------------------------------------"
					print "Alert Type: " + alert_type
					print "GRR_ID: " + grr_ID 
					print "Hostname: " + hostname
					print "Last Checkin: " + lastchecked
					print "Last IP in GRR: " + str(grr_IP)
					
					users = grrobject.Get(grrobject.Schema.USERNAMES)
					for user in users:
						user = str(user)
						if not (user == "LocalService" or user == "NetworkService" or user == "systemprofile" ):
							#Launch flow to collect browser artifacts
							print "Collecting Chrome Browser Data For " + user
							flow.GRRFlow.StartFlow(client_id=grr_ID, flow_name="ChromeHistory", username=user)


	
				else:
					print "------------------------------------"
					print "Alert host information does not match GRR Database"
					grr_ID = str(computer[0]).split("aff4:/")[1].split(">")[0]
					hostname = computer[1]
					lastchecked = computer[3]
					print "Alert Type: " + alert_type
					print "GRR_ID: " + grr_ID 
					print "Hostname: " + hostname
					print "Last Checkin: " + lastchecked
					print "Last IP in GRR: " + str(grr_IP)
		else:
			print "Client not found"
        except KeyboardInterrupt:
            print "Quitting"
            c.close()
            break
        finally:
            c.send('Thank you for connecting')
            c.close()                # Close the connection

    print len(theconsole.SearchClients(".")) 

if __name__ == "__main__": 
  flags.StartMain(main) 


