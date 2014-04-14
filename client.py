import socket
import time
import os, sys
import time
from datetime import datetime
from struct import *
from socket import *
import pickle

mynetwork = "10.1.0.0"

recentalerts = []

class Alert:
    def __init__(self,alertline):
        alert = alertline.split(" ")
        #for split in alert:
        #print split
        self.time = alert[0]
        self.time = "2014/" + self.time
        self.alerttime = self.time
        #print self.time
        self.time = datetime.strptime(self.time, "%Y/%m/%d-%H:%M:%S.%f")
        #self.time = time.mktime(self.time.timetuple())*1e3 + self.time.microsecond/1e3
        #print self.time

        #self.epochtime += (self.time.microsecond / 1000000000)
        #self.time = str(self.time) + "." + str(self.time.microsecond)
        #print self.epochtime
        #print self.time.microsecond
        self.type = alertline.split("[**]")[1].rstrip().lstrip()
        self.dstip = alert[-1]
        self.dstip = self.dstip.strip()
        self.dstip = self.dstip.split(":")
        self.dstip = self.dstip[0]
        #print self.dstip
        self.srcip = alert[-3]
        self.srcip = self.srcip.strip()
        self.srcip = self.srcip.split(":")
        self.srcip = self.srcip[0]
        #print self.srcip
        self.priority = alertline.split("Priority: ")[1].split("]")[0]
    def setmac(self, newmac):
        self.mac = newmac

def getmac(ip):
    fields = os.popen('grep %s /proc/net/arp' % ip).read().split()
    if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
        return fields[3]
    else:
        os.popen('ping -c 1 %s' % ip)
        fields = os.popen('grep %s /proc/net/arp' % ip).read().split()
        if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
            return fields[3]
        else:
            return 'no response from', ip

def follow(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def lookup(ip):
    f = unpack('!I',inet_pton(AF_INET,ip))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    ) 
    for net in private:
        if (f & net[1] == net[0]):
            return True
    return False
  
def notsamealert(alert1, alert2):
    timediff = alert1.time - alert2.time
    time = timediff.seconds + timediff.microseconds/1E6
    #print time
    same = False
    if (alert1.srcip == alert2.srcip) or (alert1.dstip == alert2.dstip) or (alert1.srcip == alert2.dstip) or (alert2.srcip == alert1.dstip) and (alert1.type == alert2.type):
        #print "TIME DIFFERENCE " + str(time)
        if time < 2:
            same = False
        else:
            same = True
    else:
        same = True
    return same

def sendalert(alert):
    s = socket()
    host = "10.1.0.10"
    port = 8081
    try:
        s.connect((host, port))
        s.send(alert)
        s.send("EODfsdf")
        s.close  
    except:
        print "The server refused our connection"
        #should try again later when the server is available


logfile = open("/var/log/snort/alert.fast")
loglines = follow(logfile)
oldalert = None
for line in loglines:
    newalert = Alert(line)
    #print newalert.time
    itsnew = False
    if oldalert != None:
        if notsamealert(newalert, oldalert):
            if lookup(newalert.srcip):
                print "New Alert"
                newalert.setmac(getmac(newalert.srcip))
                print newalert.mac + "|" + newalert.type + "|" + newalert.priority
                sendalert("*STARTALERT*" + newalert.mac + "|" + newalert.type + "|" + newalert.priority + "*ENDALERT*")
                #print getmac(newalert.srcip)
                #print "----------------------"
        #else:
            #print "Same Alert"
    else:
        if lookup(newalert.srcip):
            print "New Alert"
            newalert.setmac(getmac(newalert.srcip))
            print newalert.alerttime + "|FROM|" + newalert.srcip + "|" + newalert.mac + "|" + newalert.type + "|" + newalert.priority
            sendalert("*STARTALERT*" + newalert.alerttime + "|FROM|" + newalert.srcip + "|" + newalert.mac + "|" + newalert.type + "|" + newalert.priority + "*ENDALERT*")
            #print "----------------------"
        elif lookup(newalert.dstip):
            print "New Alert"
            newalert.setmac(getmac(newalert.srcip))
            print newalert.alerttime + "|TO|" + newalert.dstip + "|" + newalert.mac + "|" + newalert.type + "|" + newalert.priority
            sendalert("*STARTALERT*" + newalert.alerttime + "|TO|" + newalert.dstip + "|" + newalert.mac + "|" + newalert.type + "|" + newalert.priority + "*ENDALERT*")
            #print "----------------------"
	oldalert = newalert
