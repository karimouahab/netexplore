'''
Generates an RTT matrix from an arbitrary number of machines
Detect significant deviations from a reference matrix
Send a report of the analysis by email

Created on Nov 6, 2014

@author: karim ouahab
'''

from optparse import OptionParser   # For command line parsing
import subprocess                   # For shell commands
import json                         # For json input/output files
import re                           # For ping output parsing
import time
import collections
import smtplib
from email.mime.text import MIMEText

#global variables
machines    = None
pingMatrix  = collections.defaultdict()
refMatrix   = collections.defaultdict()
cmdLineOptions              = None
jsonconfig                  = None
PingOutputToMicroFactor     = 1000
pingCmd                     = "ping"
sshCmd                      = "ssh"
pingOKAlerts                = list()
pingNOKAlerts               = list()
allErrors                   = list()

OK_COLOR    = "#C1FFC1"
NOK_COLOR   = "#FF0000"
BET_COLOR   = "#33A1C9"


class Machine():
    """This class encapsulates information about a machine used as a source and/or a target of
    a ping test.
    """    
    def __init__(self, hostname, datacenter):
        self.hostname = hostname
        self.datacenter = datacenter
    def __str__(self):
        return "{}|{}".format(self.hostname, self.datacenter)
    def __eq__(self, other):
        return self.hostname == other.hostname and self.datacenter == other.datacenter
    def __ne__(self, other):
        return not self.__eq__(other)
    def __hash__(self):
        return hash(self.datacenter) ^ hash(self.hostname)
        
class Ping():
    """This class encapsulates the result of a ping command, with min, max, average, deviations, along
    with information on the source and target of the ping
    """    
    def __init__(self, minp, avgp, maxp, mdevp):
        self.min            = minp
        self.max            = maxp
        self.avg            = avgp
        self.mdev           = mdevp
        
    def __str__(self):
        return "min={} max={} avg={} mdev={}".format(self.min, self.max, self.avg, self.mdev)

class PingAlert():
    """This class encapsulates an alert, which is generated when a ping resultis abnormally low or high
    """    
    def __init__(self, srcMachine, tgtMachine, ping, refPing):
        self.srcMachine      = srcMachine
        self.tgtMachine      = tgtMachine
        self.ping            = ping
        self.refPing         = refPing
        
    def __str__(self):
        diff = 100 * (1 - float(self.ping) / float(self.refPing))
        return "RTT from {} to {} ".format(self.srcMachine.datacenter, self.tgtMachine.datacenter) + ("increased" if diff < 0 else "decreased") + " : from {} us to {} us ({} %)".format(self.refPing, self.ping, "{0:.1f}".format(diff))

def parseConfigurationFile(fileName):
    global machines, jsonconfig
    if not cmdLineOptions.quiet:
        print "Getting servers configuration from " + fileName
    with open(fileName) as machinesFile:
        jsonconfig  = json.load(machinesFile)
        machines    = jsonconfig["configuration"]["machines"]

def parseReferenceFile(fileName):
    if not cmdLineOptions.quiet:
        print "Getting reference rtt from " + fileName
    with open(fileName) as referenceFile:
        for line in referenceFile:
            match = re.search('(.*?)\|(.*?)->(.*?)\|(.*?) : (.*)', line)
            srcMachine = Machine(match.group(1),match.group(2))
            tgtMachine = Machine(match.group(3),match.group(4))
            ping       = Ping("0", match.group(5), "0", "0")
            if not refMatrix.has_key(srcMachine):
                refMatrix[srcMachine] = dict()
            refMatrix[srcMachine][tgtMachine] = ping

def getReferencePing(src, tgt):
    if refMatrix.has_key(src) and refMatrix[src].has_key(tgt):
        return refMatrix[src][tgt];
    return Ping("0", "N/A", "0", "0")

def jdefault(o):
    if isinstance(o, Machine):
        return [o.hostname, o.datacenter]
    return o.__dict__

def generateReferenceFile(matrix, fileName):
    with open(fileName, "w") as refFile:
        for src in matrix:
            for tgt in matrix[src]:
                refFile.write("{}->{} : {}\n".format(src, tgt, matrix[src][tgt].avg))

def parseConfiguration():
    global cmdLineOptions, pingCmd
    parser = OptionParser()
    
    parser.add_option("-f", "--file", dest="config_filename",
                      help="json configuration file", metavar="FILE")                      
    parser.add_option("-g", "--gen-reference",
                      dest="genReference", default=False,
                      help="generate a new rtt reference file to GEN_REFERENCE from the run") 
    parser.add_option("-q", "--quiet",
                      dest="quiet", default=True,
                      help="don't print ping messages to stdout")
    
    (cmdLineOptions, args)   = parser.parse_args() 
    
    if "" == cmdLineOptions.config_filename:
        print "Please provide a machines filename"
        parser.print_help()
        exit(1)
    parseConfigurationFile(cmdLineOptions.config_filename)
    pingCmd += " -q -c " + str(jsonconfig["configuration"]["ping_count"]) + " -w" + str(jsonconfig["configuration"]["ping_timeout"])
    if not cmdLineOptions.quiet:
        print "ping command is : " + pingCmd
    ref_rtt_filename = jsonconfig["configuration"]["reference_file"]
    if "" == ref_rtt_filename:
        print "Please provide a reference rtt filename"
        parser.print_help()
        exit(1)
    if not cmdLineOptions.genReference:
        parseReferenceFile(ref_rtt_filename)

def parsePingOutput(pingStr):
    try:
        match = re.search('([\d]*\.[\d]*)/([\d]*\.[\d]*)/([\d]*\.[\d]*)/([\d]*\.[\d]*)', pingStr)
        return Ping(
                    str(float(match.group(1)) * PingOutputToMicroFactor),
                    str(float(match.group(2)) * PingOutputToMicroFactor),
                    str(float(match.group(3)) * PingOutputToMicroFactor),
                    str(float(match.group(4)) * PingOutputToMicroFactor)
                    )   
    except Exception:
        return Ping("N/A", "N/A", "N/A", "N/A")


def executePings():
    sshUser     = jsonconfig["configuration"]["ssh_user"]
    sshOptions  = jsonconfig["configuration"]["ssh_options"]
    for source in machines:
        for target in machines:
            srcHost         = source["host"]
            tgtHost         = target["host"]
            srcDatacenter   = source["datacenter"]
            tgtDatacenter   = target["datacenter"]
            srcMachine = Machine(srcHost, srcDatacenter)
            tgtMachine = Machine(tgtHost, tgtDatacenter)
            if srcMachine == tgtMachine:
                output = "N/A"
            else:
                try:
                    output = subprocess.check_output("{} {} {}@localhost {} {} | grep rtt".format(sshCmd, sshOptions, sshUser, pingCmd, tgtHost) , shell=True)
                except Exception as e:
                    allErrors.append("An error occurred will trying to ping from {} to {} : {}".format(srcHost, tgtHost, e))
                    output = ""
            if not pingMatrix.has_key(srcMachine):
                pingMatrix[srcMachine] = dict()
            pingMatrix[srcMachine][tgtMachine] = parsePingOutput(output)
    printPings(pingMatrix)
    if cmdLineOptions.genReference:
        generateReferenceFile(pingMatrix, jsonconfig["configuration"]["reference_file"])
    return pingMatrix            

def printPings(results):
    if cmdLineOptions.quiet:
        return
    for src in results:
        for tgt in results[src]:
            print str(results[src][tgt])

def getPingAlertHtmlMessages():
    result = ""
    if len(pingNOKAlerts) > 0:
        result = "<b><font color=" + NOK_COLOR + ">Regressions:</font></b><ul>"
        for alert in pingNOKAlerts:
            result += "<li>" + str(alert) + '</li><br>'
        result += "</ul>"
    if len(pingOKAlerts) > 0:
        result += "<b><font color=" + BET_COLOR + ">Improvements:</font></b><ul>"
        for alert in pingOKAlerts:
            result += "<li>" + str(alert) + '</li><br>'
        result += "</ul>"        
    return  result

def getAllErrorsHtmlMessages():
    result = ""
    if len(allErrors) > 0:
        result = "<b>Errors:</b><ul>"
        for error in allErrors:
            result += "<li>" + error + '</li><br>'
        result += "</ul>"
    return result

def getHtmlComparisonToReference(srcMachine, tgtMachine, newPing, refPing):
    diff = 0
    deviationPercent = jsonconfig["configuration"]["deviation_percent"]
    if newPing.avg != "N/A" and refPing.avg != "N/A":
        diff = 100 * (1 - float(newPing.avg) / float(refPing.avg))
    color = OK_COLOR
    if diff > 0 and diff > deviationPercent:
        color =  BET_COLOR
        pingOKAlerts.append(PingAlert(srcMachine, tgtMachine, newPing.avg, refPing.avg))
    elif diff < 0 and -diff > deviationPercent:
        color =  NOK_COLOR
        pingNOKAlerts.append(PingAlert(srcMachine, tgtMachine, newPing.avg, refPing.avg))
    return "bgcolor=" + color + ">" + newPing.avg    

def generateHtmlTable(results):
    htmlTable = '<table border="1" style="width:100%" cellspacing="1" cellpadding="0" border="0" align="center" bgcolor="#999999">'
    htmlTable += "<tr><td></td>"
    for src in results:
        htmlTable += "<td align='center' bgcolor='#DBDBDB'><b>"
        htmlTable += "{} [{}]".format(src.datacenter, src.hostname)
        htmlTable += "</b></td>"
    htmlTable += "</tr>"
    for src in results:
        htmlTable += "<tr>"
        htmlTable += "<td align='center' bgcolor='#DBDBDB'><b>"
        htmlTable += "{} [{}]".format(src.datacenter, src.hostname)
        htmlTable += "</b></td>"
        for tgt in results[src]:
            htmlTable += "<td align='center' "
            htmlTable += getHtmlComparisonToReference(src, tgt, results[src][tgt], getReferencePing(src, tgt))
            htmlTable += "</td>"  
        htmlTable += "</tr>"
            
    htmlTable += "</table>"
    return htmlTable

def generateOutput(newTable, refTable):
    htmlOut = '''  
<html>  
    <head>  
    <title> Data Centers links round trip times (microseconds) </title>  
    </head>
    <body>
        <br>
        <br>
        <b>Latest RTT (microseconds) on {} :</b>
        {}
        <br>
        <br>
        {}
        <br>
        <br>
        {}
        <br>
        <br>        
        <b>Reference RTT (microseconds) :</b>
        {}
    </body>  
</html>
    
    '''.format(time.strftime("%d/%m/%Y %H:%M:%S"), newTable, getPingAlertHtmlMessages(), getAllErrorsHtmlMessages(), refTable)
    #with open("pings.html", "w") as output:
    #    output.write(htmlOut)
    return htmlOut

def sendReport(htmlReport):
    if not jsonconfig["configuration"]["always_send_report"] and len(pingOKAlerts) == 0 and len(pingNOKAlerts) == 0 :
        return
    
    fromMail    = jsonconfig["configuration"]["mail_from"]
    toMail      = jsonconfig["configuration"]["mail_to"]
    if not cmdLineOptions.quiet:
        print "sending report from {} to {}".format(fromMail, toMail)
    
    # Create a html message
    msg = MIMEText(htmlReport, 'html')
    
    msg['Subject']  = "[ALERT][DataCenters links] {} regressions - {} improvements".format(len(pingNOKAlerts), len(pingOKAlerts))
    msg['From']     = fromMail
    msg['To']       = toMail
    
    # Send the message via our own SMTP server, but don't include the
    # envelope header.
    s = smtplib.SMTP("smtp.gmail.com:587")
    s.ehlo()
    s.starttls()
    s.login("karim.ouahab", "")
    s.sendmail(fromMail, [toMail], msg.as_string())
    s.quit()

if __name__ == '__main__':
    parseConfiguration()
    newRun = generateHtmlTable(executePings())
    
    if cmdLineOptions.genReference: #don't generate a report if a new ref is generated
        exit(0)
    
    refRun = generateHtmlTable(refMatrix)
    report = generateOutput(newRun, refRun)
    sendReport(report)
    
