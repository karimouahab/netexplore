'''
- Generates an RTT matrix from an arbitrary number of machines
- Detect significant deviations from a reference matrix
- Send a report of the analysis by email

Created on Nov 6, 2014

@author: karim ouahab
'''

from optparse import OptionParser   # For command line parsing
import subprocess                   # For shell commands
import json                         # For json input/output files
import re                           # For ping output parsing
import socket                       # For gethostname
import time
import collections
import smtplib
import os
from email.mime.text import MIMEText

#global variables
machines                    = None
pingMatrix                  = collections.defaultdict()
refMatrix                   = collections.defaultdict()
cmdLineOptions              = None
jsonconfig                  = None
PingOutputToMicroFactor     = 1000
pingOKAlerts                = list()
pingNOKAlerts               = list()
allErrors                   = list()

PING_NA     = "N/A"

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
    """This class encapsulates an alert, which is generated when a ping result is abnormally low or high
    """    
    def __init__(self, srcMachine, tgtMachine, ping, refPing):
        self.srcMachine      = srcMachine
        self.tgtMachine      = tgtMachine
        self.ping            = ping
        self.refPing         = refPing
        
    def __str__(self):
        diff = 100 * (1 - float(self.ping.avg) / float(self.refPing.avg))
        return "RTT from {} to {} {} : from {} us to {} us ({} %) | ref min : {} us, ref max : {} us".format(
                                           self.srcMachine.datacenter,
                                           self.tgtMachine.datacenter,
                                           "increased" if diff < 0 else "decreased",
                                           self.refPing.avg,
                                           self.ping.avg, "{0:.1f}".format(diff),
                                           self.refPing.min,
                                           self.refPing.max)

"""Parse the json configuration file. The configuration node is stored in 'jsonconfig'
"""  
def parseConfigurationFile(fileName):
    global jsonconfig, machines
    if cmdLineOptions.verbose:
        print "Getting servers configuration from " + fileName
    with open(fileName) as machinesFile:
        jsonconfig  = json.load(machinesFile)["configuration"]
        machines    = jsonconfig["machines"]

"""Parse the reference average rtt file. The result is stored in refMatrix
""" 
def parseReferenceFile(fileName):
    if cmdLineOptions.verbose:
        print "Getting reference rtt from " + fileName
    with open(fileName) as referenceFile:
        for line in referenceFile:
            match = re.search('(.*?)\|(.*?)->(.*?)\|(.*?) : min=(.*) max=(.*) avg=(.*) mdev=(.*)', line)
            srcMachine = Machine(match.group(1),match.group(2))
            tgtMachine = Machine(match.group(3),match.group(4))
            ping       = Ping(match.group(5), match.group(7), match.group(6), match.group(8))
            if not refMatrix.has_key(srcMachine):
                refMatrix[srcMachine] = dict()
            refMatrix[srcMachine][tgtMachine] = ping

""" Retrieve the reference average rtt between the two given Machine
    If non is found, N/A is returned
""" 
def getReferencePing(src, tgt):
    if refMatrix.has_key(src) and refMatrix[src].has_key(tgt):
        return refMatrix[src][tgt];
    return Ping("0", PING_NA, "0", "0")

def jdefault(o):
    if isinstance(o, Machine):
        return [o.hostname, o.datacenter]
    return o.__dict__

def generateReferenceFile(matrix, fileName):
    with open(fileName, "w") as refFile:
        for src in matrix:
            for tgt in matrix[src]:
                ping = matrix[src][tgt]
                refFile.write("{}->{} : min={} max={} avg={} mdev={}\n".format(src, tgt, ping.min, ping.max, ping.avg, ping.mdev))

def parseConfiguration():
    global cmdLineOptions, jsonconfig
    parser = OptionParser()
    
    parser.add_option("-f", "--file", dest="config_filename",
                      help="json configuration file", metavar="FILE")                      
    parser.add_option("-g", "--gen-reference",
                      dest="genReference", default=False,
                      help="generate a new rtt reference file to GEN_REFERENCE from the run") 
    parser.add_option("-v", "--verbose",
                      dest="verbose", default=False,
                      help="verbose output to stdout")
    
    (cmdLineOptions, args)   = parser.parse_args() 
    
    if "" == cmdLineOptions.config_filename:
        print "Please provide a machines filename"
        parser.print_help()
        exit(1)
    parseConfigurationFile(cmdLineOptions.config_filename)
    ref_rtt_filename = jsonconfig["reference_file"]
    if "" == ref_rtt_filename:
        print "Please provide a reference rtt filename"
        parser.print_help()
        exit(1)
    if not cmdLineOptions.genReference:
        parseReferenceFile(ref_rtt_filename)

"""Parse the text output of a ping command, returns a Ping instance representing that output.
""" 
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
        return Ping(PING_NA, PING_NA, PING_NA, PING_NA)


"""Main ping procedure : execute ssh/ping command over all the links.
   Returns the ping matrix
""" 
def executePings():
    sshUser     = jsonconfig["ssh_user"]
    sshCmd      = jsonconfig["ssh_cmd"]
    sshOptions  = jsonconfig["ssh_options"]
    pingCmd     = jsonconfig["ping_cmd"] + " -q -c " + str(jsonconfig["ping_count"]) + " -w " + str(jsonconfig["ping_timeout"])
    if cmdLineOptions.verbose:
        print "ping command is : " + pingCmd
    
    for source in machines:
        for target in machines:
            srcHost         = source["host"]
            tgtHost         = target["host"]
            srcDatacenter   = source["datacenter"]
            tgtDatacenter   = target["datacenter"]
            srcMachine = Machine(srcHost, srcDatacenter)
            tgtMachine = Machine(tgtHost, tgtDatacenter)
            if srcMachine == tgtMachine and not jsonconfig["allow_ping_to_self"]:
                output = "-"
            else:
                try:
                    cmd = "{} {} {}@{} {} {} | grep rtt".format(sshCmd, sshOptions, sshUser, srcHost, pingCmd, tgtHost)
                    if cmdLineOptions.verbose:
                        print cmd
                    output = subprocess.check_output(cmd , shell=True)
                except Exception as e:
                    allErrors.append("An error occurred while trying to ping from {} to {} : {}".format(srcHost, tgtHost, e))
                    output = ""
            if not pingMatrix.has_key(srcMachine):
                pingMatrix[srcMachine] = dict()
            pingMatrix[srcMachine][tgtMachine] = parsePingOutput(output)
    printPings(pingMatrix)
    if cmdLineOptions.genReference:
        generateReferenceFile(pingMatrix, jsonconfig["reference_file"])
    return pingMatrix            

"""In non quiet mode, output the ping matrix to the standard output
""" 
def printPings(results):
    if not cmdLineOptions.verbose:
        return
    for src in results:
        for tgt in results[src]:
            print "{} to {} : {}".format(src, tgt, str(results[src][tgt]))

"""Returns an HTML view of all the ping alert messages
""" 
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
    if not result == "":
        result += "<br><i>Since changes have been detected, you may want to reset the reference rtt (-g option), or (unlikely) increase the deviation tolerances (current value : " + str(jsonconfig["deviation_percent"]) +" % or " + str(jsonconfig["deviation_micros"]) + " micros ) </i>"       
    return  result

"""Returns an HTML view of all the error messages (an error is NOT a ping alert)
""" 
def getAllErrorsHtmlMessages():
    result = ""
    if len(allErrors) > 0:
        result = "<b>Errors:</b><ul>"
        for error in allErrors:
            result += "<li>" + error + '</li><br>'
        result += "</ul>"
    return result

def isfloat(string):
    try:
        float(string)
        return True;
    except:
        return False

def getHtmlComparisonToReference(srcMachine, tgtMachine, results, isreference):
    newPing = results[srcMachine][tgtMachine]
    if isreference:
        return "bgcolor=" + OK_COLOR + ">" + newPing.avg  
    
    refPing     = getReferencePing(srcMachine, tgtMachine)
    diff        = 0
    diffPercent = 0
    devToAverage= 0
    deviationPercent    = jsonconfig["deviation_percent"]
    deviationMicros     = jsonconfig["deviation_micros"]
    pingStr = newPing.avg
    
    if isfloat(newPing.avg) and isfloat(refPing.avg):
        pingStr = str(float(newPing.avg)/1000) + " ms" if float(newPing.avg) > 1000 else str(float(newPing.avg)) + " us"
        devToAverage = 100 * (1 - float(newPing.avg) / float(refPing.avg))
        if devToAverage < 0 :
            diffPercent = 100 * (1 - float(newPing.avg) / float(refPing.max))
            diff = abs(float(newPing.avg) - float(refPing.max))
        else:
            diffPercent = 100 * (1 - float(newPing.avg) / float(refPing.min))
            diff = abs(float(newPing.avg) - float(refPing.min))
     
    if devToAverage > 0 and (diffPercent > deviationPercent or diff > deviationMicros): 
        pingOKAlerts.append(PingAlert(srcMachine, tgtMachine, newPing, refPing))
        return "bgcolor=" + BET_COLOR + "><b>" + pingStr + "</b>" 
    elif devToAverage < 0 and (-diffPercent > deviationPercent or diff > deviationMicros):
        pingNOKAlerts.append(PingAlert(srcMachine, tgtMachine, newPing, refPing))
        return "bgcolor=" + NOK_COLOR + "><b>" + pingStr + "</b>" 
    return "bgcolor=" + OK_COLOR + ">" + pingStr    

def generateHtmlTable(results, isreference):
    htmlTable = '<table border="1" style="width:100%" cellspacing="0.5" cellpadding="0" border="1" align="center" bgcolor="#FF7F50">'
    #Draw the header line
    htmlTable += "\n<tr>\n<td align='center'>From / To</td>\n"
    for src in results:
        htmlTable += "\n<td align='center' bgcolor='#DBDBDB'><b>"
        if jsonconfig["display_only_datacenters"]:
            htmlTable += "{}".format(src.datacenter)
        else:
            htmlTable += "{} [{}]".format(src.datacenter, src.hostname)
        htmlTable += "</b></td>\n"
    htmlTable += "</tr>\n"
    #Draw all the rows
    for src in results:
        htmlTable += "<tr>\n"
        htmlTable += "<td align='center' bgcolor='#DBDBDB'><b>"
        if jsonconfig["display_only_datacenters"]:
            htmlTable += "{}".format(src.datacenter)
        else:
            htmlTable += "{} [{}]".format(src.datacenter, src.hostname)
        htmlTable += "</b></td>\n"
        for tgt in results[src]:
            htmlTable += "<td align='center' "
            htmlTable += getHtmlComparisonToReference(src, tgt, results, isreference)
            htmlTable += "</td>\n"  
        htmlTable += "</tr>\n"
            
    htmlTable += "</table>"
    return htmlTable

"""Given a reference and a new HTML version of the RTT tables, generate the final HTML body
""" 
def generateOutput(newTable, refTable, printReference):
    hostname = socket.gethostname()
    htmlOut = '''  
<html>  
    <head>  
    <title> Data Centers links round trip times </title>  
    </head>
    <body>
        <br>
        <br>
        <b>Latest average RTT on {} :</b>
        <br>
        {}
        <br>
        <br>
        {}
        <br>
        <hr>
        <br>
        {}
        <br>
        <br>     
        {}
        <br>
        {}
        <br>
        <i>Program was executed by {} from {}</i>
    </body>  
</html>
    
    '''.format(time.strftime("%d/%m/%Y at %H:%M:%S"),
                newTable, getPingAlertHtmlMessages(),
                 getAllErrorsHtmlMessages(),
                "<b>Reference average RTT :</b>" if printReference else "",
                 refTable if printReference else "",
                 os.getlogin(), hostname
                 )
    #with open("pings.html", "w") as output:
    #    output.write(htmlOut)
    return htmlOut

def sendReport(htmlReport):
    hasAlerts = len(pingOKAlerts) != 0 or len(pingNOKAlerts) != 0
    if not jsonconfig["always_send_report"] and not hasAlerts:
        return
    
    fromMail    = jsonconfig["mail_from"]
    toMail      = jsonconfig["mail_to"]
    if cmdLineOptions.verbose:
        print "sending report from {} to {}".format(fromMail, toMail)
    
    # Create a html message
    msg = MIMEText(htmlReport, 'html')
    header = "[INFO]"
    if hasAlerts:
        header = "[ALERT]"
    msg['Subject']  = header + "[Network Lines] {} regression{} - {} improvement{}".format(
                                                                                         len(pingNOKAlerts),
                                                                                         "s" if len(pingNOKAlerts) > 1 else "",
                                                                                         len(pingOKAlerts),
                                                                                         "s" if len(pingOKAlerts) > 1 else "")
    msg['From'] = fromMail
    msg['To']   = toMail
    
    # Send the message via our own SMTP server, but don't include the
    # envelope header.
    s = smtplib.SMTP(jsonconfig["smtp_server"])
    s.ehlo()
    s.starttls()
    #s.login("karim.ouahab", "")
    s.sendmail(fromMail, [toMail], msg.as_string())
    s.quit()

if __name__ == '__main__':
    parseConfiguration()
    newRun = generateHtmlTable(executePings(), False)
    
    if cmdLineOptions.genReference: #don't generate a report if a new reference file is being generated
        exit(0)
    
    refRun = generateHtmlTable(refMatrix, True)
    report = generateOutput(newRun, refRun, jsonconfig["print_reference_table"])
    sendReport(report)
    
