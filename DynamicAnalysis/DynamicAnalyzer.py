import os
import shutil
import subprocess
import time
import settings
import json
import re
import settingsDynamic

import sys
sys.path.append(settingsDynamic.PATH_MODULE_MSNEO)
from msneo import create_node_dynamic

proc = None
resDir = ""


def initCuckoo(sampleFile):
    global proc
    if not os.path.isfile(settings.PATH_IFCONFIG):
        settings.PATH_IFCONFIG = '/sbin/ifconfig'

    net = subprocess.check_output([settings.PATH_IFCONFIG])
    if not "vboxnet0" in net:
        subprocess.call(["vboxmanage", "hostonlyif", "ipconfig",
                         settings.VBOX_DEV, "--ip", settings.VBOX_IP,
                         "--netmask", settings.VBOX_NETM])
    print 'Starting CUCKOO SERVER'

    proc = subprocess.Popen(['python2', settings.CUCKOO_SERVER],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    print 'Starting CUCKOO SUBMIT'
    proc2 = subprocess.Popen(["python2",settings.CUCKOO_SUBMIT, sampleFile],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    results = proc2.communicate()
    print results
    regex_cuckooID = r'added as task with ID (\d+)'
    results = re.findall(regex_cuckooID, results[0])
    if len(results) < 1:
        print 'ERROR: Could not submit sample to cuckoo-droid!'
        return None

    if len(results) > 1:
        print 'ERROR: Somehow, cuckoo-droid returned two TASK IDs. Please revise this output: '
        from hexdump import hexdump
        for idx, result in enumerate(results):
            print 'RESULT ID {}'.format(idx)
            hexdump(result)
        return None

    cuckooID = results[0]
    return cuckooID

def isFinished(cuckooID):
    global proc
    global resDir

    running=True
    while running:
        time.sleep(1)
        path_report = '{}/{}/reports/report.html'.format(settings.CUCKOO_STORAGE,cuckooID)
        if not os.path.isfile(path_report): continue
        print "Analysis finished!"
        running=False
        time.sleep(3)
        proc.kill()
        print "Finish... "
    return True


def getListeningPorts(dir_extra_info):
    headers = ['Proto','Recv-Q','Send-Q','Local-Address','Foreign-Address','State']
    output = []
    file_netstat_before = '{}/{}'.format(dir_extra_info, settings.NETSTAT_FILE)
    file_netstat_after  = '{}/{}'.format(dir_extra_info, settings.NETSTAT_NEW)
    content = compareLists(file_netstat_before, file_netstat_after)
    for i in content:
        tmp = i.split()
        res_natstat_entries = {}
        for u in range(len(tmp)):
            res_natstat_entries[headers[u]] = tmp[u]
        output.append(res_natstat_entries)
    return output


def getProcesses(dir_extra_info):
    file_processes_before = '{}/{}'.format(dir_extra_info, settings.PLIST_FILE)
    file_processes_after  = '{}/{}'.format(dir_extra_info, settings.PLIST_NEW)
    headers = ['User','PID','PPID','VSIZE','RSS','WCHAN','PC','P','NAME']
    output = []
    content = compareLists(file_processes_before, file_processes_after)
    for i in content:
        res_process_entries = {}
        tmp = i.split()
        for u in range(len(tmp)):
            res_process_entries[headers[u]] = tmp[u]
        output.append(res_process_entries)
    return output


def compareLists(before, after):
    output = []

    with open(before,"r") as process:
        lines = process.read().splitlines()
    with open(after, "r") as processNew:
        linesNew = processNew.read().splitlines()

    for i in linesNew:
        if i not in lines:
            output.append(i)
    return output


def cleanUp():
    try:
        os.remove("cuckoo/"+settings.FILES_LIST)
        os.remove("cuckoo/"+settings.PLIST_NEW)
        os.remove("cuckoo/"+settings.PLIST_FILE)
        os.remove("cuckoo/"+settings.NETSTAT_NEW)
        os.remove("cuckoo/"+settings.NETSTAT_LIST)
        os.remove("cuckoo/"+settings.SBOX_FOLDER_LIST)
        os.removedirs("cuckoo/tmp")
    except:
        pass

def getScreenShots(workingDir, cuckooID):
    screenShotDir = '{}/{}/shots/'.format(settings.CUCKOO_STORAGE, cuckooID)
    localScreenShotDir = workingDir+"/screenshots/"
    os.makedirs(localScreenShotDir)
    for dirpath, dirnames, filenames in os.walk(screenShotDir):
        for filename in filenames:
            #print screenShotDir+filename
            shutil.copyfile(screenShotDir+filename, localScreenShotDir+filename)

def getApkFiles(cuckooTmp, workingDir):
    os.makedirs(cuckooTmp+"/apkfiles")
    shutil.move(cuckooTmp,workingDir+"/apkfiles")


def extractCuckooInfo(cuckooID):
    # Extract interesting information from cuckoo output
    file_json = '{}/{}/reports/report.json'.format(settings.CUCKOO_STORAGE, cuckooID)

    with open(file_json, 'r') as jsonData:
        data = json.load(jsonData) # TODO This might be insecure

    # Get various connection types
    connections = {'udp': [], 'tcp':[], 'irc':[], 'smtp':[]}

    print "Get network data..."
    output = {}
    if 'network' in data:
        for i in data['network']['udp']:
            udpSet = dict()
            if i['dst'] not in udpSet:
                udpSet['dst'] = i['dst']
                udpSet['sport'] = i['sport']
                udpSet['dport'] = i['dport']
            connections['udp'].append(udpSet)

        for i in data['network']['tcp']:
            tcpSet = dict()
            if i['dst'] not in tcpSet:
                tcpSet['dst'] = i['dst']
                tcpSet['sport'] = i['sport']
                tcpSet['dport'] = i['dport']
            connections['tcp'].append(tcpSet)

        for i in data['network']['irc']:
            ircSet = dict()
            if i['dst'] not in ircSet:
                ircSet['dst'] = i['dst']
                ircSet['sport'] = i['sport']
                ircSet['dport'] = i['dport']
            connections['irc'].append(ircSet)

        for i in data['network']['smtp']:
            smtpSet = dict()
            if i['dst'] not in smtpSet:
                smtpSet['dst'] = i['dst']
                smtpSet['sport'] = i['sport']
                smtpSet['dport'] = i['dport']
            connections['tcp'].append(smtpSet)
    else:
        print 'WARNING: network data could not be retrieved'
    output['network'] = connections
    # Get Certificate Info
    print "Get certificate info..."
    try:
        output['certificate'] = data['apkinfo']['certificate']
    except:
        print "No certificate found!"

    output['droppedFiles'] = data['dropped']

    # Method calls
    # print data['apkinfo']['static_method_calls']['crypto_method_calls']
    # print data['apkinfo']['static_method_calls']['dynamic_method_calls']
    # print data['apkinfo']['static_method_calls']['reflection_method_calls']

    # Get VirusTotal Scans
    virusTotal = {}
    virusTotal['permalink'] = data['virustotal']['permalink']
    virusTotal['positives'] = data['virustotal']['positives']
    output['virustotal'] = virusTotal
    #print connections
    #info = data['info']['machine']
    #for i in info:
    #    print str(i)+":"+str(info[i])
    #print output
    data_report_cuckoo = data
    return (output, data_report_cuckoo)


def createOutput(workingDir, cuckooID):
    print workingDir
    result = {}
    # Get relevant cuckoo results
    print "Extracting Cuckoo info..."
    (result['cuckoo_out'], data_report_cuckoo) = extractCuckooInfo(cuckooID)
    # Compare Processes
    print "Get process info..."
    if settingsDynamic.ENABLE_CUCKOO_EXTRA_INFO:
        dir_extrainfo = 'cuckoo/'
        result['processes'] = getProcesses(dir_extrainfo)
        #"cuckoo/" + settings.PLIST_FILE, "cuckoo/" + settings.PLIST_NEW)
        # Compare Listening Ports
        print "Get listening ports..."
        result['listening'] = getListeningPorts(dir_extrainfo)
        # Move files to working dir
        print "Moving files to working dir"
    else:
        result['processes'] = []
        result['listening'] = []
    getScreenShots(workingDir, cuckooID)
    getApkFiles("cuckoo/tmp", workingDir)
    

    # save the JSON dict to a file for later use
    print "Pack JSON file and save it...."
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    jsonFileName = workingDir + "/dynamic.json"
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(result))
    jsonFile.close()

    # Add dynamic report data of cuckoo to Neo4j
    create_node_dynamic(data_report_cuckoo)


# Main Programm
def run(sampleFile, workingDir):
    global resDir
    # Start cuckoo sandbox
    cuckooID = initCuckoo(sampleFile)
    print 'INITIALIZED CUCKOO'
    if isFinished(cuckooID):
        print 'FINISHED CUCKOO'
        # Create JSON output file
        createOutput(workingDir,cuckooID)
        # Remove temp files
        print "Cleaning up temporary files"
        cleanUp()


#sampleFile = "cuckoo/Samples/37.apk"
#run(sampleFile, setting.WORKINGDIR)
#print getProcesses("cuckoo/" + setting.PLIST_FILE, "cuckoo/" + setting.PLIST_NEW)
#print getListeningPorts("cuckoo/" + setting.NETSTAT_LIST, "cuckoo/" + setting.NETSTAT_NEW)
#Todo: Copy Databases, work on code robustness