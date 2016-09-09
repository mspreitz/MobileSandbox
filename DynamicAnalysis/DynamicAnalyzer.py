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
sys.path.append(settingsDynamic.PATH_MODULE_CONFIG)
from msneo import create_node_dynamic
import misc_config

proc = None
resDir = ""


def initCuckoo(sampleFile):
    global proc
    if not os.path.isfile(misc_config.PATH_IFCONFIG):
        misc_config.PATH_IFCONFIG = '/sbin/ifconfig'

    try:
        net = subprocess.check_output([misc_config.PATH_IFCONFIG])
        if not "vboxnet0" in net:
            subprocess.call(["vboxmanage", "hostonlyif", "ipconfig",
                             settings.VBOX_DEV, "--ip", settings.VBOX_IP,
                             "--netmask", settings.VBOX_NETM])

    except:
        print "Error during check for running VMs"

    print 'Starting CUCKOO SERVER'
    try:
        proc = subprocess.Popen(['python2', settings.CUCKOO_SERVER],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    except:
        print "Error starting cuckoo server"

    print 'Starting CUCKOO SUBMIT'
    try:
        proc2 = subprocess.Popen(["python2",settings.CUCKOO_SUBMIT, sampleFile],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)
        results = proc2.communicate()
    except:
        print "Error in sample submission"

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
        running=False
        time.sleep(3)
        proc.kill()
        print "Analysis finished!"
    return True


def getListeningPorts(dir_extra_info):
    # headers = ['Proto','Recv-Q','Send-Q','Local-Address','Foreign-Address','State']
    file_netstat_before = '{}/{}'.format(dir_extra_info, settings.NETSTAT_LIST)
    file_netstat_after  = '{}/{}'.format(dir_extra_info, settings.NETSTAT_NEW)
    content = compareLists(file_netstat_before, file_netstat_after)
    res_natstat_entries = []
    for i in content:
        tmp = i.split()
        for u in range(len(tmp)):
            res_natstat_entries.append(tmp[u])
    return res_natstat_entries


def getProcesses(dir_extra_info):
    # headers = ['User','PID','PPID','VSIZE','RSS','WCHAN','PC','P','NAME']
    file_processes_before = '{}/{}'.format(dir_extra_info, settings.PLIST_FILE)
    file_processes_after  = '{}/{}'.format(dir_extra_info, settings.PLIST_NEW)
    content = compareLists(file_processes_before, file_processes_after)
    res_process_entries = []
    for i in content:
        tmp = i.split()
        for u in range(len(tmp)):
            res_process_entries.append(tmp[u])
    return res_process_entries


def compareLists(before, after):
    output = []
    vbox_ip = settings.VBOX_IP
    snap_ip = settings.SNAP_IP

    with open(before,"r") as process:
        lines = process.read().splitlines()
    with open(after, "r") as processNew:
        linesNew = processNew.read().splitlines()

    for i in linesNew:
        if i not in lines:
            if vbox_ip not in i and snap_ip not in i:
                output.append(i)
    return output


def cleanUp():
    try:
        #subprocess.call(["python2", settings.CUCKOO_SERVER, "--clean"])
        os.remove('{}/{}'.format("cuckoo", settings.PLIST_NEW))
        os.remove('{}/{}'.format("cuckoo", settings.PLIST_FILE))
        os.remove('{}/{}'.format("cuckoo", settings.NETSTAT_NEW))
        os.remove('{}/{}'.format("cuckoo", settings.NETSTAT_LIST))
        os.remove('{}/{}'.format("cuckoo", settings.SBOX_FOLDER_LIST))
    except:
        print "Error: could not cleanup all temporary files"


def getScreenShots(workingDir, cuckooID):
    screenShotDir = '{}/{}/shots/'.format(settings.CUCKOO_STORAGE, cuckooID)
    localScreenShotDir = workingDir+"/screenshots/"
    os.makedirs(localScreenShotDir)
    for dirpath, dirnames, filenames in os.walk(screenShotDir):
        for filename in filenames:
            shutil.copyfile(screenShotDir+filename, localScreenShotDir+filename)


def getApkFiles(cuckooTmp, workingDir):
    os.makedirs(cuckooTmp + "/apkfiles")
    shutil.move(cuckooTmp, workingDir+"/apkfiles")


def extractCuckooInfo(cuckooID):
    # Extract interesting information from cuckoo output
    file_json = '{}/{}/reports/report.json'.format(settings.CUCKOO_STORAGE, cuckooID)
    vbox_ip = settings.VBOX_IP
    snap_ip = settings.SNAP_IP

    with open(file_json, 'r') as jsonData:
        data = json.load(jsonData) # TODO This might be insecure

    # Get various connection types
    connections = {'udp': [], 'tcp': [], 'irc': [], 'smtp': []}

    print "Get network data..."
    output = {}
    if 'network' in data:
        for i in data['network']['udp']:
            udpSet = dict()
            if i['dst'] not in udpSet:
                if vbox_ip not in i['dst'] and snap_ip not in i['dst']:
                    udpSet['dst'] = i['dst']
                    udpSet['sport'] = i['sport']
                    udpSet['dport'] = i['dport']
                    connections['udp'].append(udpSet)

        for i in data['network']['tcp']:
            tcpSet = dict()

            if i['dst'] not in tcpSet:
                if vbox_ip not in i['dst'] and snap_ip not in i['dst']:
                    tcpSet['dst'] = i['dst']
                    tcpSet['sport'] = i['sport']
                    tcpSet['dport'] = i['dport']
                    connections['tcp'].append(tcpSet)

        for i in data['network']['irc']:
            ircSet = dict()
            if i['dst'] not in ircSet:
                if vbox_ip not in i['dst'] and snap_ip not in i['dst']:
                    ircSet['dst'] = i['dst']
                    ircSet['sport'] = i['sport']
                    ircSet['dport'] = i['dport']
                    connections['irc'].append(ircSet)

        for i in data['network']['smtp']:
            smtpSet = dict()
            if i['dst'] not in smtpSet:
                if vbox_ip not in i['dst'] and snap_ip not in i['dst']:
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
    if misc_config.ENABLE_CUCKOO_EXTRA_INFO:
        dir_extrainfo = 'cuckoo/'
        result['processes'] = getProcesses(dir_extrainfo)
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
    jsonFileName = '{}/{}'.format(workingDir, "dynamic.json")
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
    else:
        print "Error: Not finished"

#Todo: Copy Databases, work on code robustness