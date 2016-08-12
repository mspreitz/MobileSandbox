import os
import shutil
import subprocess
import time
import settings
import json

proc = None
resDir = ""


def initCuckoo(sampleFile):
    global proc

    net = subprocess.check_output(["/usr/bin/ifconfig"])
    if not "vboxnet0" in net:
        subprocess.call(["vboxmanage", "hostonlyif", "ipconfig",
                         settings.VBOX_DEV, "--ip", settings.VBOX_IP,
                         "--netmask", settings.VBOX_NETM])

    proc = subprocess.Popen(['python2', settings.CUCKOO_SERVER],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)

    subprocess.Popen(["python2",settings.CUCKOO_SUBMIT, sampleFile],
                            stdout=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def getResDir():
    running = True
    while(running):
        time.sleep(1)
        vboxoutput = subprocess.check_output(['vboxmanage', 'list', 'runningvms'])
        if vboxoutput == "":
            pass
        else:
            running = False

    try:
        dirs = next(os.walk(settings.CUCKOO_STORAGE))[1]
    except:
        dirs = []
    if (os.path.isdir(settings.CUCKOO_STORAGE + "latest")):
        cuckooWorkingDir = len(dirs)-1
    else:
        cuckooWorkingDir = len(dirs)

    print "Workingdir is: " + str(cuckooWorkingDir)

    return str(cuckooWorkingDir)


def isFinished():
    global proc
    global resDir

    resDir = getResDir()
    running=True
    while running:
        time.sleep(1)
        if os.path.isfile(settings.CUCKOO_STORAGE+str(resDir)+"/reports/report.html"):
            print "Analysis finished!"
            running=False
            time.sleep(3)
            proc.kill()
            print "Finished... "
    return True


def getListeningPorts(file, file_new):
    headers = ['Proto','Recv-Q','Send-Q','Local-Address','Foreign-Address','State']
    content = compareLists(file, file_new)
    res_natstat_entries = []
    for i in content:
        tmp = i.split()
        for u in range(len(tmp)):
            res_natstat_entries.append(tmp[u])
    return res_natstat_entries


def getProcesses(file, file_new):
    headers = ['User','PID','PPID','VSIZE','RSS','WCHAN','PC','P','NAME']
    res_process_entries = []
    content = compareLists(file, file_new)
    for i in content:
        tmp = i.split()
        for u in range(len(tmp)):
            res_process_entries.append(tmp[u])
            #res_process_entries[headers[u]] = tmp[u]
    return res_process_entries


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
        subprocess.call(["python2", settings.CUCKOO_SERVER, "--clean"])
        os.remove('{}/{}'.format("cuckoo", settings.PLIST_NEW))
        os.remove('{}/{}'.format("cuckoo", settings.PLIST_FILE))
        os.remove('{}/{}'.format("cuckoo", settings.NETSTAT_NEW))
        os.remove('{}/{}'.format("cuckoo", settings.NETSTAT_LIST))
        os.remove('{}/{}'.format("cuckoo", settings.SBOX_FOLDER_LIST))
    except:
        print "Error: could not cleanup all temporary files"

def getScreenShots(cuckooWorkingDir, workingDir):
    screenShotDir = settings.CUCKOO_STORAGE + cuckooWorkingDir + "/shots/"
    localScreenShotDir = '{}/{}'.format(workingDir,"screenshots/")
    os.makedirs(localScreenShotDir)
    for dirpath, dirnames, filenames in os.walk(screenShotDir):
        for filename in filenames:
            shutil.copyfile(screenShotDir+filename, localScreenShotDir+filename)

def getApkFiles(cuckooTmp, workingDir):
    os.makedirs(cuckooTmp + "/apkfiles")
    shutil.move(cuckooTmp, workingDir+"/apkfiles")


def extractCuckooInfo():
    global resDir

    # Extract interesting information from cuckoo output
    output = dict()
    with open(settings.CUCKOO_STORAGE+str(resDir)+"/reports/report.json") as jsonData:
        data = json.load(jsonData)

    # Get various connection types
    connections = dict()
    connections['udp'] = []
    connections['tcp'] = []
    connections['irc'] = []
    connections['smtp'] = []

    print "Get network data..."
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
    virusTotal = dict()
    virusTotal['permalink'] = data['virustotal']['permalink']
    virusTotal['positives'] = data['virustotal']['positives']
    output['virustotal'] = virusTotal
    #print connections
    #info = data['info']['machine']
    #for i in info:
    #    print str(i)+":"+str(info[i])
    #print output
    return output


def createOutput(workingDir, cuckooWorkingDir):
    result = dict()
    # Get relevant cuckoo results
    print "Extracting Cuckoo info..."
    result['cuckoo_out'] = extractCuckooInfo()
    # Compare Processes
    print "Get process info..."
    result['processes'] = getProcesses("cuckoo/" + settings.PLIST_FILE, "cuckoo/" + settings.PLIST_NEW)
    # Compare Listening Ports
    print "Get listening ports..."
    result['listening'] = getListeningPorts("cuckoo/" + settings.NETSTAT_LIST, "cuckoo/" + settings.NETSTAT_NEW)
    # Move files to working dir
    print "Moving files to working dir"
    getScreenShots(cuckooWorkingDir, workingDir)
    getApkFiles("cuckoo/tmp", workingDir)

    # save the JSON dict to a file for later use
    print "Pack JSON file and save it...."
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    jsonFileName = '{}/{}'.format(workingDir, "dynamic.json")
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(result))
    jsonFile.close()


# Main Programm
def run(sampleFile, workingDir):
    global resDir
    # Start cuckoo sandbox
    print "workingdir is %s" % workingDir
    initCuckoo(sampleFile)
    if isFinished():
        # Create JSON output file
        resDir = str(resDir)
        createOutput(workingDir,resDir)
        # Remove temp files
        print "Cleaning up temporary files"
        cleanUp()
    else:
        print "Error: Not finished"



#Todo: Copy Databases, work on code robustness