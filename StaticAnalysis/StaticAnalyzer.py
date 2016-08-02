from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.decompiler.dad import decompile
from Neo4J.msneo import create_node # TODO Change that to a Relative Parent Import Neo4J
from sys import exit
import chilkat
import csv
import datetime
import hashlib
import json
import os
import re
import settings
import shutil
#import ssdeep

def errorMessage(msg):
    #print '\033[1;38m'+msg+'\033[1;m'
    print "Error: >> "+msg

def createLogFile(logDir):
    if not os.path.exists(logDir):
        os.mkdir(logDir)
    logFile = open(logDir + "static.log", "a+")
    logFile.write("\n\n\n")
    logFile.write("              ___.   .__.__                                                .______.                                                  \n")
    logFile.write("  _____   ____\_ |__ |__|  |   ____               ___________    ____    __| _/\_ |__   _______  ___       ____  ____   _____        \n")
    logFile.write(" /     \ /  _ \| __ \|  |  | _/ __ \    ______   /  ___/\__  \  /    \  / __ |  | __ \ /  _ \  \/  /     _/ ___\/  _ \ /     \       \n")
    logFile.write("|  Y Y  (  <_> ) \_\ \  |  |_\  ___/   /_____/   \___ \  / __ \|   |  \/ /_/ |  | \_\ (  <_> >    <      \  \__(  <_> )  Y Y  \      \n")
    logFile.write("|__|_|  /\____/|___  /__|____/\___  >           /____  >(____  /___|  /\____ |  |___  /\____/__/\_ \  /\  \___  >____/|__|_|  /      \n")
    logFile.write("      \/           \/             \/                 \/      \/     \/      \/      \/            \/  \/      \/            \/       \n")
    logFile.write("\n")
    logFile.write("---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\n\t" + "static analysis")
    logFile.write("\n\t" + str(datetime.datetime.today()).split(' ')[0] + "\t-\t" + str(datetime.datetime.today()).split(' ')[1].split('.')[0])
    logFile.write("\n\n")
    return logFile

# make local log entries
def log(logFile, file, message, type):
    if type == 0:
        logFile.write("\n")
        logFile.write("-----------------------------------------------------------------------\n")
        logFile.write("\t" + message + "\n")
        logFile.write("-----------------------------------------------------------------------\n")
    if type == 1:
        logFile.write("\t\t" + file + "\t" + message + "\n")

# log file footer
def closeLogFile(logFile):
    logFile.write("\n\n\n")
    logFile.write("---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\t (c) by mspreitz 2015 \t\t www.mobile-sandbox.com")
    logFile.close()



def getProviders(logFile,a):
    log(logFile, 0, "used providers", 0)
    providers = a.get_providers()
    for provider in providers:
        log(logFile, "AndroidManifest", provider, 1)
    return providers


def getServiceReceiver(logFile,a):
    log(logFile, 0, "used services and receivers", 0)
    serviceANDreceiver = []
    for service in a.get_services():
        log(logFile, "AndroidManifest", service, 1)
        serviceANDreceiver.append(service)
    for receiver in a.get_receivers():
        log(logFile, "AndroidManifest", receiver, 1)
        serviceANDreceiver.append(receiver)
    return serviceANDreceiver


def getManifest(PREFIX,dv):
    manifest = dv.xml["AndroidManifest.xml"].toprettyxml()
    out = os.open(PREFIX+"AndroidManifest.xml",os.O_RDWR|os.O_CREAT, 0666)
    #print "[*] Writing Manifest to ",PREFIX+"AndroidManifest.xml"
    #print manifest
    os.write(out,manifest.encode("utf-8"))
    os.close(out)
    return manifest

def getCertificate(androguardAPK):
    r_cert = re.compile(r'META-INF/.*\.[DR]{1}SA')
    cert = []
    for f in androguardAPK.get_files():
        if r_cert.match(f): cert.append(f)
    # TODO: Cannot handle more than 1 certificate (solution: Read MANIFEST.MF and extract the name from here)
    if len(cert) != 1: return None
    (success, cert) = androguardAPK.get_certificate(cert[0])
    if not success: return None

    # TODO Maybe add bools such as self-signed, signature-verified etc
    # TODO Maybe add UTF-8 strings
    certdict = {}

    # Get all issuers
    certdict['IssuerC'] = cert.issuerC() # country
    certdict['IssuerCN'] = cert.issuerCN() # common name
    certdict['IssuerDN'] = cert.issuerDN() # full distinguished name
    certdict['IssuerE'] = cert.issuerE() # email address
    certdict['IssuerL'] = cert.issuerL() # locality (city, count, township, other geographic region)
    certdict['IssuerO'] = cert.issuerO() # organization (company name)
    certdict['IssuerOU'] = cert.issuerOU() # organizational unit (unit within organization)
    certdict['IssuerS'] = cert.issuerS() # state or province

    # Get all subjects
    certdict['SubjectC'] = cert.subjectC() # country
    certdict['SubjectCN'] = cert.subjectCN() # common name
    certdict['SubjectDN'] = cert.subjectDN() # full distinguished name
    certdict['SubjectE'] = cert.subjectE() # email address
    certdict['SubjectKeyId'] = cert.subjectKeyId() # email address
    certdict['SubjectL'] = cert.subjectL() # locality (city, count, township, other geographic region)
    certdict['SubjectO'] = cert.subjectO() # organization (company name)
    certdict['SubjectOU'] = cert.subjectOU() # organizational unit (unit within organization)
    certdict['SubjectS'] = cert.subjectS() # state or province

    # See https://www.chilkatsoft.com/refdoc/pythonCkCertRef.html
    # Other
    certdict['Rfc822Name'] = cert.rfc822Name()
    certdict['SerialNumber'] = cert.serialNumber()
    certdict['Sha1Thumbprint'] = cert.sha1Thumbprint()
    certdict['validFromStr'] = cert.validFromStr()
    certdict['validToStr'] = cert.validToStr()
    certdict['Version'] = cert.version()
    return certdict

def unpack(sampleFile,PREFIX):
    location = PREFIX + "unpack"
    os.mkdir(location)
    os.system("unzip -q -d" + location + " "+ sampleFile)
    return location


#Todo: In der Manifest-Datei ist das Icon moeglicherweise kodiert?!?!
def copyIcon(PREFIX,unpackLocation):
    manifest = open(PREFIX+"AndroidManifest.xml")
    for line in manifest:

        if "application" in line:
            try:
                icon = line.split("icon=\"")[1].split("\"")[0][1:]
            except:
                continue
        else:
            continue
    try:
        inputFile1 = unpackLocation + "res/" + icon
        outputFile = PREFIX + "icon.png"
        shutil.copy(inputFile1, outputFile)
    except:
        if os.path.isfile(unpackLocation + "/res/drawable/icon.png"):
            inputFile1 = unpackLocation + "/res/drawable/icon.png"
            outputFile = PREFIX + "icon.png"
            shutil.copy(inputFile1, outputFile)
        else:
            print "no icon found!"
            #Todo: Bug mit empty image
            #inputFile1 = settings.EMPTYICON
            #outputFile = PREFIX + "icon.png"
            #shutil.copy(inputFile1, outputFile)
    #print icon


def getIntents(logFile,a):
    log(logFile, 0, "used intents", 0)
    intents = []
    for i in a.xml:
        for receiver in a.xml[i].getElementsByTagName("intent-filter"): #receiver?
            for action in receiver.getElementsByTagName("action"):
                log(logFile, "AndroidManifest", action.getAttribute("android:name"), 1)
                intents.append(action.getAttribute("android:name"))
    return intents


#Todo: Funktion testen!
def getNet(a):
     appNet = []
     for line in a.xml:
         if "android.net" in line:
             try:
                 net = line.split("=")[1].split("\"")[1]
                 print errorMessage("Etwas gefunden!!!! (getNet Funktion)")
                 if net != "":
                     appNet.append(net)
             except:
                 continue
         else:
             continue
     return appNet


def usedFeatures(logFile,a):
    log(logFile, 0, "used features", 0)
    appFeatures = []
    for i in a.xml:
        for features in a.xml[i].getElementsByTagName("uses-feature"):
            feature = features.getAttribute("android:name")
            appFeatures.append(feature)
            log(logFile, "AndroidManifest", feature, 1)
    return appFeatures



def dumpMethods(d, workingDir):
    result = ""
    dumpFile = workingDir+settings.DUMPFILE
    fd = os.open(dumpFile, os.O_RDWR|os.O_CREAT)
    for current_class in d.get_classes():
        for method in current_class.get_methods():
            byteCode = method.get_code()
            if byteCode != None:
                byteCode = byteCode.get_bc()
                for i in byteCode.get_instructions():
                    result += "%s %s %s\n" % (current_class,i.get_name(),i.get_output())
    os.write(fd,result)


def parseDumpFile(workingDir, logFile, d):
    log(logFile, 0, "potentially suspicious api-calls", 0)
    #create dump file
    if(os.path.isfile(workingDir+settings.DUMPFILE)):
        os.remove(workingDir+settings.DUMPFILE)
    dumpMethods(d, workingDir)

    dangerousCalls = []
    file = workingDir+settings.DUMPFILE
    try:
        dumpFile = open(file).readlines()
        i = 0
        for line in dumpFile:
            i += 1
            if "Cipher" in line:
                try:
                    prevLine = dumpFile[dumpFile.index(line) - 2].split("\n")[0].split('"')[1]
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Cipher(" + prevLine + ")" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Cipher(" + prevLine + ")")
                except:
                    continue
            # only for logging !
            if "crypto" in line:
                try:
                    line = line.split("\n")[0]
                    log(logFile, file + ":" + str(i), line, 1)
                except:
                    continue
            if "Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append(
                        "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))")
            if "Ljava/net/HttpURLconnection" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "HttpURLconnection (Ljava/net/HttpURLconnection)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("HttpURLconnection (Ljava/net/HttpURLconnection)")
            if "getExternalStorageDirectory" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Read/Write External Storage" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Read/Write External Storage")
            if "getSimCountryIso" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSimCountryIso" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getSimCountryIso")
            if "execHttpRequest" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "execHttpRequest" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("execHttpRequest")
            if "Lorg/apache/http/client/methods/HttpPost" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "HttpPost (Lorg/apache/http/client/methods/HttpPost)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("HttpPost (Lorg/apache/http/client/methods/HttpPost)")
            if "Landroid/telephony/SmsMessage;->getMessageBody" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "readSMS (Landroid/telephony/SmsMessage;->getMessageBody)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("readSMS (Landroid/telephony/SmsMessage;->getMessageBody)")
            if "sendTextMessage" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "sendSMS" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("sendSMS")
            if "getSubscriberId" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSubscriberId" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getSubscriberId")
            if "getDeviceId" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getDeviceId" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getDeviceId")
            if "getPackageInfo" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getPackageInfo" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getPackageInfo")
            if "getSystemService" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSystemService" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getSystemService")
            if "getWifiState" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getWifiState" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getWifiState")
            if "system/bin/su" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "system/bin/su" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("system/bin/su")
            if "setWifiEnabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "setWifiEnabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("setWifiEnabled")
            if "setWifiDisabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "setWifiDisabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("setWifiDisabled")
            if "getCellLocation" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getCellLocation" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getCellLocation")
            if "getNetworkCountryIso" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getNetworkCountryIso" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getNetworkCountryIso")
            if "SystemClock.uptimeMillis" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "SystemClock.uptimeMillis" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("SystemClock.uptimeMillis")
            if "getCellSignalStrength" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getCellSignalStrength" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("getCellSignalStrength")
            if "Landroid/os/Build;->BRAND:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)")
            if "Landroid/os/Build;->DEVICE:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)")
            if "Landroid/os/Build;->MODEL:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)")
            if "Landroid/os/Build;->PRODUCT:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)")
            if "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)")
            if "adb_enabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Check if adb is enabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Check if adb is enabled")
            # used by exploits and bad programers
            if "Ljava/io/IOException;->printStackTrace" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "printStackTrace" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("printStackTrace")
            if "Ljava/lang/Runtime;->exec" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Execution of external commands (Ljava/lang/Runtime;->exec)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Execution of external commands (Ljava/lang/Runtime;->exec)")
            if "Ljava/lang/System;->loadLibrary" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ljava/lang/System;->loadLibrary)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ljava/lang/System;->loadLibrary)")
            if "Ljava/lang/System;->load" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ljava/lang/System;->load)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ljava/lang/System;->load)")
            if "Ldalvik/system/DexClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/DexClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ldalvik/system/DexClassLoader;)")
            if "Ldalvik/system/SecureClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/SecureClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ldalvik/system/SecureClassLoader;)")
            if "Ldalvik/system/PathClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/PathClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ldalvik/system/PathClassLoader;)")
            if "Ldalvik/system/BaseDexClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)")
            if "Ldalvik/system/URLClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/URLClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Loading of external Libraries (Ldalvik/system/URLClassLoader;)")
            if "android/os/Exec" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Execution of native code (android/os/Exec)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Execution of native code (android/os/Exec)")
            if "Base64" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Obfuscation(Base64)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.append("Obfuscation(Base64)")
    except:
        print "Error"

    return dangerousCalls


def getSampleInfo(sampleFile,logFile,a):
    # Todo: Exception handling besser machen!
    # Todo: get application label
    # Todo: check if SDK-Version ect. is specified...

    appInfos = []

    fp = open(sampleFile,'rb')
    content = fp.read()
    md5OfFile = hashlib.md5(content).hexdigest()
    shaOfFile = hashlib.sha256(content).hexdigest()
    fp.close()
    appInfos.append(shaOfFile)
    appInfos.append(md5OfFile)
    sdkVersion = a.get_target_sdk_version()
    try:
        appName = a.get_app_name()
    except:
        appName = ""

    apkName = str(sampleFile).split("/")[-1]

    if (sdkVersion == None):
        sdkVersion = ""

    log(logFile, 0, "application infos", 0)
    log(logFile, "sha256:", shaOfFile, 1)
    log(logFile, "md5:", md5OfFile, 1)

    appInfos.append(sdkVersion)
    appInfos.append(appName)
    appInfos.append(apkName)
    log(logFile,"SDK-Version",sdkVersion, 1)

    try:
        log(logFile,"App-Name",appName ,1)
    except:
        pass
    log(logFile,"APK-Name",apkName ,1)

    return appInfos


def parseURLs(workingdir,logFile):
    url = []
    fileList = []
    i=0
    log(logFile, 0, "URL's and IP's inside the code", 0)
    for dirname,dirnames,filenames in os.walk(workingdir):
        for filename in filenames:
            fileList.append(os.path.join(dirname,filename))
    for file in fileList:
        sourceFile = open(file).readlines()
        for line in sourceFile:
            try:
                urlPattern = re.search('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line).group()
                log(logFile, file + ":" + str(i), urlPattern, 1)
                if (urlPattern not in url) and (urlPattern != ""):
                    url.append(urlPattern)
                else:
                    continue
            except:
                continue
            try:
                ips = re.search('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line).group()
                log(logFile, file + ":" + str(i), ips, 1)
                if (ips not in url) and (ips != ""):
                    url.append(ips)
                else:
                    continue
            except:
                continue
            i += 1
    return url


def convert_descriptor(name):
    name=name[1:]
    return name.replace("/",".").replace(";","")


def check_dirs(directory,PREFIX):
    if not os.path.exists(PREFIX+directory):
        try:
            #Todo: war os.makedirs...
            os.makedirs(PREFIX+directory)
        except:
            errorMessage("Failed to create directory")
            pass


def check_path(class_path, PREFIX):
    if(settings.SOURCELOCATION[-1:] != "/"):
        PREFIX = PREFIX+settings.SOURCELOCATION+"/"
    else:
        PREFIX = PREFIX + settings.SOURCELOCATION

    org_path = class_path.replace(".","/")
    paths = org_path.split("/")
    paths = paths[:len(paths)-1]
    for index,folder in enumerate(paths):
        check_dirs("/".join(paths[:index+1]),PREFIX)
    return PREFIX+org_path+".java"


def getPermission(logFile,a):
    log(logFile, 0, "granted permissions", 0)
    permissions = a.get_permissions()
    for perm in permissions:
        log(logFile, "Permission:", perm, 1)
    return permissions


def getActivities(a):
    return a.get_activities()


def extractSourceFiles(PREFIX,d,vmx):
    check_dirs(settings.SOURCELOCATION,PREFIX)

    for _class in d.get_classes():
        class_path = convert_descriptor(_class.get_name())
        path = check_path(class_path,PREFIX)
        #print "[*] writing...'", path, "'"
        if not os.path.exists(path):
            source = open(path, "w")
            for field in _class.get_fields():

                access_flags = field.get_access_flags_string()
                if access_flags == "0x0":
                    access_flags = ""

                source.write("\t%s %s %s\n" % (access_flags, convert_descriptor(field.get_descriptor()), field.get_name()))

            for method in _class.get_methods():
                try:
                    g = vmx.get_method(method)
                    if method.get_code() == None:
                        continue
                    ms = decompile.DvMethod(g)
                    ms.process()
                    for line in ms.get_source().split("\n"):
                        source.write("\t%s\n" % line)
                except:
                    errorMessage("There was an error in decompiling one source file! Continuing...")
                    continue
            source.flush()
            source.close()


def checkAPIPermissions(workingDir):
    dumpFile = workingDir+settings.DUMPFILE
    file = open(dumpFile).read()
    apiCallList = open(settings.APICALLS).readlines()
    apiPermissions = []
    apiCalls = []

    for apiCall in apiCallList:
        apiCall = apiCall.split("|")
        if file.find(apiCall[0]) != -1:
            try:
                permission = apiCall[1].split("\n")[0]
            except:
                permission = ""
            if (permission not in apiPermissions) and (permission != ""):
                apiPermissions.append(permission)
                apiCalls.append(apiCall)
        else:
            continue
    return (apiPermissions, apiCalls)


def getFilesInsideApk(workingDir):
    fileList = []
    directory = workingDir+settings.SOURCELOCATION
    print directory
    if not os.path.exists(directory):
        errorMessage("source file directory does not exist!\nTerminating...")
        exit(1)
    for dirname, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    return fileList


#Todo: Methode muss noch mit einer APK, welche Ad-Networks enthaelt, getestet werden
#Check Ad-Networks
def check():
    dumpFile = settings.DUMPFILE
    with open(settings.ADSLIBS, 'Ur') as f:
        sPath = list(tuple(rec) for rec in csv.reader(f, delimiter=';'))
    detectedAds = list()
    for path in sPath:
        adPath = str(path[1])
        if(adPath in dumpFile):
            if (str(path[0]) not in detectedAds) and (str(path[0]) != ""):
                detectedAds.append(str(path[0]))
            else:
                continue
        else:
            continue
    return detectedAds


# create ssdeep hashes
#def ssdeepHash(fileSystemPosition):
#    try:
#        ssdeepValue = ssdeep.hash_from_file(fileSystemPosition)
#        return ssdeepValue
#    except Exception as e:
#        print str(e.message)
#        ssdeepValue = "(None)"
#        return ssdeepValue


def clearOldFiles(workingDir):
    jsonFile = workingDir+"static.json"
    logFile = workingDir+"static.log"
    dumpFile = workingDir+"Dump.txt"
    srcDir = workingDir+settings.SOURCELOCATION
    unpackDir = workingDir+settings.UNPACKLOCATION

    if os.path.isfile(jsonFile):
        os.remove(jsonFile)
    if os.path.isfile(logFile):
        os.remove(logFile)
    if os.path.isfile(dumpFile):
        os.remove(dumpFile)
    if os.path.exists(srcDir):
        shutil.rmtree(srcDir)
    if os.path.exists(unpackDir):
        shutil.rmtree(unpackDir)


def createOutput(workingDir, appNet, appProviders, appPermissions, appFeatures, appIntents, servicesANDreceiver, detectedAds,
                 dangerousCalls, appUrls, appInfos, apiPermissions, apiCalls, appFiles, appActivities):
    output = dict()
    output['md5'] = appInfos[1]
    output['sha256'] = appInfos[0]
    #output['ssdeep'] = ssdeepValue
    output['package_name'] = appInfos[3]
    output['apk_name'] = appInfos[4]
    output['sdk_version'] = appInfos[2]
    output['app_permissions'] = appPermissions
    output['api_permissions'] = apiPermissions
    output['api_calls'] = apiCalls
    output['features'] = appFeatures
    output['intents'] = appIntents
    output['activities'] = appActivities
    output['s_and_r'] = servicesANDreceiver
    output['interesting_calls'] = dangerousCalls
    output['urls'] = appUrls
    output['networks'] = appNet
    output['providers'] = appProviders
    output['included_files'] = appFiles
    output['detected_ad_networks'] = detectedAds

    # Save Certificate Information into output dict
    # TODO

    # save the JSON dict to a file for later use
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    jsonFileName = workingDir + "static.json"
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(output))
    jsonFile.close()

    # Transfer static analysis data to Neo4J by creating a node
    create_node(output)


def run(sampleFile, workingDir):

    clearOldFiles(workingDir)

    logFile = createLogFile(workingDir)
    PREFIX = workingDir
    unpackLocation = PREFIX+settings.UNPACKLOCATION

    if(PREFIX[-1:]!="/"):
        PREFIX += "/"
    if(unpackLocation[-1:] != "/"):
        unpackLocation += "/"

    if not os.path.exists(PREFIX):
        errorMessage("Targed path %s could not be found !" % PREFIX+"\nTerminating...")
        exit(1)

    if not os.path.exists(sampleFile):
        errorMessage("Could not find APK file %s !" % sampleFile+"\nTerminating...")
        exit(1)

    a = apk.APK(sampleFile)
    dv = dvm.APK(sampleFile)
    d = dvm.DalvikVMFormat(a.get_dex())
    vmx = analysis.newVMAnalysis(d)

    print "extract manifest..."
    getManifest(PREFIX,dv)
    print "unpacking sample..."
    unpack(sampleFile,PREFIX)
    print "extracting source files..."
    extractSourceFiles(PREFIX,d,vmx)
    print "get network data..."
    appNet = getNet(a)                                        #Todo: Ausgabe testen! android.net?!?!?!?
    print "get sample info..."
    appInfos = getSampleInfo(sampleFile,logFile,a)
    print "get providers..."
    appProviders = getProviders(logFile,a)
    print "get permissions..."
    appPermissions = getPermission(logFile, a)
    print "get activities..."
    appActivities = getActivities(a)
    print "get features..."
    appFeatures = usedFeatures(logFile,a)
    print "get intents..."
    appIntents = getIntents(logFile,a)
    print "list files"
    appFiles = getFilesInsideApk(workingDir)
    print "get service and receivers"
    serviceANDreceiver = getServiceReceiver(logFile,a)
    print "search for dangerous calls..."
    dangerousCalls = parseDumpFile(workingDir,logFile,d)
    print "get urls and ips..."
    appUrls = parseURLs(workingDir,logFile)
    print "check api permissions..."
    apiPermissions = checkAPIPermissions(workingDir)
    #print "create ssdeep hash..."
    #ssdeepValue = ssdeepHash(sampleFile)
    print "check for ad-networks"
    detectedAds = check()
    print "extract certificate information"
    #cert = getCertificate(a)
    print "create json report..."
    createOutput(workingDir,appNet,appProviders,appPermissions,appFeatures,appIntents,serviceANDreceiver,detectedAds,
                 dangerousCalls,appUrls,appInfos,apiPermissions[0],apiPermissions[1],appFiles,appActivities)#,ssdeepValue)
    print "copy icon image..."
    copyIcon(PREFIX,workingDir)
    print "closing log-file..."
    closeLogFile(logFile)


#run("Samples/833.apk","test/")
#exit(0)
count = 0
for root, dir, file in os.walk("Samples"):
    for s in file:
        print s
        sample = "Samples/"+s
        folder = s+"/"
        run(sample,folder)
        count = count + 1
        if count > 20:
            break

#Todo: ssdeep installieren und wieder einkommentieren!!