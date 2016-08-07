from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.decompiler.dad import decompile
#from base64 import b64decode
#from hexdump import hexdump
from utils.mhash import *
from Neo4J.msneo import create_node # TODO Change that to a Relative Parent Import Neo4J
from sys import exit
import chilkat
import csv
import datetime
import json
import os
import re
import settings
import shutil
import xml.etree.ElementTree as ET
#import ssdeep

### TODO LIST
# ssdeep installieren und wieder einkommentieren!!
###
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def errorMessage(msg):
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
        logFile.write('\t {} \n'.format(message))
        logFile.write("-----------------------------------------------------------------------\n")
    if type == 1:
        logFile.write('\t\t {} {} \n'.format(file,message))

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
    serviceANDreceiver = set()
    for service in a.get_services():
        log(logFile, "AndroidManifest", service, 1)
        serviceANDreceiver.add(service)
    for receiver in a.get_receivers():
        log(logFile, "AndroidManifest", receiver, 1)
        serviceANDreceiver.add(receiver)
    return serviceANDreceiver


def getManifest(PREFIX,dv):
    manifest = dv.xml["AndroidManifest.xml"].toprettyxml()
    out = os.open(PREFIX+"AndroidManifest.xml",os.O_RDWR|os.O_CREAT, 0666)
    os.write(out,manifest.encode("utf-8"))
    os.close(out)
    return manifest


# See https://www.chilkatsoft.com/refdoc/pythonCkCertRef.html
def getCertificate(androguardAPK):
    # TODO Returns empty cert on any error case for now

    # TODO ECC missing
    r_cert = re.compile(r'META-INF/.*\.[DR]{1}SA')
    cert = [ f for f in androguardAPK.get_files() if r_cert.match(f) ]

    # TODO: Cannot handle more than 1 certificate (solution: Read MANIFEST.MF and extract the name from here)
    if len(cert) != 1: return {}

    (success, cert) = androguardAPK.get_certificate(cert[0])
    if not success: return {}

    # TODO Maybe add bools such as self-signed, signature-verified etc
    # TODO Maybe add UTF-8 strings
    # http://stackoverflow.com/questions/5790860/and-vs-list-and-dict-which-is-better
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

    # Other
    certdict['Rfc822Name'] = cert.rfc822Name()
    certdict['SerialNumber'] = cert.serialNumber()
    certdict['Sha1Thumbprint'] = cert.sha1Thumbprint()
    certdict['validFromStr'] = cert.validFromStr()
    certdict['validToStr'] = cert.validToStr()
    certdict['Version'] = cert.version()

    # Public Key Information: Modulus / Exponent / Key Length == Modulus Length
    # NOTE Unfortunately these are a lot of calls 
    # TODO Differentiate between DSA / RSA
    # TODO Read the getXml Method to ensure parsing this output can't be exploited
    pubKey = cert.ExportPublicKey()
    pubKeyXML = pubKey.getXml()
    root = ET.fromstring(pubKeyXML)
    certdict['pubkey'] = { 'keytype': None }
    if root.tag == 'RSAPublicKey':
        certdict['pubkey']['keytype'] = 'RSA'
        modulus  = root.find('Modulus')
        exponent = root.find('Exponent')
        # TODO Check for None
        #hexdump(b64decode(modulus.text))
        #hexdump(b64decode(exponent.text))
        # NOTE: Returns base64 encoded hex data. Convert to int using sage or python3
        certdict['pubkey']['modulus'] = modulus.text
        certdict['pubkey']['exponent'] = exponent.text
    elif root.tag == 'DSAPublicKey':
        certdict['pubkey']['keytype'] = 'DSA'
        dsa_P = root.find('P')
        dsa_Q = root.find('Q')
        dsa_G = root.find('G')
        dsa_Y = root.find('Y')
        certdict['pubkey']['P'] = P.text
        certdict['pubkey']['Q'] = Q.text
        certdict['pubkey']['G'] = G.text
        certdict['pubkey']['Y'] = Y.text
    elif root.tag == 'ECCPublicKey':
        certdict['pubkey']['keytype'] = 'ECC'
        # TODO
        pass
    else:
        # TODO
        pass
    return certdict


def unpack(sampleFile,PREFIX):
    location = PREFIX + "unpack"
    os.mkdir(location)
    os.system("unzip -q -d" + location + " "+ sampleFile)
    return location


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


def getIntents(logFile,a):
    log(logFile, 0, "used intents", 0)
    intents = set()
    for i in a.xml:
        for receiver in a.xml[i].getElementsByTagName("intent-filter"): #receiver?
            for action in receiver.getElementsByTagName("action"):
                log(logFile, "AndroidManifest", action.getAttribute("android:name"), 1)
                intents.add(action.getAttribute("android:name"))
    return intents


#Todo: Funktion testen!
def getNet(a):
     appNet = set()
     for line in a.xml:
         if "android.net" not in line: continue
         try:
             net = line.split("=")[1].split("\"")[1]
             print errorMessage("Etwas gefunden!!!! (getNet Funktion)")
             if net != "":
                 appNet.add(net)
         except:
             continue
     return appNet


def usedFeatures(logFile,a):
    log(logFile, 0, "used features", 0)
    appFeatures = set()
    for i in a.xml:
        for features in a.xml[i].getElementsByTagName("uses-feature"):
            feature = features.getAttribute("android:name")
            appFeatures.add(feature)
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

    dangerousCalls = set()
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
                        dangerousCalls.add("Cipher(" + prevLine + ")")
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
                    dangerousCalls.add(
                        "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))")
            if "Ljava/net/HttpURLconnection" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "HttpURLconnection (Ljava/net/HttpURLconnection)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("HttpURLconnection (Ljava/net/HttpURLconnection)")
            if "getExternalStorageDirectory" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Read/Write External Storage" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Read/Write External Storage")
            if "getSimCountryIso" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSimCountryIso" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getSimCountryIso")
            if "execHttpRequest" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "execHttpRequest" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("execHttpRequest")
            if "Lorg/apache/http/client/methods/HttpPost" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "HttpPost (Lorg/apache/http/client/methods/HttpPost)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("HttpPost (Lorg/apache/http/client/methods/HttpPost)")
            if "Landroid/telephony/SmsMessage;->getMessageBody" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "readSMS (Landroid/telephony/SmsMessage;->getMessageBody)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("readSMS (Landroid/telephony/SmsMessage;->getMessageBody)")
            if "sendTextMessage" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "sendSMS" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("sendSMS")
            if "getSubscriberId" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSubscriberId" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getSubscriberId")
            if "getDeviceId" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getDeviceId" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getDeviceId")
            if "getPackageInfo" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getPackageInfo" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getPackageInfo")
            if "getSystemService" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getSystemService" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getSystemService")
            if "getWifiState" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getWifiState" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getWifiState")
            if "system/bin/su" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "system/bin/su" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("system/bin/su")
            if "setWifiEnabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "setWifiEnabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("setWifiEnabled")
            if "setWifiDisabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "setWifiDisabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("setWifiDisabled")
            if "getCellLocation" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getCellLocation" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getCellLocation")
            if "getNetworkCountryIso" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getNetworkCountryIso" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getNetworkCountryIso")
            if "SystemClock.uptimeMillis" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "SystemClock.uptimeMillis" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("SystemClock.uptimeMillis")
            if "getCellSignalStrength" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "getCellSignalStrength" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("getCellSignalStrength")
            if "Landroid/os/Build;->BRAND:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)")
            if "Landroid/os/Build;->DEVICE:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)")
            if "Landroid/os/Build;->MODEL:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)")
            if "Landroid/os/Build;->PRODUCT:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)")
            if "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)")
            if "adb_enabled" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "Check if adb is enabled" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Check if adb is enabled")
            # used by exploits and bad programers
            if "Ljava/io/IOException;->printStackTrace" in line:
                log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                if "printStackTrace" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("printStackTrace")
            if "Ljava/lang/Runtime;->exec" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Execution of external commands (Ljava/lang/Runtime;->exec)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Execution of external commands (Ljava/lang/Runtime;->exec)")
            if "Ljava/lang/System;->loadLibrary" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ljava/lang/System;->loadLibrary)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ljava/lang/System;->loadLibrary)")
            if "Ljava/lang/System;->load" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ljava/lang/System;->load)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ljava/lang/System;->load)")
            if "Ldalvik/system/DexClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/DexClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ldalvik/system/DexClassLoader;)")
            if "Ldalvik/system/SecureClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/SecureClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ldalvik/system/SecureClassLoader;)")
            if "Ldalvik/system/PathClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/PathClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ldalvik/system/PathClassLoader;)")
            if "Ldalvik/system/BaseDexClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)")
            if "Ldalvik/system/URLClassLoader;" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Loading of external Libraries (Ldalvik/system/URLClassLoader;)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Loading of external Libraries (Ldalvik/system/URLClassLoader;)")
            if "android/os/Exec" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Execution of native code (android/os/Exec)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Execution of native code (android/os/Exec)")
            if "Base64" in line:
                log(logFile, file + ":" + str(i), line, 1)
                if "Obfuscation(Base64)" in dangerousCalls:
                    continue
                else:
                    dangerousCalls.add("Obfuscation(Base64)")
    except:
        print "Error"

    return dangerousCalls


def getSampleInfo(sampleFile,logFile,a):
    # Todo: get application label
    # Todo: check if SDK-Version ect. is specified...

    appInfos = {}
    with open(sampleFile, 'rb') as f:
        data = f.read()
        appInfos = hash_all(data)

    if not appInfos:
        print 'ERROR: cannot read sample {}'.format(sampleFile)
        exit(1)

    # TODO: Why replace None results with ''?
    appInfos['sdk_version_target'] = a.get_target_sdk_version()
    appInfos['sdk_version_min'] = a.get_min_sdk_version()
    appInfos['sdk_version_max'] = a.get_max_sdk_version()
    try:
        appInfos['app_name'] = a.get_app_name()
    except AttributeError: # TODO: This is a bug by androguard. Issue a pull request for this funciton
        appInfos['app_name'] = None
    appInfos['apk_name'] = str(sampleFile).split("/")[-1]
    appInfos['package_name'] = a.get_package()

    log(logFile, 0, "application infos", 0)
    log(logFile, "sha256:", appInfos['sha256'], 1)
    log(logFile, "sha1:", appInfos['sha1'], 1)
    log(logFile, "md5:", appInfos['md5'], 1)
    log(logFile,"SDK-Version",appInfos['sdk_version_target'], 1)
    log(logFile,"App-Name",appInfos['app_name'],1)
    log(logFile,"APK-Name",appInfos['apk_name'],1)
    log(logFile,"Package-Name",appInfos['package_name'],1)

    return appInfos


def parseURLs(workingdir,logFile):
    url = set()
    fileList = set()
    i=0
    log(logFile, 0, "URL's and IP's inside the code", 0)
    for dirname,dirnames,filenames in os.walk(workingdir):
        for filename in filenames:
            fileList.add(os.path.join(dirname,filename))
    for file in fileList:
        sourceFile = open(file).readlines()
        for line in sourceFile:
            try:
                urlPattern = re.search('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line).group()
                log(logFile, file + ":" + str(i), urlPattern, 1)
                if (urlPattern not in url) and (urlPattern != ""):
                    url.add(urlPattern)
                else:
                    continue
            except:
                continue
            try:
                ips = re.search('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line).group()
                log(logFile, file + ":" + str(i), ips, 1)
                if (ips not in url) and (ips != ""):
                    url.add(ips)
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
    permissions = set(a.get_permissions())
    for perm in permissions:
        log(logFile, "Permission:", perm, 1)
    return permissions


def getActivities(a):
    return set(a.get_activities())


def extractSourceFiles(PREFIX,d,vmx):
    check_dirs(settings.SOURCELOCATION,PREFIX)

    for _class in d.get_classes():
        class_path = convert_descriptor(_class.get_name())
        path = check_path(class_path,PREFIX)
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
    apiPermissions = set()
    apiCalls = []

    for apiCall in apiCallList:
        apiCall = apiCall.split("|")
        if file.find(apiCall[0]) != -1:
            try:
                permission = apiCall[1].split("\n")[0]
            except:
                permission = ""
            if (permission not in apiPermissions) and (permission != ""):
                apiPermissions.add(permission)
                apiCalls.append(apiCall)
        else:
            continue
    return (apiPermissions, apiCalls)

def getFilesInsideApk(androidAPK):
    return androidAPK.get_files()
    #return androidAPK.get_files_types()

def getFilesInsideApkSrc(workingDir):
    fileList = set()
    directory = workingDir+settings.SOURCELOCATION
    if not os.path.exists(directory):
        errorMessage("source file directory does not exist!\nTerminating...")
        exit(1)
    for dirname, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filename = dirname + filename
            fileList.add(filename[len(directory):])
    return fileList


#Todo: Funktion testen
#Check Ad-Networks
def check():
    dumpFile = settings.DUMPFILE
    with open(settings.ADSLIBS, 'Ur') as f:
        sPath = list(tuple(rec) for rec in csv.reader(f, delimiter=';'))
    detectedAds = set()
    for path in sPath:
        adPath = str(path[1])
        if(adPath in dumpFile):
            if (str(path[0]) not in detectedAds) and (str(path[0]) != ""):
                detectedAds.add(str(path[0]))
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
                 dangerousCalls, appUrls, appInfos, apiPermissions, apiCalls, appFilesSrc, appActivities, cert, appFiles):
    output = appInfos # Since it already contains a dict of most fingerprints
    output['app_permissions'] = list(appPermissions)
    output['api_permissions'] = list(apiPermissions)
    output['api_calls'] = list(apiCalls)
    output['features'] = list(appFeatures)
    output['intents'] = list(appIntents)
    output['activities'] = list(appActivities)
    output['s_and_r'] = list(servicesANDreceiver)
    output['interesting_calls'] = list(dangerousCalls)
    output['urls'] = list(appUrls)
    output['networks'] = list(appNet)
    output['providers'] = list(appProviders)
    output['included_files_src'] = list(appFilesSrc)
    output['included_files'] = list(appFiles)
    output['detected_ad_networks'] = list(detectedAds)
    # Save Certificate Information into output dict
    output['cert'] = cert


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

    print "get sample info..."
    appInfos = getSampleInfo(sampleFile,logFile,a)
    print 'Got Sample Information for Sample with SHA256: {}'.format(appInfos['sha256'])
    print "extract manifest..."
    getManifest(PREFIX,dv)
    print "unpacking sample..."
    unpack(sampleFile,PREFIX)
    print "extracting source files..."
    extractSourceFiles(PREFIX,d,vmx)
    print "get network data..."
    appNet = getNet(a)                                        #Todo: Ausgabe testen! android.net?!?!?!?
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
    print "get files in src..."
    appFilesSrc = getFilesInsideApkSrc(workingDir)
    print "get files in APK..."
    appFiles = getFilesInsideApk(a)
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
    cert = getCertificate(a)
    print "create json report..."
    createOutput(workingDir,appNet,appProviders,appPermissions,appFeatures,appIntents,serviceANDreceiver,detectedAds,
                 dangerousCalls,appUrls,appInfos,apiPermissions[0],apiPermissions[1],appFilesSrc,appActivities, cert, appFiles)#,ssdeepValue)
    print "copy icon image..."
    copyIcon(PREFIX,workingDir)
    print "closing log-file..."
    closeLogFile(logFile)