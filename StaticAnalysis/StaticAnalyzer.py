from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.decompiler.dad import decompile
#from base64 import b64decode
from hexdump import hexdump
from utils.mhash import *
from sys import exit
import chilkat
import datetime
import json
import os
import re
import settings
import shutil
import xml.etree.ElementTree as ET
import traceback
#import ssdeep

### TODO LIST
# ssdeep installieren und wieder einkommentieren!!
###
import sys
sys.path.append(settings.PATH_MODULE_MSNEO)
sys.path.append(settings.PATH_MODULE_CONFIG)
from msneo import create_node_static
import misc_config
reload(sys)
sys.setdefaultencoding('utf-8')

def errorMessage(msg):
    print "Error: >> "+msg

def createLogFile(logDir):
    if not os.path.exists(logDir):
        os.mkdir(logDir)
    logFile = open('{}/{}'.format(logDir,"static.log"), "a+")
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
    destManifest = '{}/{}'.format(PREFIX, 'AndroidManifest.xml')
    out = os.open(destManifest,os.O_RDWR|os.O_CREAT, 0666)
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
        certdict['pubkey']['P'] = dsa_P.text
        certdict['pubkey']['Q'] = dsa_Q.text
        certdict['pubkey']['G'] = dsa_G.text
        certdict['pubkey']['Y'] = dsa_Y.text
    elif root.tag == 'ECCPublicKey':
        certdict['pubkey']['keytype'] = 'ECC'
        # TODO
        pass
    else:
        # TODO
        pass
    return certdict


def unpack(sampleFile, PREFIX):
    location = '{}/{}/'.format(PREFIX, settings.DEFAULT_NAME_DIR_UNPACK)
    os.mkdir(location)
    os.system('unzip -q -d {} {}'.format(location, sampleFile))
    return location


def copyIcon(PREFIX,unpackLocation):

    icon = None
    with open(PREFIX+"AndroidManifest.xml") as manifest:
        for line in manifest:
            if "application" not in line: continue
            try:
                icon = line.split("icon=\"")[1].split("\"")[0][1:]
            except:
                continue

    if not icon:
        print 'No Icon Found!'
        return

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

def getAPICallsADs(workingDir, logFile, d): # TODO Mid-High O
    nope="""
        if "Cipher" in line:
            try:
                prevLine = dumpFile[dumpFile.index(line) - 2].split("\n")[0].split('"')[1]
                log(logFile, dumplinenumber, line.split("\n")[0], 1)
                if "Cipher(" + prevLine + ")" in dangerousCalls:
                    continue
                dangerousCalls.add("Cipher(" + prevLine + ")")
            except:
                continue
        # only for logging !
        if "crypto" in line:
            try:
                line = line.split("\n")[0]
                log(logFile, dumplinenumber, line, 1)
            except:
                continue
    """


    log(logFile, 0, "Potentially suspicious API-Calls", 0)

    data_dump = ''

    dumplinenumber = 0
    api_calls_dump = {}
    dict_detected_ads = {}

    # Dump smali instructions with related class names and output using AndroGuard
    for current_class in d.get_classes():
        for method in current_class.get_methods():
            byteCode = method.get_code()
            if byteCode is None: continue

            byteCode = byteCode.get_bc()
            try:
                for instr in byteCode.get_instructions():
                    line = '{} {} {}'.format(current_class, instr.get_name(), instr.get_output())
                    data_dump += line + '\n'
                    dumplinenumber += 1

                    # Parse API Calls from Dump
                    # TODO Exchange if apicall in line with regex over the whole dump
                    for apicall, apicall_attributes in settings.DICT_APICALLS.items():
                        if apicall not in line: continue
                        log(logFile, 'Dump.txt:{}'.format(dumplinenumber), line, 1)
                        api_calls_dump[apicall] = apicall_attributes
                        break

                    for adslib_name, adslib_attributes in settings.DICT_ADSLIBS.items():
                        if adslib_attributes['path'] not in line: continue
                        dict_detected_ads[adslib_name] = adslib_attributes['path'] 
                        break


            except dvm.InvalidInstruction:
                print 'ERROR: Androguard could not decompile. Continue/Abort decompiling this instruction!'
                continue

    path_dump = '{}/{}'.format(workingDir,settings.DUMPFILE)
    with open(path_dump, 'w') as f:
        f.write(data_dump)

    TODO="""
    bigregex = ''

    set_apicall_names = set()
    for apicall_name, apicall_attributes in settings.DICT_APICALLS.items():
        bigregex += apicall_name + '|'
        set_apicall_names.add(apicall_name)


    set_adslibs_paths = set()
    dict_adslib_path_to_adslib_name = {}
    for adslib_name, adslib_attributes in settings.DICT_ADSLIBS.items():
        bigregex += adslib_attributes['path'] + '|'
        set_adslibs_paths.add(adslib_attributes['path'])
        dict_adslib_path_to_adslib_name[adslib_attributes['path']] = adslib_name


    bigregex = bigregex[:len(bigregex)-1]
    bigregex = '({})'.format(bigregex)

    print 'prereg'
    set_results = re.findall(bigregex, data_dump)
    if len(set_results) < 1:
        return ({}, {})
    print 'postreg'

    set_results = set([ x[0] for x in set_results ])

    for apicall_name in (set_apicall_names & set_results):
        api_calls_dump[apicall_name] = settings.DICT_APICALLS[apicall_name]

    for adslib_path in (set_adslibs_paths & set_results):
        adslib_name = dict_adslib_path_to_adslib_name[adslib_path]
        dict_detected_ads[adslib_name] = settings.DICT_ADSLIBS[adslib_name]
    """

    return (api_calls_dump, dict_detected_ads)


def getSampleInfo(sampleFile,logFile,a):
    # TODO: get application label
    # TODO: check if SDK-Version ect. is specified...

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

def extractSourceFiles(PREFIX,d,vmx): # TODO High O
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
                    if method.get_code() is None:
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

def getFilesExtendedInsideApk(androidAPK):
    files = {}
    for filename in androidAPK.zip.namelist():
        file_data = androidAPK.zip.read(filename)
        files[filename] = {}
        files[filename]['md5'] = hash_md5(file_data)
        files[filename]['sha1'] = hash_sha1(file_data)
        files[filename]['sha256'] = hash_sha256(file_data)
        #files['ssdeep'] = hash_ssdeep(file_data)
    return files

def getFilesInsideApk(androidAPK):
    return androidAPK.get_files()
    #return androidAPK.get_files_types()

def getFilesInsideApkSrc(workingDir):
    fileList = set()
    directory = '{}/{}/'.format(workingDir, settings.SOURCELOCATION)
    if not os.path.exists(directory):
        errorMessage("source file directory does not exist!\nTerminating...")
        exit(1)
    for dirname, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            filename = dirname + filename
            fileList.add(filename[len(directory):])
    return fileList


def clearOldFiles(workingDir):
    jsonFile  = '{}/{}'.format(workingDir,"static.json")
    logFile   = '{}/{}'.format(workingDir,"static.log")
    srcDir    = '{}/{}'.format(workingDir,settings.DEFAULT_NAME_DIR_SOURCE)
    unpackDir    = '{}/{}'.format(workingDir,settings.DEFAULT_NAME_DIR_UNPACK)

    if os.path.isfile(jsonFile):
        os.remove(jsonFile)
    if os.path.isfile(logFile):
        os.remove(logFile)
    if os.path.exists(srcDir):
        shutil.rmtree(srcDir)
    if os.path.exists(unpackDir):
        shutil.rmtree(unpackDir)


def createOutput(workingDir, appNet, appProviders, appPermissions, appFeatures, appIntents, servicesANDreceiver, detectedAds,
                 appUrls, appInfos, api_dict, appFilesSrc, appActivities, cert, appFiles, dict_dex):
    output = appInfos # Since it already contains a dict of most fingerprints
    output['app_permissions'] = list(appPermissions)
    output['api_permissions'] = []
    output['api_calls'] = api_dict
    output['interesting_calls'] = []
    for api_call, api_call_attributes in api_dict.items():
        if api_call_attributes['permission']:
            output['api_permissions'].append(api_call_attributes['permission'])
        if api_call_attributes['dangerous']:
            output['interesting_calls'].append(api_call)

    output['features'] = list(appFeatures)
    output['intents'] = list(appIntents)
    output['activities'] = list(appActivities)
    output['s_and_r'] = list(servicesANDreceiver)
    output['urls'] = list(appUrls)
    output['networks'] = list(appNet)
    output['providers'] = list(appProviders)
    output['included_files_src'] = list(appFilesSrc)
    output['included_files'] = appFiles
    output['detected_ad_networks'] = detectedAds
    # Save Certificate Information into output dict
    output['cert'] = cert
    output['strings'] = dict_dex['strings']
    output['fields'] = dict_dex['fields']


    # save the JSON dict to a file for later use
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    jsonFileName = '{}/{}'.format(workingDir,"static.json")
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(output))
    jsonFile.close()

    # Transfer static analysis data to Neo4J by creating a node
    create_node_static(output)


def run(sampleFile, workingDir):

    if misc_config.ENABLE_CLEAR_OLD_FILES: clearOldFiles(workingDir)

    logFile = createLogFile(workingDir)
    PREFIX = workingDir
    unpackLocation = '{}/{}'.format(PREFIX,settings.DEFAULT_NAME_DIR_UNPACK)

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
    if misc_config.ENABLE_EXTRACT_SOURCES: extractSourceFiles(PREFIX,d,vmx)
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
    if misc_config.ENABLE_EXTRACT_SOURCES:
        appFilesSrc = getFilesInsideApkSrc(workingDir)
    else:
        appFilesSrc = []
    print "get files in APK..."
    appFiles = getFilesExtendedInsideApk(a)
    print "get service and receivers"
    serviceANDreceiver = getServiceReceiver(logFile,a)
    print "get (dangerous) api calls and ad-networks..."
    (api_dict, ads_dict) = getAPICallsADs(workingDir,logFile,d)
    print "get urls and ips..."
    appUrls = parseURLs(workingDir,logFile)
    #print "create ssdeep hash..."
    #ssdeepValue = ssdeepHash(sampleFile)
    print "extract certificate information"
    cert = getCertificate(a)

    dict_dex = {'strings':[], 'fields':[]}
    print 'get strings...'
    if misc_config.ENABLE_PARSING_STRINGS: dict_dex['strings'] = list(set([ string.strip() for s in d.get_strings()]))
    print 'get fields...'
    if misc_config.ENABLE_PARSING_FIELDS: dict_dex['fields'] = list(set([ field.get_name().strip() for field in d.get_all_fields() ]))
    print "create json report..."
    createOutput(workingDir,appNet,appProviders,appPermissions,appFeatures,appIntents,serviceANDreceiver,ads_dict,
                 appUrls,appInfos,api_dict,appFilesSrc,appActivities, cert, appFiles, dict_dex)#,ssdeepValue)
    print "copy icon image..."
    copyIcon(PREFIX,workingDir)
    print "closing log-file..."
    closeLogFile(logFile)