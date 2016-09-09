#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
# MobileSandbox Authentication Parameters
MSURL = ''	# URL of the Mobile-Sandbox backend
MSAPIFORMAT = 'json'

# important files and folders
EMPTYICON = "./empty.png"
APICALLS = "./APIcalls.txt"
ADSLIBS = "./ads.csv"

WORKINGDIR = "test/"
SOURCELOCATION = "src"
DUMPFILE = "Dump.txt"
TMPDIR = "/tmp/analysis/"

# Samples Folder for the Backend
BACKEND_PATH = '../Backend/'

# Constants # TODO Names are a bit long
PATH_SAMPLES = 'analyzer/samples/'
DEFAULT_NAME_APK = 'sample.apk'
DEFAULT_NAME_DIR_UNPACK = 'unpack'
DEFAULT_NAME_DIR_SOURCE = 'src'
DEFAULT_NAME_DIR_ANALYSIS = 'analysis'
PATH_MODULE_MSNEO = '../Neo4J/'
PATH_MODULE_CONFIG = '../config/'

###### Dictionaries etc

# Dictionary ApiCall -> Description
DICT_APICALLS_DANGEROUS = {
    'Base64' : 'Obfuscation',
    'Landroid/os/Build;->BRAND:Ljava/lang/String' : 'Access Device Info',
    'Landroid/os/Build;->DEVICE:Ljava/lang/String' : 'Access Device Info',
    'Landroid/os/Build;->FINGERPRINT:Ljava/lang/String' : 'Access Device Info',
    'Landroid/os/Build;->MODEL:Ljava/lang/String' : 'Access Device Info',
    'Landroid/os/Build;->PRODUCT:Ljava/lang/String' : 'Access Device Info',
    'Landroid/telephony/SmsMessage;->getMessageBody' : 'readSMS',
    'Ldalvik/system/BaseDexClassLoader;' : 'Loading of external Libraries',
    'Ldalvik/system/DexClassLoader;' : 'Loading of external Libraries',
    'Ldalvik/system/PathClassLoader;' : 'Loading of external Libraries',
    'Ldalvik/system/SecureClassLoader;' : 'Loading of external Libraries',
    'Ldalvik/system/URLClassLoader;' : 'Loading of external Libraries',
    'Ljava/io/IOException;->printStackTrace' : 'printStackTrace', # used by exploits and bad programers
    'Ljava/lang/Runtime;->exec' : 'Execution of external commands',
    'Ljava/lang/System;->load' : 'Loading of external Libraries',
    'Ljava/lang/System;->loadLibrary' : 'Loading of external Libraries',
    'Ljava/net/HttpURLconnection' : 'HttpURLconnection',
    'Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)': 'HTTP GET/POST',
    'Lorg/apache/http/client/methods/HttpPost' : 'HttpPost',
    'SystemClock.uptimeMillis' : None,
    'adb_enabled' : 'Check if adb is enabled',
    'android/os/Exec' : 'Execution of native code',
    'execHttpRequest': None,
    'getCellLocation' : None,
    'getCellSignalStrength' : 'SystemClock.getCellSignalStrength',
    'getDeviceId' : None,
    'getExternalStorageDirectory': 'Read/Write External Storage',
    'getNetworkCountryIso' : None,
    'getPackageInfo' : None,
    'getSimCountryIso' : None,
    'getSubscriberId' : None,
    'getSystemService' : None,
    'getWifiState' : None,
    'sendTextMessage' : 'sendSMS',
    'setWifiDisabled' : None,
    'setWifiEnabled' : None,
    'system/bin/su' : None
}

# Get dictionary APICall -> Attributes
# Dictionary from call to permission(s)
DICT_APICALLS = {}
# Add dangerous APICall dictionary
for apicall, api_description in DICT_APICALLS_DANGEROUS.items():
    DICT_APICALLS[apicall] = {'description' : api_description, 'dangerous':True, 'permission': None}

# Get all api_calls and api_permissions from the static APIcalls.txt dump
with open(APICALLS, 'r') as file_apicalls:
    for line in file_apicalls.readlines():
        (api_call, api_permission) = line.split("|") # TODO This dies if the APICalls.txt format is not call|permission\n
        api_permission = api_permission.replace('\n','')
        if api_call not in DICT_APICALLS:
            DICT_APICALLS[api_call] = {'permission': api_permission, 'dangerous':False}
        else:
            DICT_APICALLS[api_call]['permission'] = api_permission
