CUCKOO_STORAGE = '/var/www/html/DynamicAnalysis/cuckoo/storage/analyses/'
CUCKOO_SUBMIT = 'cuckoo/utils/submit.py'
CUCKOO_SERVER = 'cuckoo/cuckoo.py'
PLIST_FILE = 'processlist.txt'
PLIST_NEW = 'processlistNew.txt'
NETSTAT_LIST = 'netstat.txt'
NETSTAT_NEW = 'netstatNew.txt'
SBOX_FOLDER_LIST = 'sboxlist.txt'
INSTALLED_APPS = 'installed_apps.txt'

VBOX_IP = '192.168.56.1'
SNAP_IP = '192.168.56.10'
VBOX_NETM = '255.255.255.0'
VBOX_DEV = 'vboxnet0'
WORKINGDIR = 'test/'
PATH_MODULE_MSNEO = '../Neo4J/'
SCREENSHOT_DIR = 'screenshots'
APK_FILES = 'apkfiles'
REPORT_DIR = 'reports'
DATABASES_DIR = 'databases'

TIMEOUT = 4000
RETRY = 3

BASE_URL = 'https://mobilesandbox.org/show/?report='
SENDERS_MAIL = 'no-reply@mobilesandbox.org'

import os
cwd=os.path.dirname(os.path.realpath(__file__))
PATH_MODULE_CONFIG = '{}/../config/'.format(cwd)
BACKEND_PATH = ''
#BACKEND_PATH = '{}/../Backend/'.format(cwd)
PATH_SAMPLES = 'samples/'
DEFAULT_NAME_APK = 'sample.apk'
DEFAULT_NAME_DIR_UNPACK = 'unpack'
DEFAULT_NAME_DIR_ANALYSIS = 'analysis'
