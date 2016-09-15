CUCKOO_STORAGE = 'cuckoo/storage/analyses/'
CUCKOO_SUBMIT = 'cuckoo/utils/submit.py'
CUCKOO_SERVER = 'cuckoo/cuckoo.py'
PLIST_FILE = 'processlist.txt'
PLIST_NEW = 'processlistNew.txt'
NETSTAT_LIST = 'netstat.txt'
NETSTAT_NEW = 'netstatNew.txt'
INSTALLED_APPS = 'installed_apps.txt'
#DB_LIST = 'database.txt'
#DB_LIST_NEW = 'databaseNEW.txt'
#FILES = 'check.chk'
#FILES_LIST = 'checkNew.txt'
SBOX_FOLDER_LIST = 'sboxlist.txt'
VBOX_IP = '192.168.56.1'
VBOX_NETM = '255.255.255.0'
VBOX_DEV = 'vboxnet0'
WORKINGDIR = 'test/'
PATH_MODULE_MSNEO = '../Neo4J/'

import os
cwd=os.path.dirname(os.path.realpath(__file__))
PATH_MODULE_CONFIG = '{}/config/'.format(cwd)
print PATH_MODULE_CONFIG