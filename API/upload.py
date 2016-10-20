#!/usr/bin/env python
from requests.auth import HTTPBasicAuth
from os import listdir
import requests
import re
import sys
import time

if len(sys.argv) != 2:
    sys.stderr.write('Usage: {} <sample-directory>\n'.format(sys.argv[0]))
    sys.exit(1)

# Parse credentials
with open('credentials.txt', 'r') as f:
    fdata = f.readlines()

# Setup Authentification for upload
data = {}
for line in fdata:
    line = line.replace('\n', '').split('=')
    if line[0]=='MAIL':
        data['email'] = line[1]
    elif line[0]=='PASS':
        data['password'] = line[1]
if len(data) != 2:
    sys.stderr.write('Parsing failed for credentials file\n')
    sys.exit(1)

# Setup the connection including session and csrftoken
HOST, PORT = '131.188.31.150', 55555
url = 'http://{}:{}/analyzer'.format(HOST,PORT)
headers = {}
client = requests.session()
r = client.get('{}/'.format(url), data=data)

headers['X-CSRFToken'] = client.cookies['csrftoken']
r = client.post('{}/userLogin/'.format(url), data=data, cookies=client.cookies, headers=headers)

time_analysis_total = 0

# TODO: MultiValueDict should contain one file named 'attachments' with multiple InMemoryUploadedFiles - doesn't work as one post yet
for f in listdir(sys.argv[1]):
    sys.stdout.write('{} ... '.format(f))
    f_abs = '{}/{}'.format(sys.argv[1], f)
    files = {}
    with open(f_abs, 'rb') as tmp:
        files['attachments'] = tmp.read()

    headers['X-CSRFToken'] = client.cookies['csrftoken']
    time_analysis_start = time.time()
    r = client.post('{}/home/'.format(url), data=data, files=files, cookies=client.cookies, headers=headers)
    time_analysis_end = time.time()
    time_analysis_diff = time_analysis_end - time_analysis_start
    sys.stdout.write('{}\n'.format(r.status_code))
    sys.stdout.write('Time taken (seconds): {}\n'.format(time_analysis_diff))
    time_analysis_total += time_analysis_diff
    sys.stdout.flush()
sys.stdout.write('Time taken in total (seconds): {}\n'.format(time_analysis_total))
