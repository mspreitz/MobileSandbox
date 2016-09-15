#!/usr/bin/env python
from StaticAnalyzer import run

# Local settings in StaticAnalyzer/
import settings
import sys

import glob
import os
import psycopg2
import shutil
import time
import zipfile
import config.misc_config as misc_config


def mzip(path, src, dst):
    zf = zipfile.ZipFile("%s.zip" % (dst), "w", zipfile.ZIP_DEFLATED)
    for dirs in src:
        source = '{}/{}'.format(path,dirs)
        abs_src = os.path.abspath(source)
        for dirname, subdirs, files in os.walk(source):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = '{}/{}'.format(dirs,absname[len(abs_src) + 1:])
                zf.write(absname, arcname)
    zf.close()


def copytree(src, dst, symlinks=False, ignore=None):
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, symlinks, ignore)
        else:
            shutil.copy2(s, d)



# Connect to database
try:
    conn = psycopg2.connect("dbname='ms_db' user='ms_user' host='localhost' password='2HmUKLvf'")
except:
    print "Unable to connect to the database"
    sys.exit(1)

if not settings.BACKEND_PATH or settings.BACKEND_PATH == '':
    print 'ERROR: Please set the relative path for the Backend Data Folder'
    sys.exit(1)

if not os.path.isdir(settings.DEFAULT_NAME_DIR_ANALYSIS): os.makedirs(settings.DEFAULT_NAME_DIR_ANALYSIS)

# TODO: If we run cleandb or any db changing operation, we have to close this cursor or kill the daemon beforehand
db = conn.cursor()

running = True
while(running):
    # Get static queue elements where status is idle
    rows = None
    try: # TODO If we start more than 1 daemons, we should either use fetch_one / LIMIT 1 or somehow synchronize and fetchall once every X seconds
        col = db.execute("SELECT id, filename, sha256, path FROM analyzer_queue WHERE type='static' AND status='idle'")
        rows = db.fetchall()
    except psycopg2.ProgrammingError as pe:
        print 'ERROR', pe
        time.sleep(5)

    # No results, sleep more
    if not rows: # An empty list is returned if no results
        time.sleep(5)
        continue

    for (sampleID, filename, sha256, apkPath) in rows:
        # TODO samplesPath / apkPath
        apkPath = '{}/{}'.format(settings.BACKEND_PATH, apkPath) # Samples Directory plus APK directory structure in Backend
        apkFile = '{}/{}'.format(apkPath, settings.DEFAULT_NAME_APK) # APK in Samples Directory
        unpackPath = '{}/{}'.format(apkPath, settings.DEFAULT_NAME_DIR_UNPACK) # Unpacked Resources Directory in Samples Directory

        # If the resources directory already exists, that means we already executed the static analysis on the sample.
        # TODO Recurring analysis on updated modules don't work this way : ( - fnd some other mechanism to check on already executed analysis!
        if os.path.exists(unpackPath):
            print 'ERROR: Resources Directory already exists for sample in Queue [{}]. Analysis underway or already done. Abort!'.format(sha256)
            continue

        print '[{}] Running Analysis'.format(sha256)
        # Update the analysis status to running for this sample
        db.execute("UPDATE analyzer_queue SET status='running' WHERE id=%s" % (sampleID))
        db.execute("UPDATE analyzer_metadata SET status='running' WHERE sha256='%s'" % (sha256))
        db.connection.commit()

        # Create BACKEND direcory that contains the unpacked resources
        # TODO Maybe move this somewhere later.
        try:
            os.makedirs(unpackPath)
        except os.error:
            # NOTE We don't have permissions to create the directory
            # NOTE Or the direcytory exists already (Can not happen because we check if the unpackPath already exists and continue...)
            # See https://docs.python.org/2/library/os.html#os.makedirs
            print 'ERROR: Cannot create unpack directory for sample [{}]'.format(sha256)
            continue

        # Run static analysis
        print '[{}] Starting Static Analyzer'.format(sha256)
        workingDir = '{}/{}'.format(settings.DEFAULT_NAME_DIR_ANALYSIS, sha256)
        run(apkFile, workingDir)

        print '[{}] Packing everything to the Backend Sample Directory'.format(sha256)

        # Get Cert file
        # TODO Find out how to make a single regex
        globregex_both = '{}/{}/META-INF/*.[DR]SA'.format(workingDir, settings.DEFAULT_NAME_DIR_UNPACK)
        result = glob.glob(globregex_both)

        cFile = None
        if len(result) > 1:
            print 'Error: More than 1 certificates in the unpack Directory! Abort.'

        # Get .XXX ending: RSA / DSA / ECC
        if len(result) == 1:
            certType = result[0].split('/')[-1].split('.')[-1]
            cFile = '{}/cert.{}'.format(apkPath, certType)
            shutil.copyfile(result[0], cFile)
            print 'Wrote Certificate to {}'.format(cFile)

        # Zip decompiled source files for the user to download
        mzip(workingDir, ['src/', 'unpack/'], '{}/download'.format(apkPath))

        # Move unpack files to BACKEND UNPACK DIR
        copytree('{}/{}'.format(workingDir, 'unpack'), unpackPath) # copytree custom? TODO

        # Move Manifest to BACKEND SAMPLES DIR
        shutil.move('{}/{}'.format(workingDir, 'AndroidManifest.xml'), '{}/{}'.format(apkPath, 'AndroidManifest.xml'))

        # Create reports directory and move reports to it
        reportPath = '{}/{}'.format(apkPath, 'reports')
        if not os.path.isdir(reportPath):
            try:
                os.mkdir(reportPath)
            except os.error:
                print 'ERROR: Could not create report dir for sample [{}]!'.format(sha256)
                continue

        shutil.move('{}/{}'.format(workingDir, 'static.json'), '{}/{}'.format(reportPath, 'static.json'))
        shutil.move('{}/{}'.format(workingDir, 'static.log'), '{}/{}'.format(reportPath, 'static.log'))

        # Remove remaining analysis files
        if misc_config.ENABLE_CLEAR_OLD_FILES: shutil.rmtree(workingDir)

        print '[{}] Finished Analysis'.format(sha256)
        # Set new sample status
        db.execute("DELETE FROM analyzer_queue WHERE id=%s" % sampleID)
        db.execute("UPDATE analyzer_metadata SET status='finished' WHERE sha256='%s'" % sha256)
        db.connection.commit()
