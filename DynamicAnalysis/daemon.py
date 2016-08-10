import shutil
import time
from DynamicAnalyzer import run
import settings
import psycopg2
import sys
import os


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

db = conn.cursor()

running = True

while(running):
    rows = None

    try:
        col = db.execute("SELECT id, fileName, sha256, path FROM analyzer_queue WHERE type='dynamic' AND status='idle'")
        rows = db.fetchall()
    except psycopg2.ProgrammingError as pe:
        print 'ERROR', pe
        time.sleep(5)

    # No results, sleep more
    if not rows: # An empty list is returned if no results
        time.sleep(5)
        continue

    for (sampleID, filename, sha256, apkPath) in rows:
        apkPath = '{}/{}'.format(settings.BACKEND_PATH, apkPath)
        apkFile = '{}/{}'.format(apkPath, settings.DEFAULT_NAME_APK)

        print '[{}] Running Analysis'.format(sha256)
        # Update the analysis status to running for this sample
        db.execute("UPDATE analyzer_queue SET status='running' WHERE id=%s" % (sampleID))
        db.execute("UPDATE analyzer_metadata SET status='running' WHERE sha256='%s'" % (sha256))
        db.connection.commit()

        # Run static analysis
        print '[{}] Starting Dynamic Analyzer'.format(sha256)
        workingDir = '{}/{}'.format(settings.DEFAULT_NAME_DIR_ANALYSIS, sha256)
        run(apkFile, workingDir)

        # Move JSON-Report to backend
        shutil.move('{}/{}'.format(workingDir, 'dynamic.json'), '{}/{}'.format(apkPath, 'dynamic.json'))

        # Move screenshots to backend
        copytree('{}/{}'.format(workingDir, settings.SCREENSHOT_DIR), apkPath)

        # Move apkfiles to backend
        copytree('{}/{}'.format(workingDir, settings.APK_FILES), apkPath)

        # Remove temporary files
        shutil.rmtree(workingDir)

        print '[{}] Finished Analysis'.format(sha256)
        # Set new sample status
        db.execute("DELETE FROM analyzer_queue WHERE id=%s" % sampleID)
        db.execute("UPDATE analyzer_metadata SET status='finished' WHERE sha256='%s'" % sha256)
        db.connection.commit()