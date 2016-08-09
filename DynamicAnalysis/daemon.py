import time
from DynamicAnalyzer import run
import settings
import psycopg2
import sys
import os



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
        unpackPath = '{}/{}'.format(apkPath, settings.DEFAULT_NAME_DIR_UNPACK)

        if os.path.exists(unpackPath):
            print 'ERROR: Resources Directory already exists for sample in Queue [{}]. Analysis underway or already done. Abort!'.format(
                sha256)
            continue

        print '[{}] Running Analysis'.format(sha256)
        # Update the analysis status to running for this sample
        db.execute("UPDATE analyzer_queue SET status='running' WHERE id=%s" % (sampleID))
        db.execute("UPDATE analyzer_metadata SET status='running' WHERE sha256='%s'" % (sha256))
        db.connection.commit()

        try:
            os.makedirs(unpackPath)
        except os.error:
            # NOTE We don't have permissions to create the directory
            # See https://docs.python.org/2/library/os.html#os.makedirs
            print 'ERROR: Cannot create unpack directory for sample [{}]'.format(sha256)
            continue

        # Run static analysis
        print '[{}] Starting Dynamic Analyzer'.format(sha256)
        workingDir = '{}/{}'.format(settings.DEFAULT_NAME_DIR_ANALYSIS, sha256)
        run(apkFile, workingDir)

        # Todo: move files


        print '[{}] Finished Analysis'.format(sha256)
        # Set new sample status
        db.execute("DELETE FROM analyzer_queue WHERE id=%s" % sampleID)
        db.execute("UPDATE analyzer_metadata SET status='finished' WHERE sha256='%s'" % sha256)
        db.connection.commit()