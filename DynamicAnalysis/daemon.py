#!/usr/bin/env python
import shutil
import subprocess
import time
from DynamicAnalyzer import run
import settings
import psycopg2
import sys
import os
import misc_config
import traceback
import smtplib
from email.mime.text import MIMEText


if misc_config.ENABLE_SENTRY_LOGGING:
    from raven import Client
    client = Client('http://46a1768b67214ab3be829c0de0b9b96f:60acd07481a449c6a44196e166a5d613@localhost:9000/2')


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
    conn = psycopg2.connect(dbname='ms_db', user='ms_user', password='2HmUKLvf')
except:
    if misc_config.ENABLE_SENTRY_LOGGING:
        client.captureException()
    traceback.print_exc()
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
        if misc_config.ENABLE_SENTRY_LOGGING:
            client.captureException()
        print 'ERROR', pe
        time.sleep(5)

    # No results, sleep more
    if not rows: # An empty list is returned if no results
        time.sleep(5)
        continue

    for (sampleID, filename, sha256, apkPath) in rows:
        print sampleID
        apkPath = '{}/{}'.format(settings.BACKEND_PATH, apkPath)
        apkFile = '{}/{}'.format(apkPath, settings.DEFAULT_NAME_APK)

        reportDir = '{}/{}'.format(apkPath, settings.REPORT_DIR)
        if not os.path.isdir(reportDir): os.makedirs(reportDir)

        print '[{}] Running Analysis'.format(sha256)
        # Update the analysis status to running for this sample
        db.execute("UPDATE analyzer_queue SET status='running' WHERE id=%s" % (sampleID))
        db.execute("UPDATE analyzer_metadata SET status='running' WHERE sha256='%s'" % (sha256))
        db.connection.commit()

        # Run dynamic analysis
        print '[{}] Starting Dynamic Analyzer'.format(sha256)
        workingDir = '{}/{}'.format(settings.DEFAULT_NAME_DIR_ANALYSIS, sha256)

        status = run(apkFile, workingDir, sha256)

        # If VirtualBox gets stuck kill it and try again
        for i in range(settings.RETRY):
            if status == "TimedOut":
                print "Analysis failed for the %s time" % i

                command = "/usr/bin/ps waux|awk '/--startvm/{print $2}'"
                command2 = "/usr/bin/ps waux|awk '/cuckoo.py/{print $2}'"
                output = subprocess.check_output(command, shell=True)
                output2 = subprocess.check_output(command2, shell=True)

                pid = output + output2
                pid = output.split("\n")

                for i in pid:
                    if i != "":
                        subprocess.call(["kill", pid])

                status = run(apkFile, workingDir, sha256)
            else:
                continue


        # Move JSON-Report to backend
        shutil.move('{}/{}'.format(workingDir, 'dynamic.json'), '{}/{}'.format(reportDir, 'dynamic.json'))

        # Move screenshots to backend
        screenshotDir = '{}/{}'.format(apkPath, settings.SCREENSHOT_DIR)
        print 'Screenshot-dir: '+screenshotDir
        if not os.path.isdir(screenshotDir): os.makedirs(screenshotDir)
        copytree('{}/{}'.format(workingDir, settings.SCREENSHOT_DIR), screenshotDir)

        # Move apkfiles to backend
        filesDir = '{}/{}'.format(apkPath, settings.APK_FILES)
        if not os.path.isdir(filesDir): os.makedirs(filesDir)
        copytree('{}/{}'.format(workingDir, settings.APK_FILES), filesDir)

        dir_databases = '{}/{}'.format(workingDir, settings.DATABASES_DIR)
        if os.path.isdir(dir_databases): copytree(dir_databases, filesDir)

        # Remove temporary files
        shutil.rmtree(workingDir)

        print '[{}] Finished Analysis'.format(sha256)
        # Set new sample status
        db.execute("DELETE FROM analyzer_queue WHERE id=%s" % sampleID)
        db.execute("UPDATE analyzer_metadata SET status='finished' WHERE sha256='%s'" % sha256)
        db.connection.commit()


        # Send notification to the user
        # uncommented for now
        #db.execute("SELECT username FROM analyzer_metadata WHERE sha256='%s'" % sha256)
        #email = db.fetchone()[0]
        #
        #if email != "":
        #    db.execute("SELECT first_name FROM auth_user WHERE username = %s" % email)
        #    username = db.fetchone()[0]
        #
        #    msg = """From: MobileSandbox <%s>
        #        To: <%s>
        #        Subject: Analysis is finished!
        #
        #        Dear %s, \n
        #        the analysis of your submitted sample is finished now. In order to view the report\n
        #        please visit the following link.\n\n
        #        %s%s\n\n
        #        Best Regards\n
        #        MobileSandbox Team
        #        """ % (settings.SENDERS_MAIL, email, username, settings.BASE_URL, sha256)
        #
        #    try:
        #        smtpObj = smtplib.SMTP('localhost')
        #        smtpObj.sendmail("%s", email, msg) % settings.SENDERS_MAIL
        #        print "Successfully sent email"
        #    except smtplib.SMTPException:
        #        print "Error: unable to send email"
