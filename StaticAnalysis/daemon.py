import glob
import os
import shutil
import time
import zipfile
from string import split

import psycopg2
from StaticAnalyzer import run
import settings


def mzip(path, src, dst):
    zf = zipfile.ZipFile("%s.zip" % (dst), "w", zipfile.ZIP_DEFLATED)
    for dirs in src:
        source = path + dirs
        abs_src = os.path.abspath(source)
        for dirname, subdirs, files in os.walk(source):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = dirs+absname[len(abs_src) + 1:]
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

db = conn.cursor()

running = True


while(running):
    rows = ''
    try:
        col = db.execute("SELECT * FROM analyzer_queue")
        rows = db.fetchall()
    except:
        time.sleep(5)
    if len(rows) <= 0:
        time.sleep(5)
        continue

    time.sleep(3)
    for data in rows:

        if data[4] == 'idle':

            path = settings.BACKEND_PATH+data[2]
            type = data[5]
            fname = data[3]
            sample = path+fname
            resDirName = os.path.splitext(fname)[0]
            tmpPath = settings.SOURCELOCATION+resDirName+'/'
            sampleID = data[0]
            sha256 = data[1]

            if not os.path.exists(tmpPath):
                # Set analysis status to running
                db.execute("UPDATE analyzer_queue SET status='running' WHERE id=%s" % (sampleID))
                db.execute("UPDATE analyzer_metadata SET status='running' WHERE sha256='%s'" % (sha256))
                db.connection.commit()

                os.makedirs(tmpPath)
                # Run static analysis
                run(sample, tmpPath)

                # Get Cert file
                if glob.glob(tmpPath+"unpack/META-INF/*.RSA"):
                    cFile = glob.glob(tmpPath + "unpack/META-INF/*.RSA")
                    shutil.copyfile(cFile[0], tmpPath + 'cert.RSA')
                    print 'wrote cert to ' + tmpPath + 'cert.RSA'
                elif glob.glob(tmpPath+"unpack/META-INF/*.DSA"):
                    cFile = glob.glob(tmpPath+"unpack/META-INF/*.DSA")
                    shutil.copyfile(cFile, tmpPath + 'cert.DSA')
                    print 'wrote cert to ' + tmpPath + 'cert.DSA'
                else:
                    cFile = None

                # Zip decompiled source files for the user to download
                mzip(tmpPath, ['src/', 'unpack/'], tmpPath+'source')

                # Remove source and unpack folder and temp files
                shutil.rmtree(tmpPath+'src')
                shutil.rmtree(tmpPath+'unpack')
                os.remove(tmpPath+'Dump.txt')

                # Move files to the backend
                if not os.path.exists(path+resDirName):
                    os.mkdir(path+resDirName)
                copytree(tmpPath, path+resDirName)


                # Copy cert file to the backend
                if cFile is not None:
                    if os.path.exists(tmpPath + 'cert.RSA'):
                        shutil.move(tmpPath + 'cert.RSA', path + resDirName + 'cert.RSA')
                    elif os.path.exists(tmpPath + 'cert.DSA'):
                        shutil.move(tmpPath + 'cert.DSA', path + resDirName + 'cert.DSA')
                # Clean temp directory
                shutil.rmtree(tmpPath)

                # Set new sample status
                db.execute("UPDATE analyzer_queue SET status='finished' WHERE id=%s" % sampleID)
                db.execute("UPDATE analyzer_metadata SET status='finished' WHERE sha256='%s'" % sha256)
                db.connection.commit()
