import glob
import os
import shutil
import time
import zipfile
from pymongo import MongoClient
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
client = MongoClient('localhost:27017')
db = client.ms_db

collection = db.analyzer_queue
meta = db.analyzer_metadata

running = True


while(running):
    col = collection.find()
    if col.count() <= 0:
        time.sleep(5)
        continue

    print "found collection"
    for data in col:

        if not data['status'] == 'finished' and not data['status'] == 'running':

            path = settings.BACKEND_PATH+data['path']
            type = data['type']
            fname = data['fileName']
            sample = path+fname
            resDirName = os.path.splitext(fname)[0]
            tmpPath = settings.SOURCELOCATION+resDirName+'/'
            sampleID = data['_id']
            sha256 = data['sha256']

            # Set analysis status to running
            collection.update_one({"_id": sampleID}, {
                "$set": {
                    "status": "running"
                }
            })

            meta.update_one({"sha256": sha256}, {
                "$set": {
                    "status": "running"
                }
            })
            print 'running'
            if not os.path.exists(tmpPath):
                os.makedirs(tmpPath)
                # Run static analysis
                run(sample, tmpPath)
                #time.sleep(2)


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
                collection.update_one({"_id": sampleID}, {
                    "$set": {
                        "status": "finished"}
                })

                meta.update_one({"sha256": sha256}, {
                    "$set": {
                        "status": "finished"}
                })