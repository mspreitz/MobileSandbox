import hashlib
import os
import shutil
import textwrap

DATA_DIR = 'tmp/'
DIR_DEPTH = 8
sha256 = hashlib.sha256()
sha1 = hashlib.sha1()


def createSHA1(apkFile):
    try:
        return hashlib.sha1(open(apkFile, 'rb').read()).hexdigest()
    except:
        raise IOError('File not found')


def createSHA256(apkFile):
    try:
        return hashlib.sha256(open(apkFile, 'rb').read()).hexdigest()
    except:
        raise IOError('File not found')


def getPath(apkFile):
    chunks = textwrap.wrap(createSHA256(apkFile), DIR_DEPTH)
    path = os.path.join(*chunks)+'/'
    return path


def getFilePath(apkFile):
    path = getPath(apkFile)
    return path+createSHA1(apkFile)+".apk"


def createPath(apkFile):
    path = getPath(apkFile)
    if os.path.isfile(apkFile):
        if not os.path.exists(DATA_DIR+path):
            os.makedirs(DATA_DIR+path)
        filename = DATA_DIR+getFilePath(apkFile)
        print apkFile
        shutil.move(apkFile, filename)
    return filename


print createPath(DATA_DIR+"33.apk")