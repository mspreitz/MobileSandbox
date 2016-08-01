import json
import re
from collections import OrderedDict

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.core.context_processors import csrf
from django.shortcuts import render_to_response, render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.template import RequestContext

from classifier import classify
from .forms import UploadForm
from .models import FileUpload, Queue, Metadata, ClassifiedApp
from datastructure import *


# Constants
TMP_PATH = 'analyzer/tmp/'
BASE_URL = 'http://localhost:8000/analyzer/show/?report='

# Views

def index(request):
    return render_to_response("base.html")


def registration(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        passwd = request.POST['password']

        match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)

        # Check for empty input fields
        if match == None:
            message = 'Please enter a valid email address!'
            return render_to_response('error.html', {'message': message})
        if username == "":
            message = 'Please provide an username!'
            return render_to_response('error.html', {'message': message})
        if passwd == "":
            message = 'Please provide a password!'
            return render_to_response('error.html', {'message': message})

        try:
            user = User.objects.get(username=username)
        except:
            user = None

        if user is None:
            User.objects.create_user(username=email, password=passwd, first_name=username)
            return render_to_response("registerSuccess.html")
        else:
            message = 'Email address already in use! %s' % user.username
            return render_to_response('error.html', {'message': message})
    else:
        check = {}
        check.update(csrf(request))
        return render_to_response("register.html", check)


def userLogout(request):
    logout(request)
    return redirect("/analyzer/")


def loginUser(request):
    check = {}
    check.update(csrf(request))
    if request.method == 'POST':
        email = request.POST['email']
        passwd = request.POST['password']
        try:
            user = User.objects.get(username=email)
        except:
            user = None

        if user is not None:
            auth_user = authenticate(username=email, password=passwd)
            #if auth_user.is_active:
            login(request, auth_user)
            # Redirect to member area
            return redirect('/analyzer/home')
            #return HttpResponse("Login successful! Welcome %s" %user.first_name)
            #else:
            #    message = 'The user %s is disabled.' % user.first_name
            #    return render_to_response('error.html', {'message': message})
        else:
            # Redirect to error page
            message = 'Your email and password do not match'
            return render_to_response('error.html', {'message': message})
    else:
        check = {}
        check.update(csrf(request))
        return render_to_response("login.html", check)


def anonUpload(request):
    magic = '\x50\x4b\x03\x04'
    anonymous = True

    if request.method == 'POST':
        return uploadFile(request, magic, anonymous, 'Anonymous')
    else:
        check = {}
        check.update(csrf(request))
        form = UploadForm()
        docs = FileUpload.objects.all()
        return render_to_response('anonUpload.html', {'documents': docs, 'form': form},
                                  context_instance=RequestContext(request))


@login_required(login_url='/analyzer/userLogin')
def userHome(request):
    magic = '\x50\x4b\x03\x04'
    anonymous=False

    if request.method == 'POST':
        return uploadFile(request, magic, anonymous, request.user.first_name)
    else:
        check = {}
        check.update(csrf(request))
        form = UploadForm()
        docs = FileUpload.objects.all()
        return render_to_response('home.html', {'documents': docs, 'form': form, 'full_name': request.user.first_name},
                                  context_instance=RequestContext(request))


@login_required(login_url='/analyzer/userLogin')
def showHistory(request):
    username = request.user.username
    result = Metadata.objects.filter(username=username)
    data = OrderedDict()
    sha1 = []
    sha256 = []
    filename = []
    #Todo: put analyzer status into metadata
    status = []

    for dat in result:
        if len(filename) > 0:
            sha1.append(dat.sha1)
            sha256.append(dat.sha256)
            filename.append(dat.filename)
            status.append(dat.status)
        else:
            sha1 = [dat.sha1]
            sha256 = [dat.sha256]
            filename = [dat.filename]
            status = [dat.status]
    data['Filename'] = filename
    data['SHA1'] = sha1
    data['Status'] = status
    data['Report'] = sha256

    return render_to_response('history.html', {"data": data})



# Upload file and do sanity check
def uploadFile(request, magic, anonymous, username):
    sentFile = request.FILES['file']
    filename = sentFile.name
    form = UploadForm(request.POST, request.FILES)
    submitted = False

    if form.is_valid():
        file = FileUpload(file=sentFile)
        file.save()

        # Check if file is a valid apk
        with open(TMP_PATH + filename) as f:
            fileStart = f.read(len(magic))
            if fileStart.startswith(magic):
                apkFile = TMP_PATH + filename
                path = getPath(apkFile)
                filePath = getFilePath(apkFile)
                fileName = createSHA1(apkFile) + ".apk"
                md5 = createMD5(apkFile)
                sha1 = createSHA1(apkFile)
                sha256 = createSHA256(apkFile)
                # Todo: check for dex file
                # Todo: remove temporary file

                if not os.path.isfile(TMP_PATH+filePath):
                    # createPath() already renames the file and moves
                    # it to the target directory
                    createPath(apkFile)

                    # Put file in Queue for analysis
                    Queue.objects.create(sha256=sha256, path=path, fileName=fileName, status='idle', type='static')
                    # Queue.objects.create(sha256=sha256, path=path, filename=fileName, status='idle', type='dynamic')

                    # Put Metadata into Database
                    Metadata.objects.create(filename=filename,md5=md5, sha1=sha1, sha256=sha256, username=request.user.username, status='idle')
                else:
                    queue = Queue.objects.get(sha256=sha256)

                    if queue.status == 'idle' or queue.status == 'running':
                        return HttpResponse('This sample has already been submitted. The analysis is currently running.')
                    else:
                        return redirect('/analyzer/show/?report='+sha256)
                f.close()

                if anonymous:
                    return render_to_response("anonUploadSuccess.html", {'url': BASE_URL, 'hash': sha256})
                else:
                    return render_to_response("uploadSuccess.html", {'url': BASE_URL, 'hash': sha256})

            else:
                os.remove(TMP_PATH + filename)
                return HttpResponse('This file is not an apk file!')
    else:
        return HttpResponse('not valid')


def showReport(request):
    token = request.GET.get('report')
    # Check for valid sha256 hash
    if validateHash(token, 'sha256'):
        result = loadResults(token)
        # Todo: error handling for not finished reports

        if result is None:
            return render_to_response('error.html', {'message': 'The report for this sample does not exist (yet?)'})

        sampleId = Metadata.objects.get(sha256=token)
        cSampleId = None
        try:
            cSampleId = ClassifiedApp.objects.get(sample_id=sampleId.id)
        except:
            path = getPathFromSHA256(token)
            logfile = TMP_PATH + path + getResultFolder(TMP_PATH + path) + '/' + 'static.json'
            classify(logfile, sampleId.id)
        if cSampleId is None:
            cSampleId = ClassifiedApp.objects.get(sample_id=sampleId.id)

        if cSampleId.malicious:
            malicious='Yes!'
        else:
            malicious='No'

        return render_to_response("report.html", {'data': result, 'malicious': malicious})
    else:
        return render_to_response('error.html', {'message': 'This is not SHA256!'})


def search(request):
    MD5Length = 32
    SHA1Length = 40
    SHA256Length = 64

    if request.method == 'GET':
        req = request.GET['q']

        # Search for MD5
        if len(req) == MD5Length:
            if validateHash(req, 'md5'):
                try:
                    result = Metadata.objects.get(md5=req)
                except:
                    result = None

                if result is not None:
                    sha256 = result.sha256
                    status = result.status
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256})

        # Search for SHA1
        elif len(req) == SHA1Length:
            if validateHash(req,'sha1'):
                try:
                    result = Metadata.objects.get(sha1=req)
                except:
                    result = None

                if result is not None:
                    sha256 = result.sha256
                    status = result.status
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256})

        # Search for SHA256
        elif len(req) == SHA256Length:
            if validateHash(req,'sha256'):
                try:
                    result = Metadata.objects.get(sha256=req)
                except:
                    result = None

                if result is not None:
                    sha256 = result.sha256
                    status = result.status
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256})
        else:
            return HttpResponse('This is not a valid input!')



def loadResults(sha256):
    path = TMP_PATH+getPathFromSHA256(sha256)
    # Get result folder
    res = getResultFolder(path)
    if not os.path.isdir(path+res):
        return None

    if res is not None:
        with open(path+res+'/static.json') as f:
            data = json.load(f)
    else:
        return None
    return data


def getResultFolder(path):
    try:
        result = os.walk(path).next()[1][0]
    except:
        return None

    return result


def validateHash(hash, type):
    result = None
    if type == 'sha256':
        try:
            result = re.match(r'^\w{64}$', hash)
        except RuntimeError:
            print 'This is not sha256'
    elif type == 'sha1':
        try:
            result = re.match(r'^\w{40}$', hash)
        except RuntimeError:
            print 'This is not sha1'
    elif type == 'md5':
        try:
            result = re.match(r'^\w{32}$', hash)
        except RuntimeError:
            print 'This is not md5'

    return result is not None
