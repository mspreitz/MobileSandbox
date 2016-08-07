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
from django.views.generic.edit import FormView

from classifier import classify
from .forms import UploadForm, UploadFormMulti
from .models import FileUpload, Queue, Metadata, ClassifiedApp
from datastructure import *
from django.db.models import Q

from mhash import * # TODO: Move that and the utils/mhash from the StaticAnalyzer to a single file.


# Constants
TMP_PATH = 'analyzer/tmp/'
BASE_URL = 'http://localhost:8000/analyzer/show/?report='

# Views

def index(request):
    return render_to_response("base.html", context_instance=RequestContext(request))


def registration(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        passwd = request.POST['password']

        match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)

        # Check for empty input fields
        if match is None:
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

    check = {}
    check.update(csrf(request))
    form = UploadFormMulti()
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
    status = []

    for dat in result:
        if len(filename) > 0:
            sha1.append(dat.sha1)
            if not dat.status == 'finished':
                sha256.append("analyzing")
            else:
                sha256.append(dat.sha256)
            filename.append(dat.filename)
            status.append(dat.status)
        else:
            sha1 = [dat.sha1]
            if not dat.status == 'finished':
                sha256 = ['analyzing']
            else:
                sha256 = [dat.sha256]

            filename = [dat.filename]
            status = [dat.status]
    data['Filename'] = filename
    data['SHA1'] = sha1
    data['Status'] = status
    data['Report'] = sha256

    return render_to_response('history.html', {"data": data})

def dataIsAPK(data):
    magic = '\x50\x4b\x03\x04' # ZIP Magic
    if data[:4] != magic: return False
    # TODO classes.dex, AndroidManifest.xml, resources.arsc
    return True


# Upload file and do sanity check
def uploadFile(request, magic, anonymous, username): # TODO Use default values and set those parameters at the last positions e.g. username, anonymous=True
    form = UploadFormMulti(request.POST, request.FILES)
    if not form.is_valid():
        return HttpResponse('The form was not valid!')

    uploadedFiles = {}
    for sentFile in request.FILES.getlist('attachments'): uploadedFiles[sentFile.name] = {}


    # NOTE: sentFiles are InMemoryUploadedFiles - Binary blob already available - no need for open!
    for sentFile in request.FILES.getlist('attachments'):
        data = sentFile.read()
        if not data:
            uploadedFiles[sentFile.name]['error'] = 'Could not read APK file!'
            continue

        if not dataIsAPK(data):
            uploadedFiles[sentFile.name]['error'] = 'This file is not an APK file!'
            continue

        # NOTE: We only hash once -  we don't want to hash later again for the static analyzer - performance ! :) TODO
        appInfos = hash_all(data)

        # TODO Don't we want to abort if the file has already been uploaded?
        # TODO I got several <apk>_tmpstring.apk uploaded files. We can check if they already exist or are in the process by looking up the hash and abort if necessary
        apkFile = FileUpload(file=sentFile)
        apkFile.save()

        # Temporary APK file in location
        # TODO Somehow test for accidentally rmtree('/') etc
        if not TMP_PATH or TMP_PATH == '':
            print 'Fatal Failure. Abort!'
            sys.exit(1)

        apkFile = '{}/{}'.format(TMP_PATH,sentFile.name) # TODO Yeah this is a bad idea - can be set arbitrary. Not good :).
        filePath = getFilePath(apkFile)
        fileName = "{}.apk".format(appInfos['sha1'].lower()) # TODO Why sha1? :)

        # If the 
        apkFile_destination = '{}/{}'.format(TMP_PATH, filePath)

        # If the directory structure with saved APKs and Analyzer result does already exist
        # then tell the user that the sample is already in process / uploaded
        if os.path.isfile(apkFile_destination):
            queue = Queue.objects.get(sha256=appInfos['sha256'])

            if queue.status == 'idle' or queue.status == 'running':
                uploadedFiles[sentFile.name]['error'] = 'This sample has already been submitted. The analysis is currently running.'
                continue
            uploadedFiles[sentFile.name]['report'] = '/analyzer/show/?report={}'.format(appInfos['sha256']) # Report to redirect
            continue

        # TODO We could use the sha1APK inside this directory or reply with the results. And delete the uploaded APK (we dont need a tmp anyway)
        # TODO: remove temporary file (or don't use a temp file anyway)

        # Create the datastructure, move the file to the destination directory
        fn = createPath(apkFile) # fn == apkFile_destination
        # TODO Too many cooks :)
        #print apkFile_destination == fn, fn
        #print fileName == appInfos['sha1']+'.apk', fileName
        #print apkFile # Temporary uploaded file
        #print filePath # full path - without TMP_PATH k.
        apkPath = '{}'.format(getPathFromSHA256(appInfos['sha256'].lower()))
        # Put file in Queue for analysis
        Queue.objects.create(
                fileName=fileName, # TODO This should be the sha1 + .apk right?
                status='idle',
                sha256=appInfos['sha256'].lower(),
                path=apkPath, # TODO Path without sha1 name AND tmp_path... so confusing ! :)
                type='static'
        )

        # Put Metadata into Database
        Metadata.objects.create(
                filename=sentFile.name, # TODO Which names are which?
                status='idle',
                sha256=appInfos['sha256'].lower(),
                sha1=appInfos['sha1'].lower(),
                md5=appInfos['md5'].lower(),
                username=request.user.username
        )

        uploadedFiles[sentFile.name]['uploaded'] = appInfos['sha256'].lower()

    # Return redirect link for every successful report - or redirect to the report page
    # For every error in the uploadedFiles, print a table with apkname and error
    templatedict = {'url' : BASE_URL, 'uploaded_files': uploadedFiles }
    template = 'anonUploadSuccess.html'
    if not anonymous: template = 'uploadSuccess.html'
    return render_to_response(template, templatedict)


def showQueue(request):
    try:
        queue = Queue.objects.filter(Q(status='idle') | Q(status='running'))
    except:
        queue = None

    data = []
    if queue is not None:
        count = len(queue)
        for i in range(count-1, count-11, -1):
            if i < 0:
                continue
            tmp = [queue[i].sha256, queue[i].type, queue[i].status]
            data.append(tmp)
    else:
        return HttpResponse("Queue is empty!")

    return render_to_response("queue.html", {"data": data}, context_instance=RequestContext(request))


def showReport(request):
    token = request.GET.get('report')
    # Check for valid sha256 hash
    if validateHash(token, 'sha256'):
        result = loadResults(token)

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
    if res is None:
        return None

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
