import json
import re
from collections import OrderedDict

import sys
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
from django.conf import settings

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
    if request.method == 'POST':
        return uploadFile(request, 'Anonymous')

    # TODO What is this check for? Where is it used?
    check = {}
    check.update(csrf(request))

    template = 'anonUpload.html'
    templatedict = {}
    templatedict['documents'] = FileUpload.objects.all()
    templatedict['form'] = UploadFormMulti()
    context_instance = RequestContext(request)
    return render_to_response(template, templatedict, context_instance=context_instance)


@login_required(login_url='/analyzer/userLogin')
def userHome(request):
    if request.method == 'POST':
        return uploadFile(request, request.user.first_name, anonymous=False)

    # TODO What is this check for? Where is it used?
    check = {}
    check.update(csrf(request))

    template = 'home.html'
    templatedict = {}
    templatedict['documents'] = FileUpload.objects.all()
    templatedict['form'] = UploadFormMulti()
    templatedict['full_name'] = request.user.first_name
    context_instance = RequestContext(request)
    return render_to_response(template, templatedict, context_instance=context_instance)


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
def uploadFile(request, username, anonymous=True): # TODO Use default values and set those parameters at the last positions e.g. username, anonymous=True
    # TODO Somehow test for accidentally rmtree('/') etc
    if not settings.PATH_SAMPLES or settings.PATH_SAMPLES == '':
        print 'Fatal Failure. Abort!'
        sys.exit(1)

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

        # Hash sha256 first and test if it already exists
        appInfos = {}
        appInfos['sha256'] = hash_sha256(data)

        # Generate datastructure path for APK
        splitDir = getPathFromSHA256(appInfos['sha256'])
        apkDir = '{}/{}'.format(settings.PATH_SAMPLES, splitDir)

        # If the APK has already been updated
        # meaning the directory structure with saved APKs and Analyzer result does already exist
        # then tell the user that the sample is already in process / uploaded
        if os.path.isdir(apkDir):
            queue = Queue.objects.get(sha256=appInfos['sha256'])

            if queue.status == 'idle' or queue.status == 'running':
                uploadedFiles[sentFile.name]['error'] = 'This sample has already been submitted. The analysis is currently running.'
                continue
            uploadedFiles[sentFile.name]['report'] = '/analyzer/show/?report={}'.format(appInfos['sha256']) # Report to redirect
            continue

        # Otherwise, generate the directory structure
        try:
            os.makedirs(apkDir)
        except os.error:
            # NOTE We don't have permissions to create the directory
            # NOTE Or the direcytory exists already
            # See https://docs.python.org/2/library/os.html#os.makedirs
            uploadedFiles[sentFile.name]['error'] = 'An internal server error occurred.'
            continue

        # Put file in Queue for analysis
        Queue.objects.create(
                filename = sentFile.name,
                status='idle',
                sha256=appInfos['sha256'],
                path=apkDir,
                type='static'
        )

        Queue.objects.create(
            filename=sentFile.name,
            status='idle',
            sha256=appInfos['sha256'],
            path=apkDir,
            type='dynamic'
        )

        # NOTE: We only hash once -  we don't want to hash later again for the static analyzer - performance ! :)
        # TODO Read the hashes from Metadata or Queue and never hash again! Do once, reuse often principle
        # Generate other hashes
        appInfos['md5'] = hash_md5(data)
        appInfos['sha1'] = hash_sha1(data)

        # Put Metadata into Database
        Metadata.objects.create(
                filename=sentFile.name,
                status='idle',
                sha256=appInfos['sha256'],
                sha1=appInfos['sha1'],
                md5=appInfos['md5'],
                username=request.user.username
        )

        # Save the APK to the generated directory
        apkFile = '{}/sample.apk'.format(apkDir)
        with open(apkFile, 'wb') as f: f.write(data)

        uploadedFiles[sentFile.name]['uploaded'] = appInfos['sha256']

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
    sha256 = request.GET.get('report')
    type = request.GET.get('type')

    if not sha256: return HttpResponse('Did not specify sha256 GET parameter!')

    # Check for valid sha256 hash
    if not validateHash(sha256, 'sha256'):
        return render_to_response('error.html', {'message': 'This is not SHA256!'}) # This is Sparta!

    reports = loadResults(sha256)

    if reports is None:
        return render_to_response('error.html', {'message': 'The report for this sample does not exist (yet?)'})

    (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots) = reports

    meta = Metadata.objects.get(sha256=sha256)

    classifiedapp = None
    try:
        classfiedapp = ClassifiedApp.objects.get(sample_id=meta.id)
    except:
        classify(file_report_static, meta.id)

    if classifiedapp is None:
        classifiedapp = ClassifiedApp.objects.get(sample_id=meta.id)

    template = 'report.html'
    templatedict = {}
    templatedict['malicious'] = classifiedapp.malicious
    templatedict['jsondata_static'] = jsondata_static
    templatedict['jsondata_dynamic'] = jsondata_dynamic
    templatedict['screenshots'] = screenshots
    templatedict['sha256'] = sha256
    templatedict['type'] = type

    return render_to_response(template, templatedict)


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
    path_apk            = '{}/{}'.format(settings.PATH_SAMPLES,getPathFromSHA256(sha256))
    path_reports        = '{}/{}'.format(path_apk, settings.DEFAULT_NAME_DIR_REPORTS)
    path_screenshots    = '{}/{}'.format(path_apk, settings.DEFAULT_NAME_SCREENSHOTS)
    if not os.path.isdir(path_reports): return None

    (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots) = (None, None, None, None, None)

    file_report_static  = '{}/{}'.format(path_reports, settings.DEFAULT_NAME_REPORT_STATIC)

    if not os.path.isfile(file_report_static):
        reports = (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots)
        return reports

    with open(file_report_static, 'r') as f:
        jsondata_static = f.read()
        jsondata_static = json.loads(jsondata_static)

    file_report_dynamic = '{}/{}'.format(path_reports, settings.DEFAULT_NAME_REPORT_DYNAMIC)
    if not os.path.isfile(file_report_dynamic):
        reports = (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots)
        return reports

    with open(file_report_dynamic, 'r') as f:
        jsondata_dynamic = f.read()
        jsondata_dynamic = json.loads(jsondata_dynamic)

    screenshots = []
    for root, dirs, files in os.walk(path_screenshots):
        for f in files:
            screenshots.append('{}/{}'.format(path_screenshots, f))

    reports = (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots)

    return reports


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
