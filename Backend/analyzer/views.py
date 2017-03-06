import json
import re
from collections import OrderedDict

import sys
import zipfile

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.core.context_processors import csrf
from django.shortcuts import render_to_response, redirect
from django.contrib.auth.models import User
from django.template import RequestContext
from django.views.decorators.csrf import csrf_protect

from classifier import classify
from .forms import UploadFormMulti
from .models import FileUpload, Queue, Metadata, ClassifiedApp
from datastructure import *
from django.db.models import Q
from django.conf import settings
PATH_MODULE_CONFIG='../config/'
sys.path.append(PATH_MODULE_CONFIG)
reload(sys)

import misc_config

if misc_config.ENABLE_SENTRY_LOGGING:
    from raven import Client
    client = Client('http://46a1768b67214ab3be829c0de0b9b96f:60acd07481a449c6a44196e166a5d613@localhost:9000/2')


from mhash import * # TODO: Move that and the utils/mhash from the StaticAnalyzer to a single file.


# Constants
TMP_PATH = 'analyzer/tmp/'
BASE_URL = 'http://localhost:8000/show/?report='

# Views

def index(request):
    return render_to_response("base.html", context_instance=RequestContext(request))


def handler404(request):
    response = render_to_response('404.html', {},
                                  context_instance=RequestContext(request))
    response.status_code = 404

    return response


def handler500(request):
    response = render_to_response('500.html', {},
                                  context_instance=RequestContext(request))
    response.status_code = 500
    return response


def checkMailValid(email):
    match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)
    if match is None:
        return False
    else:
        return True

@csrf_protect
def registration(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        passwd = request.POST['password']

        match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', email)

        # Check for empty input fields
        if not checkMailValid(email):
            message = 'Please enter a valid email address!'
            return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))
        if username == "":
            message = 'Please provide an username!'
            return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))
        if passwd == "":
            message = 'Please provide a password!'
            return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))

        try:
            user = User.objects.get(username=username)
        except:
            user = None

        if user is None:
            User.objects.create_user(username=email, password=passwd, first_name=username)
            return render_to_response("registerSuccess.html")
        else:
            message = 'Email address already in use! %s' % user.username
            return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))
    else:
        return render_to_response("register.html", context_instance=RequestContext(request))


def userLogout(request):
    logout(request)
    return redirect("/")


@csrf_protect
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
            login(request, auth_user)
            # Redirect to member area
            return redirect('/home')
        else:
            # Redirect to error page
            message = 'Your email and password do not match'
            return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))
    else:
        return render_to_response("login.html", context_instance=RequestContext(request))


def anonUpload(request):
    if request.method == 'POST':
        return uploadFile(request, 'Anonymous')

    template = 'anonUpload.html'
    templatedict = {}
    templatedict['documents'] = FileUpload.objects.all()
    templatedict['form'] = UploadFormMulti()
    context_instance = RequestContext(request)
    return render_to_response(template, templatedict, context_instance=context_instance)


@csrf_protect
@login_required(login_url='/userLogin')
def userHome(request):
    if request.method == 'POST':
        return uploadFile(request, request.user.first_name, anonymous=False)

    template = 'home.html'
    templatedict = {}
    templatedict['documents'] = FileUpload.objects.all()
    templatedict['form'] = UploadFormMulti()
    templatedict['full_name'] = request.user.first_name
    context_instance = RequestContext(request)
    return render_to_response(template, templatedict, context_instance=context_instance)


@login_required(login_url='/userLogin')
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
    data['Decompiled Files'] = sha256

    return render_to_response('history.html', {"data": data}, context_instance=RequestContext(request))

def dataIsAPK(data):
    magic = '\x50\x4b\x03\x04' # ZIP Magic
    if data[:4] != magic: return False

    # Open the zipfile, check if required files are inside the APK
    # TODO We open the zipfile twice now, get rid of redundancy
    
    # TODO classes.dex, AndroidManifest.xml, resources.arsc
    return True


# Upload file and do sanity check
@csrf_protect
def uploadFile(request, username, anonymous=True): # TODO Use default values and set those parameters at the last positions e.g. username, anonymous=True
    # TODO Somehow test for accidentally rmtree('/') etc
    if not settings.PATH_SAMPLES or settings.PATH_SAMPLES == '':
        print 'Fatal Failure. Abort!'
        sys.exit(1)

    form = UploadFormMulti(request.POST, request.FILES)
    if not form.is_valid():
        message = 'The form was not valid!'
        return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))

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
            queue = None
            if Queue.objects.filter(sha256=appInfos['sha256'], type="static").exists():
                queue = Queue.objects.get(sha256=appInfos['sha256'], type="static")
            elif Metadata.objects.filter(sha256=appInfos['sha256']).exists():
                queue = Metadata.objects.get(sha256=appInfos['sha256'])

            #try:
            #    queue = Queue.objects.get(sha256=appInfos['sha256'], type="static")
            #except:
            #   queue = Metadata.objects.get(sha256=appInfos['sha256'])

            # Todo: Check if file is already in metadata!!!

            if queue is not None and (queue.status == 'idle' or queue.status == 'running'):
                entries = Queue.objects.all()
                count = 1
                for i in range(len(entries)):
                    if entries[i].type == 'dynamic':
                        if queue.sha256 == entries[i].sha256:
                            break
                        else:
                            count += 1

                uploadedFiles[sentFile.name]['error'] = 'This sample has already been submitted. The analysis is currently running. ' \
                                                        'Your sample has position %s in the queue. This should give you an estimate' \
                                                        ' when the analysis is finished.' % count
                continue
            # If the sample is already sumbitted show the user the link immediatelly
            else:
                templatedict = {'url': BASE_URL, 'uploaded_files': uploadedFiles, 'hash': appInfos['sha256']}
                template = 'existing_sample.html'
                if anonymous: template = 'existing_sample_anon.html'
                return render_to_response(template, templatedict, context_instance=RequestContext(request))


        # Otherwise, generate the directory structure
        try:
            os.makedirs(apkDir)
        except os.error:
            # NOTE We don't have permissions to create the directory
            # NOTE Or the directory exists already
            # See https://docs.python.org/2/library/os.html#os.makedirs
            if misc_config.ENABLE_SENTRY_LOGGING:
                client.captureException()
            uploadedFiles[sentFile.name]['error'] = 'An internal server error occurred.'
            continue

        # Save the APK to the generated directory
        apkFile = '{}/sample.apk'.format(apkDir)
        with open(apkFile, 'wb') as f: f.write(data)

        # TODO Since zipfile cannot read from stream, we have to check for zipfile contents here
        # Second APK test on the saved file
        try:
            z = zipfile.ZipFile(apkFile)
        except zipfile.BadZipfile:
            # TODO Remove the directory, otherwise an exception is thrown after uploading the sample again
            uploadedFiles[sentFile.name]['error'] = 'Sample has to be in APK format: Not a ZIP file'
            continue

        zfiles = set(z.namelist())
        afiles = set(['classes.dex', 'AndroidManifest.xml'])
        if len(afiles-zfiles) != 0:
            # TODO Remove the directory, otherwise an exception is thrown after uploading the sample again
            uploadedFiles[sentFile.name]['error'] = 'One of the following files is not in the sample: {}'.format(afiles)
            continue

        # Put file in Queue for analysis
        if anonymous:
            mail = request.POST.get("email")
            if checkMailValid(mail):
                Queue.objects.create(
                    filename=sentFile.name,
                    status='idle',
                    sha256=appInfos['sha256'],
                    path=apkDir,
                    type='static',
                    retry=0,
                    email=mail
                )

                Queue.objects.create(
                    filename=sentFile.name,
                    status='idle',
                    sha256=appInfos['sha256'],
                    path=apkDir,
                    type='dynamic',
                    retry=0,
                    email=mail
                )
            else:
                message = 'Please enter a valid email address!'
                return render_to_response('error.html', {'message': message},context_instance=RequestContext(request))
        else:
            Queue.objects.create(
                filename=sentFile.name,
                status='idle',
                sha256=appInfos['sha256'],
                path=apkDir,
                type='static',
                retry=0
            )

            Queue.objects.create(
                filename=sentFile.name,
                status='idle',
                sha256=appInfos['sha256'],
                path=apkDir,
                type='dynamic',
                retry=0
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

        uploadedFiles[sentFile.name]['uploaded'] = appInfos['sha256']

    # Return redirect link for every successful report - or redirect to the report page
    # For every error in the uploadedFiles, print a table with apkname and error
    templatedict = {'url' : BASE_URL, 'uploaded_files': uploadedFiles, 'hash': appInfos['sha256'] }
    template = 'anonUploadSuccess.html'
    if not anonymous:
        template = 'uploadSuccess.html'

    return render_to_response(template, templatedict, context_instance=RequestContext(request))


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


@csrf_protect
def serveFile(request):
    sha256 = request.GET.get('token')
    if not validateHash(sha256, 'sha256'):
        return render_to_response('error.html', {'message': 'This is not SHA256!'},context_instance=RequestContext(request)) # This is Sparta!

    path = '{}/{}'.format('analyzer/samples', getPathFromSHA256(sha256))
    filePath = '{}/{}'.format(path, 'download.zip')
    if os.path.exists(filePath):
        file = open(filePath, 'r')
    else:
        return render_to_response('error.html', {'message': 'The file does not exist. Try again later!'},context_instance=RequestContext(request))

    response = HttpResponse(file, mimetype='application/zip')
    response['Content-Disposition'] = 'attachment; filename="decompiled.zip"'
    response.write(file)
    return response


@csrf_protect
def showReport(request):
    sha256 = request.GET.get('report')
    type = request.GET.get('type')

    if not sha256: return HttpResponse('Did not specify sha256 GET parameter!')

    # Check for valid sha256 hash
    if not validateHash(sha256, 'sha256'):
        return render_to_response('error.html', {'message': 'This is not SHA256!'},context_instance=RequestContext(request)) # This is Sparta!

    reports = loadResults(sha256)
    (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots) = reports

    if Queue.objects.filter(sha256=sha256).exists():
        queue = Queue.objects.get(sha256=sha256)
        entries = Queue.objects.all()
        count = 1
        found = False
        res = ''
        if queue:
            for i in range(len(entries)):
                if entries[i].type == 'dynamic':
                    if queue.sha256 == entries[i].sha256:
                        found = True
                        break
                    else:
                        count += 1
            if found:
                res = 'However your sample is in the queue and has position %s. This should give you an estimate when the analysis is finished' % count

    if file_report_static is None and type == "static":
        return render_to_response('error.html', {'message': 'The report for this sample does not exist. '+res+' Please try'
                                                            'later after the analysis is complete'},context_instance=RequestContext(request))
    if file_report_dynamic is None and type == "dynamic":
        return render_to_response('error.html', {'message': 'The report for this sample does not exist. '+res+' Please try'
                                                            ' again later after the analysis is complete'},context_instance=RequestContext(request))

    meta = Metadata.objects.get(sha256=sha256)

    classifiedapp = None

    if file_report_static is not None:
        try:
            classfiedapp = ClassifiedApp.objects.get(sample_id=meta.id)
        except:
            classify(file_report_static, meta.id)

        if classifiedapp is None:
            classifiedapp = ClassifiedApp.objects.get(sample_id=meta.id)


    template = 'report.html'
    templatedict = {}
    templatedict['sha256'] = sha256

    if type == "static":
        templatedict['malicious'] = classifiedapp.malicious
        templatedict['jsondata_static'] = jsondata_static
        templatedict['type'] = type
    elif type == "dynamic":
        templatedict['jsondata_dynamic'] = jsondata_dynamic
        templatedict['screenshots'] = screenshots
        templatedict['type'] = type

    return render_to_response(template, templatedict, context_instance=RequestContext(request))


@csrf_protect
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
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256}, context_instance=RequestContext(request))

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
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256}, context_instance=RequestContext(request))

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
                    return render_to_response("searchResult.html", {'status': status, 'sha256': sha256}, context_instance=RequestContext(request))
        else:
            return HttpResponse('This is not a valid input!')

        return render_to_response('error.html', {'message': 'We could not find this sample in our database! '
                                                            'Please submit it to our system.'},context_instance=RequestContext(request))

def loadResults(sha256):
    path_apk            = '{}/{}'.format(settings.PATH_SAMPLES,getPathFromSHA256(sha256))
    path_reports        = '{}/{}'.format(path_apk, settings.DEFAULT_NAME_DIR_REPORTS)
    path_screenshots    = '{}/{}'.format(path_apk, settings.DEFAULT_NAME_SCREENSHOTS)
    if not os.path.isdir(path_reports): return None

    (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots) = (None, None, None, None, None)

    file_report_static  = '{}/{}'.format(path_reports, settings.DEFAULT_NAME_REPORT_STATIC)

    if os.path.isfile(file_report_static):
    #    reports = (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots)
    #    return reports
        with open(file_report_static, 'r') as f:
            jsondata_static = f.read()
            jsondata_static = json.loads(jsondata_static)
    else:
        file_report_static = None


    file_report_dynamic = '{}/{}'.format(path_reports, settings.DEFAULT_NAME_REPORT_DYNAMIC)
    if os.path.isfile(file_report_dynamic):
    #    reports = (file_report_static, file_report_dynamic, jsondata_static, jsondata_dynamic, screenshots)
    #    return reports
        with open(file_report_dynamic, 'r') as f:
            jsondata_dynamic = f.read()
            jsondata_dynamic = json.loads(jsondata_dynamic)
    else:
        file_report_dynamic = None

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
            print 'This is not sha256 format'
    elif type == 'sha1':
        try:
            result = re.match(r'^\w{40}$', hash)
        except RuntimeError:
            print 'This is not sha1 format'
    elif type == 'md5':
        try:
            result = re.match(r'^\w{32}$', hash)
        except RuntimeError:
            print 'This is not md5 format'

    return result is not None
