import json
import re
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.core.context_processors import csrf
from django.shortcuts import render_to_response, render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.template import RequestContext

from .forms import UploadForm
from .models import FileUpload, Queue, Metadata
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


@login_required(login_url='/analyzer/userLogin')
def userHome(request):
    magic = '\x50\x4b\x03\x04'

    if request.method == 'POST':
        sentFile = request.FILES['file']
        filename = sentFile.name
        form = UploadForm(request.POST, request.FILES)

        if form.is_valid():
            file=FileUpload(file=sentFile)
            file.save()

            # Check if file is a valid apk
            with open(TMP_PATH+filename) as f:
                fileStart = f.read(len(magic))
                if fileStart.startswith(magic):
                    apkFile = TMP_PATH+filename
                    path = getPath(apkFile)
                    filePath = getFilePath(apkFile)
                    fileName = createSHA1(apkFile)+".apk"
                    md5 = createMD5(apkFile)
                    sha1 = createSHA1(apkFile)
                    sha256 = createSHA256(apkFile)

                    if not os.path.isfile(filePath):
                        # createPath() already renames the file and moves
                        # it to the target directory
                        createPath(apkFile)

                        # Put file in Queue for analysis
                        Queue.objects.create(sha256=sha256,path=path, fileName=fileName, status='idle', type='static')
                        #Queue.objects.create(sha256=sha256, path=path, filename=fileName, status='idle', type='dynamic')

                        # Put Metadata into Database
                        Metadata.objects.create(md5=md5, sha1=sha1, sha256=sha256)
                    else:
                        # Todo: File already submitted. Load and show results to the user
                        pass

                    f.close()
                    return render_to_response("uploadSuccess.html", {'url': BASE_URL, 'hash': sha256})
                else:
                    os.remove(TMP_PATH+filename)
                    return HttpResponse('This file is not an apk file!')


        else:
            return HttpResponse('not valid')
    else:
        check = {}
        check.update(csrf(request))
        form = UploadForm()
        docs = FileUpload.objects.all()
        return render_to_response('home.html', {'documents': docs, 'form': form, 'full_name': request.user.first_name},
                                  context_instance=RequestContext(request))

def showReport(request):
    token = request.GET.get('report')
    # Check for valid sha256 hash
    if validateHash(token):
        result = loadResults(token)
        if result is None:
            return render_to_response('error.html', {'message': 'The report for this sample does not exist (yet?)'})
        # Check if sample is already classified

        return render_to_response("report.html", {'data': result})
    else:
        return render_to_response('error.html', {'message': 'This is not SHA256!'})


def loadResults(sha256):
    path = TMP_PATH+getPathFromSHA256(sha256)
    # Get result folder
    res = getResultFolder(path)
    if res is not None:
        with open(path+res+'/static.json') as f:
            data = json.load(f)
    else:
        return None
    return data


def getResultFolder(path):
    try:
        result = os.listdir(path)[0]
    except OSError:
        return None
    return result


def validateHash(hash):
    result = None
    try:
        result = re.match(r'^\w{64}$', hash)
    except RuntimeError:
        print 'This is not sha256'
    return result is not None
