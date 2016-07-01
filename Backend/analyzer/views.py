import os
import re
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.core.context_processors import csrf
from django.shortcuts import render_to_response, render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.template import RequestContext

from .forms import UploadForm
from .models import FileUpload
from datastructure import createPath, getPath, getFilePath


# Constants
TMP_PATH='analyzer/tmp/'


# Views

def index(request):
    return HttpResponse("User registration successful!")


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
            return HttpResponse("User registration successful!")
        else:
            message = 'Email address already in use! %s' % user.username
            return render_to_response('error.html', {'message': message})
    else:
        check = {}
        check.update(csrf(request))
        return render_to_response("register.html", check)


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
            if auth_user.is_active:
                login(request, auth_user)
                # Redirect to member area
                return redirect('/analyzer/home')
                #return HttpResponse("Login successful! Welcome %s" %user.first_name)
            else:
                message = 'The user %s is disabled.' % user.first_name
                return render_to_response('error.html', {'message': message})
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

                    if not os.path.isfile(filePath):
                        if not os.path.isdir(path):
                            # createPath() already renames the file and moves
                            # it to the target directory
                            createPath(path)
                            # Todo: Put file in queue for analysis
                    else:
                        # Todo: File already submitted. Show results from database
                        pass

                    f.close()
                    return HttpResponse('is apk')
                else:
                    os.remove(TMP_PATH+filename)
                    return HttpResponse('not an apk file')


        else:
            return HttpResponse('not valid')
        return HttpResponse('upladed!')
    else:
        check = {}
        check.update(csrf(request))
        form = UploadForm()
        docs = FileUpload.objects.all()
        return render_to_response('home.html', {'documents': docs, 'form': form, 'full_name': request.user.first_name},
                                  context_instance=RequestContext(request))