from django.conf.urls import url
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    url(r'^$', views.index),
    url(r'^registration/$', views.registration),
    url(r'^userLogin/$', views.loginUser),
    url(r'^home/$', views.userHome),
    url(r'^logout/$', views.userLogout),
    url(r'^show/$', views.showReport),
    url(r'^anonUpload/$', views.anonUpload),
    url(r'^history/$', views.showHistory),
    url(r'^search/$', views.search)

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)