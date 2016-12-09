from django.conf.urls import url
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.conf.urls import (
handler400, handler403, handler404, handler500)

handler404 = 'analyzer.views.handler404'
handler500 = 'analyzer.views.handler500'

urlpatterns = [
    url(r'^$', views.index),
    url(r'^registration/$', views.registration),
    url(r'^userLogin/$', views.loginUser),
    url(r'^home/$', views.userHome),
    url(r'^logout/$', views.userLogout),
    url(r'^show/$', views.showReport),
    url(r'^anonUpload/$', views.anonUpload),
    url(r'^history/$', views.showHistory),
    url(r'^search/$', views.search),
    url(r'^queue/$', views.showQueue),
    url(r'^download/$', views.serveFile),
    url(r'^samples/(?P<path>.*)$', 'django.views.static.serve',
        {'document_root': settings.MEDIA_ROOT})

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
