from django.conf.urls import patterns, include, url
from django.contrib import admin

#admin.autodiscover()

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = [
    url(r'^', include('analyzer.urls')),
    #url(r'^admin/', admin.site.urls),

    # Examples:
    # url(r'^$', 'mobilesandbox.views.home', name='home'),
    # url(r'^mobilesandbox/', include('mobilesandbox.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
]
