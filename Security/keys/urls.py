from django.conf.urls import url
from .views import *
from . import views

# urlpatterns = patterns('',
#     url(r'^$', SetKeys.as_view()),
#     url(r'^web$', SetWebClientKeys.as_view()),
#     url(r'^(?P<username>\+[0-9]+\w+|[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})/(?P<device_id>[a-zA-Z0-9*]+)$',
#         GetDeviceKeysV2.as_view()),
#     # get keys for web client
#     url(r'^web/get/(?P<username>\+[0-9]+\w+|[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})$', GetWebClientKeys.as_view()),
#     url(r'^signed$', SignedKeyView.as_view()),
#     url(r'^web_signed$', WebSignedKeyView.as_view()),
#     url(r'^get_serverKey/$', views.get_serverKey, name='get_serverKey'),
#     # url(r'^get_allKey/$', views.get_allKey, name='get_allKey'),
#     # url(r'^get_allFileKey/$', views.get_allFileKey, name='get_allFileKey'),
#     url(r'^store_key/$', views.upload_key, name='upload_key'),
#     url(r'^get_key$', views.get_key, name='get_key'),
#     url(r'^store_filekey/$', views.upload_filekey, name='upload_filekey'),
#     # url(r'^get_filekey$', views.get_filekey, name='get_filekey'),
# )

urlpatterns = [
    url(r'^$', views.SetKeys.as_view()),
    url(r'^web$', views.SetWebClientKeys.as_view()),
    url(r'^create_user/$', views.VerificationOfCode.as_view()),
    url(r'^(?P<username>\+[0-9]+\w+|[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})/(?P<device_id>[a-zA-Z0-9*]+)$',
        views.GetDeviceKeysV2.as_view()),
    # url(r'^web/get/(?P<username>\+[0-9]+\w+|[\w.%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})$', views.GetWebClientKeys),
    url(r'^signed$', views.SignedKeyView.as_view()),
    url(r'^web_signed$', views.WebSignedKeyView.as_view()),
]

