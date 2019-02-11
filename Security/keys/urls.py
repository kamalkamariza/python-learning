from django.conf.urls import url

from . import views

urlpatterns = [
    # url(r'^$', views.index, name='index'),
    url(r'^test_rsa/$', views.test_rsa, name='test_rsa'),
    url(r'^test_test/$', views.test_test, name='test_test'),
    url(r'^test_key/$', views.test_key, name='test_key'),
    url(r'^get_serverPrivKey/$', views.get_serverPrivKey, name='get_serverPrivKey'),
    url(r'^get_serverKey/$', views.get_serverKey, name='get_serverKey'),
    url(r'^get_allKey/$', views.get_allKey, name='get_allKey'),
    url(r'^get_allFileKey/$', views.get_allFileKey, name='get_allFileKey'),
    url(r'^store_key/$', views.upload_key, name='upload_key'),
    url(r'^get_key$', views.get_key, name='get_key'),
    url(r'^store_filekey/$', views.upload_filekey, name='upload_filekey'),
    url(r'^get_filekey$', views.get_filekey, name='get_filekey'),
    # url(r'^get_key/(?P<user_number>.+)/$', views.get_key, name='get_key'),
    # url(r'^$', views.IndexView.as_view(), name='index'),
]