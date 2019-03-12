from django.conf.urls import url

from . import views

urlpatterns = [
    # url(r'^$', views.index, name='index'),
    url(r'^create_user/$', views.CreateUser.as_view(), name='create_user'),
    url(r'^store_key/$', views.SetKeys.as_view(), name='store_key'),
    url(r'^message/$', views.SetEncryptedMessage.as_view(), name='message'),
    url(r'^decrypt/$', views.DecryptMessage.as_view(), name='message'),
]