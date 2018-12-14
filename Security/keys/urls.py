from django.conf.urls import url

from . import views

urlpatterns = [
    # url(r'^$', views.index, name='index'),
    url(r'^get_allKey/$', views.get_allKey, name='get_allKey'),
    url(r'^store_key/$', views.upload_key, name='upload_key'),
    url(r'^get_key$', views.get_key, name='get_key'),
    # url(r'^get_key/(?P<user_number>.+)/$', views.get_key, name='get_key'),
    # url(r'^$', views.IndexView.as_view(), name='index'),
]