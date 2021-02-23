from django.contrib import admin
from django.urls import path
from django.urls.conf import include
from . import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/',include('authentication.urls') ),
]
urlpatterns += static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)