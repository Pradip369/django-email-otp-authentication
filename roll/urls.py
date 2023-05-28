from django.urls import path
from . import views
from django.views.generic.base import RedirectView

urlpatterns = [
        path('sign_up/',views.sign_up),
        path('login_user/',views.login_user),
        path('logout_user/',views.logout_user),
        path('profile/',views.profile),
        path('changepassword/',views.changepassword,name="cp"),
        path('',RedirectView.as_view(url='sign_up/')),

]
