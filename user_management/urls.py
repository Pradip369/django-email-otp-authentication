from django.urls import path
from .views import (sign_up,
                    otp_verify,
                    send_otp,
                    login,
                    reset_password_verify,
                    reset_password,
                    ChangePasswordView,
                    change_email_send,
                    change_email,
                    ProfileDetail)

urlpatterns = [
    path('send_otp/',send_otp),
    path('otp_verify/',otp_verify),
    path('sign_up/',sign_up),
    path('login/',login),
    path('reset_password_verify/',reset_password_verify),
    path('reset_password/',reset_password),
    path('change_password/',ChangePasswordView.as_view()),
    path('change_email_send/',change_email_send),
    path('change_email/',change_email),
    path('user_profile/',ProfileDetail.as_view()),
    path('update_profile/',ProfileDetail.as_view()),
]