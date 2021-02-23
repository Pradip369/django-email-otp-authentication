from django.urls import path
from .views import signup,signupVerify,resendOtp,LoginView,two_step_otp_Verify,reset_password_send,reset_password_verify,reset_password,ChangePasswordView,set_pass_email,UsernameView,change_email_send,change_email_verify,Logout,CustomTokenRefreshView
from rest_framework_simplejwt.views import TokenRefreshView,TokenVerifyView

urlpatterns = [
    path('signup/', signup,name = "sign_up"),
    path('resend_otp/',resendOtp,name = "resend_otp"),
    path('signup_verify/', signupVerify,name = "signup_verify"),
    
    
    path('login/',LoginView.as_view(),name = "login_user"),
    path('two_step_otp_Verify/<int:otp>/',two_step_otp_Verify,name = "two_step_otp_Verify"),
    
    path('logout/',Logout.as_view(),name = "logout_user"),
    
    
    path('reset_password_send/',reset_password_send,name = "reset_password_send"),
    path('reset_password_verify/',reset_password_verify,name = "reset_password_verify"),
    path('reset_password/',reset_password,name = "reset_password"),
    path('set_pass_email/<str:key>/',set_pass_email,name = "set_pass_email"),
    
    
    path('change_password/',ChangePasswordView.as_view(),name = "change_password"),
    
    
    path('username_get_update/',UsernameView.as_view(),name = "username_get_update"),
    
    path('change_email_send/',change_email_send,name = "change_email_send"),
    path('change_email_verify/',change_email_verify,name = "change_email_verify"),
    
    
    path('api/token/custom_refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'), 
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
    # path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]
