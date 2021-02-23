from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
from django.conf import settings
from django.middleware import csrf


def generateKey():
    secret = pyotp.random_base32()        
    totp = pyotp.TOTP(secret, interval=86400)
    OTP = totp.now()
    return {"totp":secret,"OTP":OTP}
    
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
        
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }
    
def verify_otp(activation_key,otp):
    totp = pyotp.TOTP(activation_key, interval=86400)
    verify = totp.verify(otp)
    return verify


def set_browser_cookie(response,key,value):
    response.set_signed_cookie(
                       key = key, 
                       value = value,
                       salt = settings.SIMPLE_JWT['AUTH_COOKIE_SALT'],
                       expires = 214748364,
                       secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                       httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                       samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                       ) 

def set_token_cookie(request,response,user,user_secret_key):
    data = get_tokens_for_user(user)
    
    set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_ACCESS'],data["access"])
    set_browser_cookie(response,settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],data["refresh"])
    set_browser_cookie(response,settings.SIMPLE_JWT['USER_SECRET_KEY'],user_secret_key)

    csrf.get_token(request)
    return True