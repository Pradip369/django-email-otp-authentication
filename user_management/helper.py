from pyotp import random_base32,TOTP

def generate_otp():
    secret = random_base32()        
    totp = TOTP(secret, interval=1800)
    OTP = totp.now()
    return secret,OTP
    
def verify_otp(activation_key,otp):
    totp = TOTP(activation_key, interval=1800)
    verify = totp.verify(otp)
    return verify