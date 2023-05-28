from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

User = get_user_model()

'''
    User Authentication(Login) with email or username...
'''


class UsernameOrEmailBackend(ModelBackend):
    def authenticate(self,request, username=None, password=None,**kwargs):
        try:
            if '@' in username:
                kwargs = {'email': username}
            else:
                kwargs = {'username': username}   
            user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None
        except Exception as e:
            return None