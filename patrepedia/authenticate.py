from django.contrib.auth.backends import ModelBackend
import re
from django.contrib.auth import get_user_model


User = get_user_model()
class UsernameOrEmailBackend(ModelBackend):

    def authenticate(self,request, username=None, password=None,**kwargs):
        if '@' in username:
            kwargs = {'email': username}
        else:
            kwargs = {'username': username}   
        try:
            user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
