from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db.models.signals import post_save
from django.dispatch.dispatcher import receiver

class User(AbstractUser): 
    username = models.CharField(
        max_length = 150,
        unique = True,
        error_messages = {
            'unique': "A user with that username already exists.",
        },
    )
    email = models.EmailField(unique=True)    
    first_name = None
    last_name = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return '%s' %(self.username)

gender_type = [
        ("MALE","MALE"),
        ("FEMALE","FEMALE"),
        ("OTHER","OTHER"),
        ]

class Profile(models.Model):     
    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name='user_profile')
    full_name = models.CharField(max_length=80)
    gender = models.CharField(max_length=8,default='MALE',choices=gender_type)
    phone_no = models.CharField(unique=True,max_length=20,null=True,blank=True)
    otp = models.CharField(max_length = 51,null=True,blank=True,unique=True)
    activation_key = models.CharField(max_length=100,blank=True,null=True)

    def __str__(self):
        return '%s' %(self.user)


@receiver(post_save, sender=User)
def user_create(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user = instance,full_name=instance.username)