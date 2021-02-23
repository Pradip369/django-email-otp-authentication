from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from PIL import Image
from django.core.files.storage import default_storage as storage
from django.utils.html import mark_safe

def no_special_char(value): 
    if '@' in value or '!' in value or '#' in value or '$' in value or '%' in value or '^' in value or '&' in value or '*' in value or '+' in value or '-' in value or '.' in value:
        raise ValidationError("This field is not accept special character or space..")

class CustomUser(AbstractUser):
     
    username = models.CharField(
        max_length=80,
        unique=True,
        validators=[no_special_char],
    )
    
    email = models.EmailField(
                unique=True,
                )
    
    first_name = None
    last_name = None
    
    change_email = models.EmailField(blank=True,null=True)
    otp = models.IntegerField(null=True,blank=True)
    activation_key = models.CharField(max_length=150,blank=True,null=True)
    two_step_verification = models.BooleanField(default = False)
    total_login_devices = models.IntegerField(default=0)
    user_secret_key = models.CharField(max_length=500,null=True,blank=True)
    
    def save(self,*args,**kwargs):
        super().save()
        if ' ' in self.username:
            self.username = self.username.replace(" ", "_")
            super(CustomUser, self).save(*args, **kwargs)
            
    def __str__(self):
        return '%s' %(self.username)
    
class Profile(models.Model):
    user_name = models.OneToOneField(to = CustomUser,on_delete=models.CASCADE)
    name = models.CharField(null=True,max_length=30, blank=True)
    public_name = models.CharField(null=True,max_length=30, blank=True)
    bio = models.CharField(max_length=500,null=True,blank=True)
    profile_pic = models.ImageField(upload_to = 'profile_pic',null=True,blank=True)
    phone_number = models.IntegerField(null = True,blank=True)
    location = models.CharField(max_length=10,null=True,blank=True)
    gender = models.CharField(max_length=10,null=True,blank=True)
    cr_date = models.DateTimeField(auto_now_add=True)
    
    # def save(self, *args, **kwargs):
    #     super(Profile, self).save(*args, **kwargs)

    #     if self.profile_pic:
    #         imag = Image.open(self.profile_pic)
    #         output_size = (300, 300)
    #         imag.thumbnail(output_size,Image.ANTIALIAS)
    #         fh = storage.open(self.profile_pic.name, "w")
    #         format = 'png'
    #         imag.save(fh,format)
    #         fh.close()
    
    def save(self):
        super().save()  # saving image first
        if self.profile_pic:

            img = Image.open(self.profile_pic.path) # Open image using self

            if img.height > 300 or img.width > 300:
                new_img = (300, 300)
                img.thumbnail(new_img)
                img.save(self.profile_pic.path)   
    
    def image_tag(self):
        if self.profile_pic:
            return mark_safe('<img src="%s" width="45px" height="45px" />' % (self.profile_pic.url))
    image_tag.short_description = 'Profile Pic.'