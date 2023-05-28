from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User,Profile
from django.contrib import admin

class CustomUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username','email','password')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('password1', 'password2'),
        }),
    )
    list_display = ('username','email','is_staff','is_active')
    search_fields = ('username', 'email')
    ordering = ()
    list_display_links = list_display
    filter_horizontal = ('groups', 'user_permissions',)

admin.site.register(User,CustomUserAdmin)

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ['id','full_name','gender']
    search_fields=["gender",'full_name','user__username']
    list_per_page = 10
    list_filter = ["gender","user__date_joined"]
    list_display_links = list_display
    ordering = ['-id']