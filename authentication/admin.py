from django.contrib import admin
from .models import CustomUser,Profile

from import_export.admin import ImportExportModelAdmin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _


class CustomUserAdmin(UserAdmin,ImportExportModelAdmin):
    """Define admin model for custom User model with no username field."""
    fieldsets = (
        (None, {'fields': ('username','email','password')}),
        (_('Authentication Info'), {'fields': ('otp','activation_key','two_step_verification','total_login_devices','user_secret_key','change_email')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2'),
        }),
    )
    list_display = ('username', 'email','is_staff')
    search_fields = ('username','email')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions',)


admin.site.register(CustomUser,CustomUserAdmin)

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display= ["id","image_tag","user_name","public_name","location","cr_date"]
    search_fields=["user_name","id","public_name","name",'gender',"location","phone_number"]
    list_filter = ["user_name","gender"]
    list_display_links = ["id","user_name","image_tag","public_name","cr_date"]
    readonly_fields = ['image_tag']
