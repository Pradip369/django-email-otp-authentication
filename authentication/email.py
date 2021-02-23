from django.template.loader import render_to_string
from django.core.mail.message import EmailMultiAlternatives
from django.conf import settings


def send_email(template,subject,receiver_email,**kwargs):
    email_template = render_to_string(template,kwargs)    
    email_content = EmailMultiAlternatives(
                    subject, 
                    None,
                    settings.EMAIL_HOST_USER, 
                    [receiver_email],
                )
    email_content.attach_alternative(email_template, 'text/html')
    email_content.send()
    return True