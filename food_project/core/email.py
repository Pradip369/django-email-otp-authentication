from django.template.loader import render_to_string
from django.core.mail.message import EmailMultiAlternatives
from django.conf import settings
import threading

class EmailThread(threading.Thread):
    def __init__(self,template,subject,receiver_email,**kwargs):
        self.template = template
        self.subject = subject
        self.receiver_email = receiver_email
        self.kwargs = kwargs
        threading.Thread.__init__(self)
    
    def run(self):
        try:
            email_template = render_to_string(self.template,self.kwargs)    
            email_content = EmailMultiAlternatives(
                            self.subject, 
                            None,
                            settings.EMAIL_HOST_USER, 
                            [self.receiver_email],
                        )
            email_content.attach_alternative(email_template, 'text/html')
            email_content.send()
        except Exception as e:
            print(e)
            return None

def send_email(template,subject,receiver_email,**kwargs):
    return EmailThread(template, subject, receiver_email,**kwargs).start()