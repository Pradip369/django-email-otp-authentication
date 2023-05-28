from django.shortcuts import render
from .forms import SignUpForm
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth import authenticate, login,logout,\
    update_session_auth_hash
from django.http.response import HttpResponseRedirect
from django.contrib import messages

def sign_up(request):
    if request.method=="POST":
        fm = SignUpForm(request.POST)
        if fm.is_valid():
            fm.save()
            return HttpResponseRedirect("/roll/login_user/")
    else:
        fm = SignUpForm()
    return render(request,'signup.html',{"fm":fm})

def login_user(request):
    if not request.user.is_authenticated:
        if request.method == "POST":
            fm = AuthenticationForm(request=request,data=request.POST)
            if fm.is_valid():
                uname = fm.cleaned_data['username']
                upw = fm.cleaned_data['password']
                user = authenticate(request=request,username=uname,password=upw)
                if user is not None:
                    login(request,user)
                    return HttpResponseRedirect("/roll/profile/")
                else:
                    print("Locha")
                
        else:
            fm = AuthenticationForm()
        return render(request, "login.html",{"fm":fm})
    else:
        return HttpResponseRedirect("/roll/profile/")

def profile(request):
    if request.user.is_authenticated:
        return render(request,"profile.html",{"us":request.user})
    else:
        return HttpResponseRedirect("/roll/login_user/")

def logout_user(request):
    logout(request)
    return HttpResponseRedirect("/roll/login_user/")

def changepassword(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            fm = PasswordChangeForm(user=request.user,data=request.POST)
            if fm.is_valid():
                fm.save()
                update_session_auth_hash(request,fm.user)
                messages.success(request,"You changed password Successfully ")
                return HttpResponseRedirect("/roll/profile/")
        else:
            fm = PasswordChangeForm(user=request.user)
    else:
        return HttpResponseRedirect("/roll/login_user/")
    return render(request,"changepass.html",{"fm":fm})















# if request.method == "POST":
#         fm = Studentregistrtion(request.POST)
#         if fm.is_valid:
#             fm.save()
#     else:
#         fm = Studentregistrtion()