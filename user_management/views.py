from django.shortcuts import render
from django.http.response import HttpResponse
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from .serializer import CreateUserSerializer,ChangePasswordSerializer,ProfileSerializer,UserSerializer
from rest_framework.response import Response
from rest_framework import status
from .helper import generate_otp,verify_otp
from django.contrib.auth import get_user_model, authenticate
from .models import Profile
from food_project.core.email import send_email
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.generics import UpdateAPIView
from rest_framework.permissions import AllowAny,IsAuthenticatedOrReadOnly

User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny,])
def sign_up(request):
    serializer = CreateUserSerializer(data = request.data,context = {"request": request})
    if serializer.is_valid(raise_exception=True):
        activation_key,otp = generate_otp()
        user = User(username = serializer.data.get('username'),email = serializer.data.get('email'))
        user.set_password(serializer.data['password'])
        user.is_active = False
        user.save()

        Profile.objects.filter(user = user).update(otp = otp,activation_key = activation_key)
        send_email('email_templates/otp_verification.html', 'Otp Verification',user.email, otp=otp, username=user.username)
    return Response({"message" : "Otp successfully sent!!","email":serializer.data.get('email')},status = status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny,])
def otp_verify(request):
    otp = request.data.get('otp')
    req_type = request.data.get('req_type')
    try:
        profile = Profile.objects.filter(otp = otp).first()
        if not profile:
            return Response({"message" : "Invalid OTP!!"},status = status.HTTP_400_BAD_REQUEST)
        verify = verify_otp(profile.activation_key,profile.otp)
        profile.otp = None
        profile.activation_key = None
        profile.save()
        if verify:
            profile.user.is_active = True
            profile.user.save()
            token = None
            user_data = None
            if req_type == 'sigup':
                token = str(RefreshToken.for_user(profile.user).access_token)
                user_data = ProfileSerializer(profile).data
            return Response({"message" : "OTP verified!!",'token': token,'user_data' : user_data},status = status.HTTP_200_OK)
        else:
            return Response({"message" : "OTP Expired!!"},status = status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"message" : "Something went wrong","error" : str(e)},status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny,])
def send_otp(request):
    data = request.data
    email = data.get("email")
    req_type = data.get("req_type",False)
    try:
        is_active = False if req_type == 'create_account' else True
        profile = Profile.objects.get(user__email = email,user__is_active = is_active)
        activation_key,otp = generate_otp()
        profile.activation_key = activation_key
        profile.otp = otp
        profile.save()   
        send_email('email_templates/otp_verification.html', 'Otp Verification',email, otp=otp, username=profile.user.username)
        return Response({'email' : email,"message" : "Otp successfully send!!"},status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"message" : "No account found for this given email!!"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny,])
def login(request):
    data = request.data
    username = data.get('username', None)
    password = data.get('password', None)
    user = authenticate(username=username,password=password)
    if user is not None:
        if user.is_active:
            update_last_login(None, user)
            token = str(RefreshToken.for_user(user).access_token)
            user_data = ProfileSerializer(user.user_profile).data
            return Response({"message" : "Login successfull!!","token" : token,'user_data' : user_data}, status=status.HTTP_200_OK)
        else:
            return Response({"message" : "This account is not activated!!"}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"message" : "Invalid username or password!!"}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny,])
def reset_password_verify(request):
    otp = request.data.get("otp")
    try:
        profile = Profile.objects.get(otp = otp)
        verify = verify_otp(profile.activation_key,profile.otp)
        if verify:
            return Response({"message" : "OTP is verified!!"},status=status.HTTP_200_OK)
        else:
            return Response({"message" : "OTP Expired!!!"},status=status.HTTP_400_BAD_REQUEST)
    except:
        return Response({"message" : "Invalid OTP"},status=status.HTTP_400_BAD_REQUEST)\

@api_view(['POST'])
@permission_classes([AllowAny,])
def reset_password(request):
    data = request.data
    try:
        profile = Profile.objects.get(otp = data['otp'])
        try:
            validate_password(data['password'],profile.user)
        except ValidationError as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)
        profile.user.set_password(data['password'])
        profile.otp = None
        profile.activation_key = None
        profile.save()
        profile.user.save()       
        return Response({"message" : "Password updated successfully!!"},status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"message" : "Something went wrong!!",'error' : str(e)},status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(UpdateAPIView):

    serializer_class = ChangePasswordSerializer

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message" : "Password successfully changed!!!"},status=status.HTTP_200_OK)

@api_view(['POST'])
def change_email_send(request):
    email = request.data.get("email")
    user = User.objects.filter(email = email).first()
    if user:
        return Response({"message" : "Given email already exist or same as your current email address!!"},status=status.HTTP_400_BAD_REQUEST)
    else:        
        try:
            profile = Profile.objects.get(user = request.user,user__email = email)
            activation_key,otp = generate_otp()
            profile.activation_key = activation_key
            profile.otp = otp
            profile.save() 
            send_email('email_templates/otp_verification.html', 'Otp Verification',email, otp=otp, username=request.user.username)
            return Response({"message" : "OTP has been successfully sent!!","email" : email},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message" : "Something went wrong!!","error":str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def change_email(request):
    try:
        otp = request.data["otp"]
        email =  request.data["email"]
        profile = Profile.objects.get(otp = otp)
        verify = verify_otp(profile.activation_key,profile.otp)
        if verify:
            profile.user.email = email
            profile.otp = None
            profile.activation_key = None
            profile.save()  
            profile.user.save()       
            return Response({"message" : "Email changed successfully!!"},status=status.HTTP_200_OK)
        else:
            return Response({"message" : "OTP Expired!!!"},status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"message" : "Invalid OTP","error" : str(e)},status=status.HTTP_400_BAD_REQUEST)

class ProfileDetail(APIView):

    def get(self,request,formate=None):
        profile_data = ProfileSerializer(request.user.user_profile).data
        return Response({"user_data" : profile_data},status=status.HTTP_200_OK)

    def post(self,request,formate=True):
        user = request.user
        if request.data.get('username'):
            user_data = UserSerializer(user,data = request.data,partial = True)
            if user_data.is_valid(raise_exception=True):
                user_data.save()
        profile_data = ProfileSerializer(user.user_profile,data = request.data,partial = True)
        if profile_data.is_valid(raise_exception = True):
            profile_data.save()
        return Response({"user_data" : profile_data.data},status=status.HTTP_200_OK)