# from django.shortcuts import render

# Create your views here.
import email
from urllib import response
from django.shortcuts import render
from rest_framework import generics, status, views, permissions

from core.common.response import return_error_response
from .serializer import RegisterSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer,  LoginSerializer, LogoutSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
import os
from rest_framework import status
from rest_framework.decorators import (api_view, authentication_classes,
                                       permission_classes)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from core.common.logger import get_custom_logger
from core.common.response import return_error_response
from .serializer import *
from rest_framework.views import APIView


log = get_custom_logger()

# Create your views here.
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER

class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email']) 
        # token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        relativeLink = reverse('login')
        absurl = 'http://'+current_site+relativeLink
        # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.username  +'\n Thank you for registering with Terralogic Meet. Please find the credentials below for your future reference.\n '+ \
            ' Use the link below to verify your email \n'+'\n Username :'+user.username + '\n Password :'+user.password   + \
              "URl:"+absurl + '\n Hope you enjoy our Terralogic meet. Lets make it possible the impossible. \n'  + \
                   '\n Thanks,' +'\n Terralogic Team'            
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Registration successfull'}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)


# @api_view(['POST'])
# def login_api(request):
#     """Login user"""
#     try:
#         data =request.data
#         email = data.get('email', None)
#         data_validator = LoginSerializer(data=data)
#         if not data_validator.is_valid():
#             return return_error_response(
#                     data_validator.errors, status.HTTP_400_BAD_REQUEST
#                 )
#         user = User.objects.get(email=email)

#         payload = jwt_payload_handler(user)
#         token = jwt_encode_handler(payload)
#         context = {
#             'name': User.username,
#             'token' :token
#         }

#         response_validator = LoginSerializer(data = context)
#         if not response_validator.is_valid():
#             return return_error_response(response_validator.error_messages, data = response_validator.errors)
        
#         return response(
#                 code=200,
#                 status=200,
#                 data=response_validator.validated_data,
#             )

#     except Exception as e:
#         local_response = response(
#             code=400,
#             status=400,
#             message=str(e),
#             data=[]
#         )
#         return local_response

# class LoginAPIView(generics.GenericAPIView):
#     serializer_class = LoginSerializer
#     def post(self,request):
#         data=request.data
#         email=data.get('email',None)
#         password=data.get('password',None)
#         serializer=self.serializer_class(data=data)
#         if serializer.is_valid(raise_exception=True):
#             serializer.save()

#         payload = jwt_payload_handler(User)
#         token = jwt_encode_handler(payload)
#         context = {
#             'name': User.email,
#             'token' :token
#         }
#         response_validator=LoginSerializer(data=context)
#         if not response_validator.is_valid():
#             return return_error_response(response_validator.error_messages,data=response_validator.errors)
#         return response(
#                 code=200,
#                 status=200,
#                 message="USER_LOGIN_SUCCESS",
#                 data=response_validator.validated_data,
#             )

@api_view(['POST'])
# @permission_classes([AllowAny, ])
def login_user(request):
 
    try:
        email = request.data['email']
        password = request.data['password']
 
        user = User.objects.get(email=email, password=password)
        if user:
            try:
                payload = jwt_payload_handler(user)
                token = jwt.encode(payload, settings.SECRET_KEY)
                user_details = {}
                user_details['token'] = token
                return Response(user_details, status=status.HTTP_200_OK)
 
            except Exception as e:
                raise e
        else:
            res = {
                'error': 'can not authenticate with the given credentials or the account has been deactivated'}
            return Response(res, status=status.HTTP_403_FORBIDDEN)
    except KeyError:
        res = {'error': 'please provide a email and a password'}
        return Response(res)

       
            



class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' + \
                absurl+"?redirect_url="+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,
                    'email_subject': 'Reset your passsword'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
 

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)



class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)