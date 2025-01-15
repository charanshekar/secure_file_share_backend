from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from datetime import datetime

from .utils import send_otp_to_email
import pyotp

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model, logout, login
from .serializers import UserRegistrationSerializer, LoginSerializer, UserSerializer
from rest_framework.permissions import IsAuthenticated
from .permissions import IsAdminUser, IsRegularUser
from django.contrib.auth.decorators import login_required

# Create your views here.
User = get_user_model()

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def registerPage(request):
    context = {}
    return render(request, 'accounts/register.html', context)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            if user.groups.filter(name='Guest').exists():
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    'username': user.username,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'message': 'Login successful for Guest user.'
                }, status=status.HTTP_200_OK)
            else:
                send_otp_to_email(user, request)
                request.session['username'] = user.username
                return Response({
                    'username': user.username,
                    'message': 'OTP sent to your email.'
                }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class GetUserDetailsView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        user = request.user  # The authenticated user

        # Check if the user is an admin
        if user.is_superuser or user.groups.filter(name='Admin').exists():
            # Admin: Get details of all users
            all_users = User.objects.all()
            serializer = UserSerializer(all_users, many=True)
            return Response(serializer.data, status=200)

        # Regular user or guest: Return only their own info in a list
        serializer = UserSerializer(user)
        return Response([serializer.data], status=200)

    
class VerifyOTPView(APIView):
    def post(self, request):
        otp = request.data.get('otp')

        otp_secret_key = request.session['otp_secret_key']
        otp_valid_until = request.session['otp_valid_until']

        if otp_secret_key and otp_valid_until is not None:
            valid_until = datetime.fromisoformat(otp_valid_until)

            if valid_until > datetime.now():
                totp = pyotp.TOTP(otp_secret_key, interval=300)
                if totp.verify(otp):
                    user = get_object_or_404(User, username=request.session['username'])
                    login(request, user)

                    del request.session['otp_secret_key']
                    del request.session['otp_valid_until']

                    # Generate tokens
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'message': 'Login successful.'
                    }, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()
            request.session.flush()
            logout(request)
            return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)


# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             return Response(serializer.validated_data, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginView(APIView):
#     def post(self, request):
#         serializer = LoginSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.validated_data['user']
#             refresh = RefreshToken.for_user(user)
#             return Response({
#                 'access_token': str(refresh.access_token),
#                 'refresh_token': str(refresh),
#                 'message': 'Login successful.'
#             }, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class OTPLoginView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         otp = request.data.get('otp')
#         user = request.user

#         if not otp:
#             return Response({'error': 'OTP is required.'}, status=status.HTTP_400_BAD_REQUEST)

#         if user.otp == otp and user.otp_expiration > datetime.now():
#             # Clear OTP after successful verification
#             user.otp = None
#             user.otp_expiration = None
#             user.save()
#             return Response({'message': 'MFA verified successfully. Login complete.'}, status=status.HTTP_200_OK)
#         return Response({'error': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

    
# def login_view(request):
#     context = {}
#     error_message = None
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             # send one time pass
#             request.session['username'] = username
#             return redirect('otp')
#         else:
#             error_message = 'Invalid username or password'
#             context = {'error_message': error_message}
#     return render(request, 'accounts/login.html', context)

# def otp_view(request):
#     return render(request, 'otp.html', {})

# def main_view(request):
#     return render(request, 'main.html', {})

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


# class MFASetupView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         otp = random.randint(100000, 999999)
#         user = request.user
#         expiration_time = datetime.now() + timedelta(minutes=5)
        
#         # Store OTP and expiration in cache or database (for simplicity, storing in user model)
#         user.otp = otp
#         user.otp_expiration = expiration_time
#         user.save()

#         # Send email
#         send_mail(
#             subject="Your MFA OTP",
#             message=f"Your OTP is {otp}. It expires in 5 minutes.",
#             from_email=settings.DEFAULT_FROM_EMAIL,
#             recipient_list=[user.email],
#         )
        
#         return Response({
#             'otp_sent': True,
#             'message': 'OTP sent to your email.'
#         }, status=status.HTTP_200_OK)
    

# class EnableMFAView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         user = request.user
#         if not user.mfa_enabled:
#             # Generate a new TOTP secret
#             secret = pyotp.random_base32()
#             user.mfa_secret = secret
#             user.mfa_enabled = True
#             user.save()

#             # Generate a QR code URL for TOTP apps like Google Authenticator
#             totp = pyotp.TOTP(secret)
#             qr_code_url = totp.provisioning_uri(name=user.email, issuer_name="Secure File Share")
            
#             return Response({
#                 "message": "MFA enabled successfully.",
#                 "qr_code_url": qr_code_url
#             }, status=status.HTTP_200_OK)
#         return Response({"error": "MFA is already enabled."}, status=status.HTTP_400_BAD_REQUEST)

# class FileUploadView(APIView):
#     permission_classes = [IsAuthenticated, IsAdminUser | IsRegularUser]

#     def post(self, request):
#         serializer = FileUploadSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save(owner=request.user)
#             return Response({"message": "File uploaded successfully."}, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)