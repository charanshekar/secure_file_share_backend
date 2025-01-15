from django.urls import path
from .views import RegisterView, LoginView, VerifyOTPView, LogoutView, GetUserDetailsView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('login/verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user-details/', GetUserDetailsView.as_view(), name='user-details'),
]