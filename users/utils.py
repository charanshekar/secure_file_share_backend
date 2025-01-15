from django.core.mail import send_mail
from secure_file_share.settings import EMAIL_HOST_USER
from datetime import datetime, timedelta
from django.conf import settings
import pyotp

def send_otp_to_email(user, request):
    """
    Generates an OTP, saves it in the user's model, and sends it via email.
    """
    totp = pyotp.TOTP(pyotp.random_base32(), interval=300)
    otp = totp.now()
    request.session['otp_secret_key'] = totp.secret
    expiration_time = datetime.now() + timedelta(minutes=5)
    request.session['otp_valid_until'] = str(expiration_time)

    # Save OTP and expiration in the user model
    user.otp = otp
    user.otp_expiration = expiration_time
    user.save()

    print(f"Your OTP for Abnormal Security: {otp}")
    # Send email
    # send_mail(
    #     subject="Your MFA OTP",
    #     message=f"Your OTP is {otp}. It expires in 5 minutes.",
    #     from_email=EMAIL_HOST_USER,
    #     recipient_list=[user.email],
    # )
