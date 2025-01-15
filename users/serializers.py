import hashlib
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Group
import pyotp

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    role = serializers.ChoiceField(choices=['Admin', 'Regular User', 'Guest'], required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']

    def create(self, validated_data):
        role = validated_data.pop('role')
        raw_password = validated_data.pop('password')

        user = User(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
        )
        # Use set_password to hash the password
        user.set_password(raw_password)
        user.save()

        # Assign the user to the appropriate group
        group, created = Group.objects.get_or_create(name=role)
        user.groups.add(group)

        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'groups', 'user_permissions']

class MFASetupSerializer(serializers.Serializer):
    secret = serializers.CharField(max_length=32, read_only=True)
    otp = serializers.CharField(max_length=6, write_only=True)

    def create(self, validated_data):
        user = self.context['request'].user
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otp = validated_data.get('otp')

        if totp.verify(otp):
            user.mfa_secret = secret
            user.mfa_enabled = True
            user.save()
        else:
            raise serializers.ValidationError("Invalid OTP.")
        return {"secret": secret}


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data['username']
        raw_password = data['password']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid username or password.")

        # Use check_password to verify the raw password
        if not user.check_password(raw_password):
            raise serializers.ValidationError("Invalid username or password.")

        return {"user": user}


# class LoginSerializer(serializers.Serializer):
#     username = serializers.CharField()
#     password = serializers.CharField(write_only=True)
#     otp = serializers.CharField(max_length=6, required=False)

#     def validate(self, data):
#         user = User.objects.filter(username=data['username']).first()
#         if user and user.check_password(data['password']):
#             # Verify OTP if MFA is enabled
#             if user.profile.mfa_enabled:
#                 totp = pyotp.TOTP(user.profile.mfa_secret)
#                 if not totp.verify(data.get('otp')):
#                     raise serializers.ValidationError("Invalid OTP.")
#             refresh = RefreshToken.for_user(user)
#             return {
#                 'access': str(refresh.access_token),
#                 'refresh': str(refresh),
#             }
#         raise serializers.ValidationError("Invalid credentials.")
