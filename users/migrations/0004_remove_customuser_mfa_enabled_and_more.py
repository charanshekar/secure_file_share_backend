# Generated by Django 4.2.17 on 2025-01-13 23:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_customuser_otp_customuser_otp_expiration'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='mfa_enabled',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='mfa_secret',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='otp',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='otp_expiration',
        ),
    ]
