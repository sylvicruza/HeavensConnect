# Generated by Django 5.2 on 2025-05-19 13:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('welfare', '0012_adminuser_fcm_token_member_fcm_token'),
    ]

    operations = [
        migrations.CreateModel(
            name='SystemSetting',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=50, unique=True)),
                ('value', models.TextField()),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
