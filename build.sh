#!/usr/bin/env bash
set -o errexit

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --noinput

# Automatically create a superuser if it doesn't exist
echo "from django.contrib.auth import get_user_model; User = get_user_model(); import os; \
username=os.environ.get('DJANGO_SUPERUSER_USERNAME'); \
email=os.environ.get('DJANGO_SUPERUSER_EMAIL'); \
password=os.environ.get('DJANGO_SUPERUSER_PASSWORD'); \
User.objects.filter(username=username).exists() or User.objects.create_superuser(username=username, email=email, password=password)" \
| python manage.py shell
