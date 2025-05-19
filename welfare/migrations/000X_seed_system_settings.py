# --- Django Migration to Pre-populate Settings ---

from django.db import migrations

def seed_system_settings(apps, schema_editor):
    SystemSetting = apps.get_model('welfare', 'SystemSetting')
    data = [
        {"key": "bank_account", "value": "Opened Heavens Chapel, Sort Code: 30-94-44, Acc No: 51659968"},
        {"key": "categories", "value": "school_fees,marriage,funeral,job_loss,medical,baby_dedication,food,rent,others"},
        {"key": "payment_methods", "value": "cash,transfer"},
        {"key": "welfare_statuses", "value": "pending,under_review,approved,declined,paid"},
        {"key": "contribution_statuses", "value": "pending,received,verified,rejected"},
        {"key": "member_statuses", "value": "active,inactive,deceased"},
        {"key": "admin_roles", "value": "admin,finance,viewer"},
        {"key": "years", "value": "2023,2024,2025"},
    ]
    for item in data:
        SystemSetting.objects.get_or_create(key=item["key"], defaults={"value": item["value"]})

class Migration(migrations.Migration):

    dependencies = [
        ('welfare', '0001_initial'),  # replace with your actual initial migration name
    ]

    operations = [
        migrations.RunPython(seed_system_settings),
    ]
