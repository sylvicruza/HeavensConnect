from django.db import migrations

def add_contact_support(apps, schema_editor):
    SystemSetting = apps.get_model('welfare', 'SystemSetting')
    SystemSetting.objects.get_or_create(
        key="contact_support",
        defaults={"value": "Email: support@heavensconnect.org\nPhone: +44 123 456 7890\nWhatsApp: +44 987 654 3210"}
    )

class Migration(migrations.Migration):

    dependencies = [
        ('welfare', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(add_contact_support),
    ]
