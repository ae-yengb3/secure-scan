# Generated by Django 5.2.3 on 2025-07-28 12:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secure', '0010_remove_scan_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='leak_data',
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
    ]
