# Generated by Django 5.2.1 on 2025-05-14 17:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secure', '0003_user_groups_user_is_superuser_user_last_login_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='is_superuser',
            field=models.BooleanField(default=False),
        ),
    ]
