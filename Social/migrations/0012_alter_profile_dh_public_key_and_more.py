# Generated by Django 4.2.6 on 2023-11-23 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Social', '0011_profile_dh_public_key_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='dh_public_key',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='encrypted_dh_private_key',
            field=models.TextField(null=True),
        ),
    ]
