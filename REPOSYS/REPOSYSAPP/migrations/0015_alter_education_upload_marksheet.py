# Generated by Django 3.2.6 on 2021-08-24 14:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('REPOSYSAPP', '0014_education'),
    ]

    operations = [
        migrations.AlterField(
            model_name='education',
            name='upload_marksheet',
            field=models.FileField(blank=True, null=True, upload_to='marksheets/%Y/%m/%d/'),
        ),
    ]