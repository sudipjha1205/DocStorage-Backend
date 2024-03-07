# Generated by Django 4.2.5 on 2024-03-06 09:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0004_alter_kyc_consumer_no'),
    ]

    operations = [
        migrations.CreateModel(
            name='UploadedFile',
            fields=[
                ('consumer_number', models.CharField(max_length=255, primary_key=True, serialize=False)),
                ('uploader', models.CharField(max_length=255)),
                ('pdf_file', models.FileField(upload_to='pdf_documents/')),
            ],
        ),
    ]