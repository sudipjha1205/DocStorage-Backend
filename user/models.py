from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        # Create a user with the given email and password
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    # Other fields...

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    groups = models.ManyToManyField(Group, related_name='customuser_set', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='customuser_set', blank=True)

    def __str__(self):
        return self.email


class KYC(models.Model):
    consumer_no = models.CharField(max_length=255,unique=True)
    pdf_file = models.FileField(upload_to='pdf_documents/')

    def __str__(self):
        return f"{self.consumer_no} - {self.pdf_file}"

class UploadedFile(models.Model):
    consumer_number = models.CharField(primary_key=True,max_length=255)
    uploader = models.CharField(max_length=255)
    file_key = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.consumer_number} - {self.pdf_file} uploaded by {self.uploader}"

class ActionsTaken(models.Model):
    action_id = models.AutoField(primary_key=True)
    consumer_number = models.CharField(max_length=255)
    uploader = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    last_modified_time = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.consumer_number} {self.user} - {self.action} - {self.last_modified_time}"
