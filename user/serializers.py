# serializers.py
from rest_framework import serializers
from .models import CustomUser, UploadedFile, ActionsTaken

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        user = CustomUser(email=validated_data['email'])
        user.set_password(validated_data['password'])
        user.save()
        return user

class UploadedFileSerializer(serializers.ModelSerializer):

    class Meta:
        model = UploadedFile
        fields = ('consumer_number','uploader','file_key')


class ActionsTakenSerializer(serializers.ModelSerializer):

    class Meta:
        model = ActionsTaken
        fields = ('consumer_number','uploader','action','last_modified_time')

