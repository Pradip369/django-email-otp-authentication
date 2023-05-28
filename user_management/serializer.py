from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import Profile

User = get_user_model()

class CreateUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username','email','password']

    def validate_password(self, value):
        user = self.context['request'].user
        validate_password(password=value, user=user)
        return value

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username','email']

        extra_kwargs = {
            'email': {'read_only': True},
        }

class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only = True)

    class Meta:
        model = Profile
        fields = ['user','full_name','gender','phone_no']

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=60, write_only=True, required=True)
    new_password = serializers.CharField(max_length=60, write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                'Your old password is incorrect!!'
            )
        return value

    def validate(self, data):
        validate_password(data['new_password'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user