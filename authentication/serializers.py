from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class SignUpSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['username','email','password']
        write_only_fields = ('password',)
        read_only_fields = ('id',)
        
        
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=60, write_only=True, required=True)
    new_password1 = serializers.CharField(max_length=60, write_only=True, required=True)
    new_password2 = serializers.CharField(max_length=60, write_only=True, required=True)

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                'Your old password is incorrect!!'
            )
        return value

    def validate(self, data):
        if data['new_password1'] != data['new_password2']:
            raise serializers.ValidationError({'new_password2': "The both password fields didn't match."})
        validate_password(data['new_password1'], self.context['request'].user)
        return data

    def save(self, **kwargs):
        password = self.validated_data['new_password1']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user
    
class UserNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username']
        read_only_fields = ('id',)