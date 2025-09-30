from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, Enquiry



class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "phone", "password1", "password2"]


class EnquiryForm(forms.ModelForm):
    class Meta:
        model = Enquiry
        fields = '__all__'