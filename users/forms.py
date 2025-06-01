from dataclasses import fields
import re
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model, authenticate
from django.forms import widgets
from django.utils.html import strip_tags
from django.core.validators import RegexValidator

User = get_user_model()

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, max_length=66, widget=forms.EmailInput(attrs={'class': 'input-register form-control', 'placeholder': 'Your email'}))
    first_name = forms.CharField(required=True, max_length=50, widget=forms.EmailInput(attrs={'class': 'input-register form-control', 'placeholder': 'Your first name'}))
    last_name = forms.CharField(required=True, max_length=50, widget=forms.EmailInput(attrs={'class': 'input-register form-control', 'placeholder': 'Your last name'}))
    password1 = forms.CharField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-register form-control', 'placeholder': 'write your password'})
    )
    password2 = forms.CharField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'input-register form-control', 'placeholder': 'repeat your password'})
    )
    marketing_consent1 = forms.BooleanField(required=False,
                                            label="I agree to recive commercial, promotional, and marketing communications",
                                            widget=forms.CheckboxInput(attrs={'class': 'checkbox-input-register'}))
    marketing_consent2 = forms.BooleanField(required=False,
                                            label="I agree to recive personalized commercial communications",
                                            widget=forms.CheckboxInput(attrs={'class': 'checkbox-input-register'}))
                    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password1', 'password2', 
                  'marketing_consent1', 'marketing_consent2')
        
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Thi email is already')
        return email
            

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = None
        user.marketing_consent1 = self.cleaned_data['marketing_consent1']
        user.marketing_consent2 = self.cleaned_data['marketing_consent2']
        if commit:
            user.save()
        return user
    
class CustomUserLoginForm(AuthenticationForm):
    username = forms.CharField(label = 'Email', 
                               widget=forms.TextInput(attrs={'autofocus': True, 'class': 'input-register form-control', 'placeholder': 'your email'}))
    
    password = forms.CharField(
        label='Password',
         widget=forms.TextInput(attrs={'autofocus': True, 'class': 'input-register form-control', 'placeholder': 'your password'}))
    
    def clean(self):
        email = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if email and password:
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
                raise forms.ValidationError('Invaild Email or Password')
            elif not self.user_cache.is_active:
                raise forms.ValidationError('This account is inactive')
        return self.cleaned_data
    
class CustomUserUpdateForm(forms.ModelForm):
    phone = forms.CharField(
        required=False,
        validators=[RegexValidator(r'^\+?1?\d{9, 15}$', "Enter a valid phone number")],
        widget=forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update phone'})
    )
    first_name = forms.CharField(
        required=True,
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your fname'})
    )
    phone = forms.CharField(
        required=True,
        max_length=50,
        widget=forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your lname'})
    )
    email = forms.EmailField(
        required=False,
        widget=forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your email'})
    )
    

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'adress1', 'adress2',
                  'city', 'country', 'province', 'postal_code', 'phone')
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your fname'}),
            'last_name': forms.TextInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your lname'}),
            'email': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'update your email'}),
            'adress1': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your adress1'}),
            'adress2': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your adress2'}),
            'city': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your city'}),
            'country': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your country'}),
            'province': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your province'}),
            'postasl_code': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your postal_code'}),
            'phone': forms.EmailInput(attrs={'class': 'imput-register form-control', 'placeholder': 'enter your phone'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and User.objects.filter(email=email).exclude(id=self.instance.id).exists():
            raise forms.ValidationError('This email is already in use')
        return email
    
    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('email'):
            cleaned_data['email'] = self.instance.email

            for field in ['adress1', 'adress2', 'city', 
                          'country', 'province', 'postal_code', 'phone']:
                if cleaned_data.get(field):
                    cleaned_data[field] = strip_tags(cleaned_data[field])
                return cleaned_data