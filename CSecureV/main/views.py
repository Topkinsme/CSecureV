from django.http import HttpResponse
from django.shortcuts import render

def home(request):
    return render(request, 'main/landing_page.html')

def login(request):
    return render(request,'main/login.html')

def sign_up(request):
    return render(request,'main/signup.html')

def main_page(request):
    return render(request,'main/main_page.html')

def profile(request):
    return render(request,'main/profile.html')
