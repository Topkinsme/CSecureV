from django.http import HttpResponse
from django.shortcuts import render,redirect
from .models import User
import random
def home(request):
    return render(request, 'main/landing_page.html')


def gen_id():
    genid="USER_"+str(random.randint(1000,9999))
    while User.objects.filter(user_id=genid):
        genid="USER_"+str(random.randint(1000,9999))
    return genid

def login(request):
    context={}
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user=User.objects.filter(username=username)
        if not user:
            context["error"]="No such user found!"
        else:
            user=user[0]
            if not user.check_password(password):
                context["error"]="Wrong password!"
            else:
                request.session['user']=user.user_id
                request.session.modified=True
                request.session.set_expiry(600)
                return redirect('main_page')  

    return render(request,'main/login.html',context=context)

def logout(request):
    request.session.clear()
    request.session.flush()
    return redirect('/')

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')
        if password != confirm_password:
            context={'error':"Passwords do not match!"}
            return render(request,'main/signup.html',context=context) 
        user = User(user_id=gen_id(),username=username, password=None)
        user.set_password(password)
        # GEN KEYS
        user.save()
        return redirect('login')  

    return render(request, 'main/signup.html')

def main_page(request):
    if 'user' not in request.session:
        return redirect('login')
    return render(request,'main/main_page.html')

def profile(request):
    context={}
    if 'user' not in request.session:
        return redirect('login')
    context['username']=User.objects.filter(user_id=request.session['user'])[0].username
    return render(request,'main/profile.html',context=context)

def decrypt(request):
    if 'user' not in request.session:
        return redirect('login')
    return render(request,'main/encrypt.html')

def encrypt(request):
    if 'user' not in request.session:
        return redirect('login')
    return render(request,'main/decrypt.html')
