from django.http import HttpResponse
from django.shortcuts import render,redirect
from .models import User
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
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
        user=User.objects.filter(username=username)
        if user:
            context={'error':"User already exists! Use a different username!"}
            return render(request,'main/signup.html',context=context) 
        if password != confirm_password:
            context={'error':"Passwords do not match!"}
            return render(request,'main/signup.html',context=context) 
        
        user = User(user_id=gen_id(),username=username, password=None)
        user.set_password(password)
        user.private_key=RSA.generate(2048).exportKey().decode('utf-8')  #RSA.importKey('-----BEGIN RSA PRIVATE KEY--- ....')
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
    if request.method == 'POST':
        sender_id = request.session.get('user')
        receiver_username = request.POST.get('receiver-username')
        pin = request.POST.get('pin')
        uploaded_file = request.FILES.get('file-upload')

        #get all keys
        sender = User.objects.get(user_id=sender_id)
        receiver = User.objects.get(username=receiver_username)
        sender_private_key = RSA.importKey(sender.private_key.encode('utf-8'))
        receiver_public_key = RSA.importKey(receiver.private_key.encode('utf-8')).publickey()
        file_data = uploaded_file.read()

        cipher_rsa_sender = PKCS1_OAEP.new(sender_private_key)
        encrypted_by_sender = cipher_rsa_sender.encrypt(file_data)

        cipher_rsa_receiver = PKCS1_OAEP.new(receiver_public_key)
        encrypted_by_receiver = cipher_rsa_receiver.encrypt(encrypted_by_sender)

        aes_key = pin.encode().ljust(32, b'\0')
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(encrypted_by_receiver, AES.block_size)
        final_encrypted_data = cipher_aes.encrypt(padded_data)

        response = HttpResponse(final_encrypted_data, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="encrypted_file.enc"'
        return response


    return render(request, 'main/encrypt.html',{
        'usernames': User.objects.values_list('username', flat=True)
    })
