from django.http import HttpResponse
from django.shortcuts import render,redirect
from django.contrib import messages
from .models import User
import random
import rsa
import hashlib
from cryptography.fernet import Fernet
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
        (public_key, private_key) = rsa.newkeys(2048)
        user.private_key=private_key.save_pkcs1().decode('utf-8')
        user.public_key=public_key.save_pkcs1().decode('utf-8')
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
    if request.method == 'POST':
        reciever_id = request.session.get('user')
        sender_username = request.POST.get('sender-username')
        uploaded_file = request.FILES.get('file-upload')
        print("request.FILES:", request.FILES)
        file_data = uploaded_file.read().decode('utf-8')

        received_hash,pin,file_data=file_data.split('λλλλλ')
        import ast
        pin_bytes = ast.literal_eval(pin)
        #print(pin,file_data)
        #print(type(pin_bytes))

        sender = User.objects.get(username=sender_username)
        receiver = User.objects.get(user_id=reciever_id)

        keytext=receiver.private_key.encode('utf-8')
        receiver_private_key = rsa.PrivateKey.load_pkcs1(keytext)
        try:
            pin=rsa.decrypt(pin_bytes, receiver_private_key)
        except:
            error="You are not the intended receipient of this file."
            return render(request, 'main/decrypt.html',{
                'usernames': User.objects.values_list('username', flat=True),
                'error':error
            })

        fernet = Fernet(pin)
        if file_data.startswith("b'") and file_data.endswith("'"):
            file_data = ast.literal_eval(file_data)  # Convert to real bytes
        else:
            file_data = file_data.encode('utf-8')

        decrypted_message=fernet.decrypt(file_data).decode()
        compute_hash= hashlib.sha256(decrypted_message.encode('utf-8')).hexdigest()

        if compute_hash==received_hash:
            response = HttpResponse(decrypted_message, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="decrypted_file.csv"'
            return response
        else:
            error="The file appears to be tampered or corrupted. Decryption aborted."
            return render(request, 'main/decrypt.html',{
                'usernames': User.objects.values_list('username', flat=True),
                'error':"The file appears to be tampered or corrupted. Decryption aborted."
            })
        #encrypted_message = fernet.encrypt()

        #encrypted_fernet_key = rsa.encrypt(pin, receiver_public_key)

        #msg=f"{encrypted_fernet_key}λλλλλ{encrypted_message}"



    return render(request, 'main/decrypt.html',{
        'usernames': User.objects.values_list('username', flat=True),
    })

def encrypt(request):
    if 'user' not in request.session:
        return redirect('login')
    if request.method == 'POST':
        sender_id = request.session.get('user')
        receiver_username = request.POST.get('receiver-username')
        uploaded_file = request.FILES.get('file-upload')

        pin=Fernet.generate_key()
        fernet = Fernet(pin)

        #get all keys
        sender = User.objects.get(user_id=sender_id)
        receiver = User.objects.get(username=receiver_username)

        keytext=receiver.public_key.encode('utf-8')
        #print(keytext,repr(keytext),repr(receiver.private_key),end="\n\n")
        receiver_public_key = rsa.PublicKey.load_pkcs1(keytext)
        file_data = uploaded_file.read().decode('utf-8')
        hash = hashlib.sha256(file_data.encode('utf-8')).hexdigest()
        encrypted_message = fernet.encrypt(file_data.encode('utf-8'))

        encrypted_fernet_key = rsa.encrypt(pin, receiver_public_key)


        msg=f"{hash}λλλλλ{encrypted_fernet_key}λλλλλ{encrypted_message}"

        response = HttpResponse(msg, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="encrypted_file.enc"'
        return response


    return render(request, 'main/encrypt.html',{
        'usernames': User.objects.values_list('username', flat=True)
    })
