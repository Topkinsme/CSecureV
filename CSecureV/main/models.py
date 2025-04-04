from django.db import models
from django.contrib.auth.hashers import make_password,check_password

class User(models.Model):
    user_id=models.CharField(max_length=10)
    username=models.CharField(max_length=20)
    password = models.CharField(max_length=128)
    public_key=models.CharField(max_length=128)
    private_key=models.CharField(max_length=128)


    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)



