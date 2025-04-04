from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login',views.login,name='login'),
    path('signup',views.signup,name='signup'),
    path('main-page',views.main_page,name='main_page'),
    path('profile',views.profile,name='profile'),
    path('decrypt',views.decrypt,name='decrypt'),
    path('encrypt',views.encrypt,name='encrypt'),
    path('logout',views.logout,name='logout'),
]
