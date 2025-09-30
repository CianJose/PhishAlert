from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.


class CustomUser(AbstractUser):
    phone = models.CharField(max_length=10, blank=True, null=True)

    def __str__(self):
        return self.username
    
           
class SuspiciousWebsite(models.Model):
    url = models.URLField(max_length=200, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        
        # Retrieve the numerical index by counting the existing objects with older timestamps
        index = SuspiciousWebsite.objects.filter(created_at__lte=self.created_at).count()
        return f"{index} - {self.url}"


class SqlinjectedWebsite(models.Model):
    url = models.URLField(max_length=200, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        
        # Retrieve the numerical index by counting the existing objects with older timestamps
        index = SqlinjectedWebsite.objects.filter(created_at__lte=self.created_at).count()
        return f"{index} - {self.url}"
    
    
class Enquiry(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)  
    email = models.EmailField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)
    def __str__(self):
        return self.name 
    
    
