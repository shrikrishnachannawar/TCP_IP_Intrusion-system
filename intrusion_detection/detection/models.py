from django.db import models

class intrusionLog(models.Model):
    timestamp=models.DateTimeField(auto_now_add=True)
    src_ip =models.GenericIPAddressField()
    dst_ip=models.GenericIPAddressField()
    protocol=models.CharField(max_length=10)
    packet_size=models.IntegerField()
    prediction=models.CharField(max_length=20)
    
    def __str__(self):
        return f"{self.timestamp}-{self.prediction}"
    
    