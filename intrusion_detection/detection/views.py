from django.shortcuts import render
from detection.models import intrusionLog

def packet_logs(request):
    logs = intrusionLog.objects.all()  # Fetch latest 50 logs
    return render(request, 'detection/packet_logs.html', {'logs': logs})
