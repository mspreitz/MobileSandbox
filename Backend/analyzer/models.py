from django.db import models


class FileUpload(models.Model):
    file = models.FileField(upload_to='')
    title = models.CharField()