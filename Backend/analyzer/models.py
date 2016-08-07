from django.db import models


class FileUpload(models.Model):
    file = models.FileField(upload_to='./')
    title = models.CharField(max_length=200)

class Attachment(models.Model):
    data = models.ForeignKey(FileUpload, verbose_name='Uploaded Data Blob')
    file = models.FileField('Attachment', upload_to='attachments')


class Queue(models.Model):
    id = models.AutoField(primary_key=True)
    sha256 = models.CharField(max_length=64)
    path = models.CharField(max_length=100)
    fileName = models.CharField(max_length=60)
    status = models.CharField(max_length=10)
    type = models.CharField(max_length=10)


class Metadata(models.Model):
    id = models.AutoField(primary_key=True)
    filename = models.CharField(max_length=300)
    md5 = models.CharField(max_length=32)
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64)
    issuer = models.CharField(max_length=120)
    username = models.CharField(max_length=300)
    status = models.CharField(max_length=10)


class Classifier(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.CharField(max_length=300)
    feature = models.CharField(max_length=300, db_index=True)
    ranking = models.CharField(max_length=300)


class ClassifiedApp(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.CharField(max_length=300)
    score = models.CharField(max_length=300)
    malicious = models.IntegerField()