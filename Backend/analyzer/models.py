from django.db import models

# NOTE: Please do only user lowercase column names. postgresql is a bit hard to use with uppercase column names
# NOTE See http://stackoverflow.com/questions/37910287/sql-hint-to-reference-a-column


class FileUpload(models.Model):
    file = models.FileField(upload_to='./')
    title = models.CharField(max_length=200)

class Attachment(models.Model):
    data = models.ForeignKey(FileUpload, verbose_name='Uploaded Data Blob')
    file = models.FileField('Attachment', upload_to='attachments')


class Queue(models.Model):
    id = models.AutoField(primary_key=True)
    filename = models.CharField(max_length=255) # The name given by the user
    sha256 = models.CharField(max_length=64)
    path = models.CharField(max_length=255)
    status = models.CharField(max_length=10)
    type = models.CharField(max_length=10)
    starttime = models.DateTimeField(auto_now_add=True)
    retry = models.IntegerField()


class Metadata(models.Model):
    id = models.AutoField(primary_key=True)
    filename = models.CharField(max_length=255) # The name given by the user
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