from django.db import models


class FileUpload(models.Model):
    file = models.FileField(upload_to='')
    title = models.CharField()


class Queue(models.Model):
    id = models.AutoField(primary_key=True)
    sha256 = models.CharField(primary_key=True, max_length=64)
    path = models.CharField(max_length=100)
    fileName = models.CharField(max_length=60)
    status = models.CharField(max_length=7)
    type = models.CharField(max_length=10)


class Metadata(models.Model):
    id = models.AutoField(primary_key=True)
    md5 = models.CharField(max_length=32)
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64)
    issuer = models.CharField(max_length=120)


class Classifier(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_classifier', db_index=True)
    feature = models.CharField(max_length=300, db_index=True)
    ranking = models.CharField(max_length=300)
    #class Meta:
    #    db_table = u'app_classifier'


class ClassifiedApp(models.Model):
    id = models.AutoField(primary_key=True)
    sample_id = models.ForeignKey('Sample', related_name='sample_id_2_classified_app', db_index=True)
    score = models.CharField(max_length=300, db_index=True)
    malicious = models.IntegerField()
    #class Meta:
    #    db_table = u'app_classified_app'