from django import forms
from multiupload.fields import MultiFileField
from .models import Attachment


class UploadForm(forms.Form):
    file = forms.FileField(label='Select a file')

class UploadFormMulti(forms.Form):
    # NOTE Max size right now: 10MB
    maxsize = 10*1024*1024
    attachments = MultiFileField(
        min_num=1,
        max_num=10,
        max_file_size=maxsize
    )
    def save(self, commit=True):
        instance = super(ContactForm, self).save(commit)
        for each in self.cleaned_data['files']:
            Attachment.objects.create(file=each, data=instance)
        return instance