import sys
sys.path.append('../')
import smtplib
import DynamicAnalysis.settings as settings

def sendNotification(email, sha256):
    if email != "":
        msg = """From: MobileSandbox <%s>
               To: <%s>
               Subject: Analysis is finished!
               Hello, \n
               the analysis of your submitted sample is finished now. In order to view the report\n
               please visit the following link.\n\n
               %s%s\n\n
               Best Regards\n
               MobileSandbox Team
               """ % (settings.SENDERS_MAIL, email, settings.BASE_URL, sha256)

        try:
            smtpObj = smtplib.SMTP('localhost')
            smtpObj.sendmail("%s", email, msg) % settings.SENDERS_MAIL
            print "Successfully sent email"
        except smtplib.SMTPException:
            print "Error: unable to send email"