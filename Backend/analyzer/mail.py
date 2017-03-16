import sys
sys.path.append('../')
import smtplib
import DynamicAnalysis.settings as settings
import textwrap

def sendNotification(email, sha256):
    if email != "":
        SERVER = "localhost"

        FROM = settings.SENDERS_MAIL
        TO = email

        SUBJECT = "Your analysis is finished!"

        TEXT = """Hello, \n
        the analysis of your submitted sample is finished now. In order to view the report\n
        please visit the following link.\n\n
        %s%s\n\n
        Best Regards\n
        MobileSandbox Team"""  % (settings.BASE_URL, sha256)

        message = textwrap.dedent("""\
        From: %s
        To: %s
        Subject: %s

        %s
        """ % (FROM, TO, SUBJECT, TEXT))

        # Send the mail

        server = smtplib.SMTP(SERVER)
        server.sendmail(FROM, TO, message)
        server.quit()

#sendNotification("jah-bru@bruzzzla.de", "faewfasdkfdksafsllfasfasfasfasfasaa")
