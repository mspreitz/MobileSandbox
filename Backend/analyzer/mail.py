import sys
sys.path.append('../')
import smtplib
import sys
import traceback
import psycopg2
import DynamicAnalysis.settings as settings
import config.misc_config as misc_config

try:
    conn = psycopg2.connect(dbname=misc_config.SQL_DB, user='ms_user', password='2HmUKLvf')
except:
    traceback.print_exc()
    print "Unable to connect to the database"
    sys.exit(1)
db = conn.cursor()

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