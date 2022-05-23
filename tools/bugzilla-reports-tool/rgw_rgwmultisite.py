from jinja2 import Environment, FileSystemLoader,select_autoescape
from jinja_markdown import MarkdownExtension
import os
import time
from helpers import *
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cephQeInfra import commonFunctions
from datetime import datetime
import pytz
import sys




items=[]
target=""

UTC = pytz.utc
IST = pytz.timezone('Asia/Kolkata')
datetime_ist = datetime.now(IST)
start_time=datetime_ist.strftime("%d %b %Y %H:%M")
current_time = str(datetime.now(IST))
now=datetime.strptime(str(current_time),"%Y-%m-%d %H:%M:%S.%f+05:30")
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
template_dir=os.path.join(project_dir, "bugzilla-reports-tool/html_template")

g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "New_Bugs")
bugs=get_rgw_rgwmultisite_bugs()
for  idx, bug in enumerate(bugs):
    chdate=str(bug.last_change_time)
    converted = datetime.strptime(chdate, "%Y%m%dT%H:%M:%S")
    age=(now - converted).days
    an_item = dict(bug_id=bug.bug_id,summary=bug.summary,qa_contact=bug.qa_contact,
                   component=bug.component,severity=bug.severity,target_release=bug.target_release,age=age
                   )
    items.append(an_item)

jinja_env = Environment(extensions=[MarkdownExtension],
    loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
template = jinja_env.get_template("Rgw_RgwMultisite.html")
html = template.render(items=items)

sender = "ceph-qe-infra@redhat.com"
recipients = ["ceph-qe-BZ-tracker@redhat.com"]

msg = MIMEMultipart("alternative")
msg["Subject"] = "ON_QA bugs for RGW & RGW-Multisite -Auto generated at "\
                    + start_time +"[IST]"
msg["From"] = sender
msg["To"] = ", ".join(recipients)
part1 = MIMEText(html, "html")
msg.attach(part1)
        

try:
            s = smtplib.SMTP("localhost")
            s.sendmail(sender, recipients, msg.as_string())
            s.quit()
            print(
                "Results have been emailed to {recipients}".format(
                    recipients=recipients
                )
            )

except Exception as e:
            print("\n")
            log.exception(e)
print("done")

