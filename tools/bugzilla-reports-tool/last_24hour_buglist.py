# -*- coding: utf-8 -*-

import datetime
import os
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytz
from cephQeInfra import commonFunctions
from helpers import *
from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja_markdown import MarkdownExtension

items=[]
target=""

UTC = pytz.utc
IST = pytz.timezone('Asia/Kolkata')
datetime_ist = datetime.now(IST)
start_time=datetime_ist.strftime("%d %b %Y %H:%M")

project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
template_dir=os.path.join(project_dir, "bugzilla-reports-tool/html_template")

g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "New_Bugs")
bugs=get_ceph_new_arrivals(5,"-24h")
for  idx, bug in enumerate(bugs):
    target_list=[*bug.target_release]
    target=target.join(target_list)
    blocker_status=commonFunctions.get_blocker_status(bug.flags)
    an_item = dict(bug_id=bug.bug_id,summary=bug.summary,reporter=bug.creator, status=bug.status,
                   component=bug.component,severity=bug.severity,
                   is_Blocker=blocker_status,
                   version=bug.version,target_release=target
                   )
    items.append(an_item)

jinja_env = Environment(extensions=[MarkdownExtension],
    loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
template = jinja_env.get_template("last_24hrs_bugs.html")
html1 = template.render(items=items)

bugs=get_rbd_rbd_mirror_bugs()
jinja_env = Environment(extensions=[MarkdownExtension],
    loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
template = jinja_env.get_template("rbd_red_hat_openshift_data_foundation.html")
html2 = template.render(items=bugs)

bugs=get_ceph_bugs()
jinja_env = Environment(extensions=[MarkdownExtension],
    loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
template = jinja_env.get_template("ceph_red_hat_openshift_data_foundation.html")
html3 = template.render(items=bugs)


sender = "ceph-qe-infra@redhat.com"
recipients = ["ceph-qe@redhat.com"]

msg = MIMEMultipart("mixed")
msg["Subject"] = "Last 24 hrs Reported bugs -Auto generated at "\
                    + start_time +"[IST]"
msg["From"] = sender
msg["To"] = ", ".join(recipients)
table1 = MIMEText(html1, "html")
table2 = MIMEText(html2, "html")
table3 = MIMEText(html3, "html")
msg.attach(table1)
msg.attach(table2)
msg.attach(table3)

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
            print(e)
print("done")
