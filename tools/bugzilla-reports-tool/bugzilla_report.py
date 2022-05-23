#!/usr/bin/env python
import datetime

from helpers import *
from config import *
import sys

temp = sys.stdout
sys.stdout = open(f'report_{PRODUCT}_status', 'w')
print("<html><body>")
print("<h3>Hi,</h3>")
print(f"<h3>This is the status of {PRODUCT} - bugs:</h3>")
print(f"<h1><u>{PRODUCT} {VERSION} Status</u></h1>")
report_new_arrivals()
report_resolved_bugs()
report_status_on_qa()
report_on_qa_blockers()
report_open_blockers()
report_open_candidate_blockers()

print("<p></p>")
print("<h3>Thanks</h3>")
print("</body></html>")
sys.stdout = temp
raport_file = open(f'report_{PRODUCT}_status')
report = raport_file.read()
raport_file.close()
now = datetime.datetime.now()
date = "%s %s %s" % (now.strftime("%b"), now.strftime("%d"), now.year)
send_email(
    gmail_user, gmail_pwd, [mail_to],
    f"Bugzilla report [{date}] - {PRODUCT} QE Status", report
)
