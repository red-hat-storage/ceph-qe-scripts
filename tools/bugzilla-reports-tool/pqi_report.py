#!/usr/bin/env python
from helpers import *
from datetime import datetime

now = datetime.today()
g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "PQI_report")

dev_backlog = get_dev_backlog(BUGZILLA_VERSION_FLAG)
new = filter_by_status(dev_backlog, 'NEW')
assigned = filter_by_status(dev_backlog, 'ASSIGNED')
post = filter_by_status(dev_backlog, 'POST')
modified = filter_by_status(dev_backlog, 'MODIFIED')

qe_backlog = get_qe_backlog()
g.insert_row(
    [
         now.strftime("%Y-%m-%d"), len(new), len(assigned),
         len(post), len(modified), len(qe_backlog)
    ]
)
