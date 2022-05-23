#!/usr/bin/env python
from helpers import *
from datetime import datetime

now = datetime.today()
g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "arrivals_vs_resolved_data")

new_bugs = get_new_arrivals(
    changed_from=now.strftime("%Y-%m-%d"), changed_to=now.strftime("%Y-%m-%d")
)
resolved_bugs = get_resolved_bugs(
    changed_from=now.strftime("%Y-%m-%d"), changed_to=now.strftime("%Y-%m-%d")
)
verified_bugs = get_verified_bugs(
    changed_from=now.strftime("%Y-%m-%d"), changed_to=now.strftime("%Y-%m-%d")
)
blocker_bugs = get_blocker_arrivals(
    changed_from=now.strftime("%Y-%m-%d"), changed_to=now.strftime("%Y-%m-%d")
)

g.insert_row(
    [
         now.strftime("%Y-%m-%d"), len(new_bugs), len(resolved_bugs),
         len(verified_bugs), len(blocker_bugs)
    ]
)
