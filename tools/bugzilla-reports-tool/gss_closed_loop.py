#!/usr/bin/env python
from helpers import *
from datetime import datetime

g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "GSS closed loop")
now = datetime.today()

open_gss = get_gss_closed_loop("qe_test_coverage?")
acked_gss = get_gss_closed_loop("qe_test_coverage+")
naked_gss = get_gss_closed_loop("qe_test_coverage-")
g.insert_row(
    [now.strftime("%Y-%m-%d"), len(open_gss), len(acked_gss), len(naked_gss)]
)

g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "component_distribution")
all_gss_bugs = (open_gss + acked_gss + naked_gss)
component_dict = filter_by_component(all_gss_bugs, verify_status=False)
for idx, comp in enumerate(component_dict):
    urgent_bugs = len(filter_by_severity(component_dict[comp], 'urgent'))
    high_bugs = len(filter_by_severity(component_dict[comp], 'high'))
    medium_bugs = len(filter_by_severity(component_dict[comp], 'medium'))
    low_bugs = len(filter_by_severity(component_dict[comp], 'low'))

    row = 21 + idx
    column = 1

    g.update_sheet(row, column, comp)
    g.update_sheet(row, column + 1, urgent_bugs)
    g.update_sheet(row, column + 2, high_bugs)
    g.update_sheet(row, column + 3, medium_bugs)
    g.update_sheet(row, column + 4, low_bugs)
