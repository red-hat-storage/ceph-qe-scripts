#!/usr/bin/env python
from helpers import *

g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "component_distribution")

all_bugs = get_overall_backlog(version=BUGZILLA_VERSION_FLAG)
component_dict = filter_by_component(all_bugs)
for idx, comp in enumerate(component_dict):
    urgent_bugs = len(filter_by_severity(component_dict[comp], 'urgent'))
    high_bugs = len(filter_by_severity(component_dict[comp], 'high'))
    medium_bugs = len(filter_by_severity(component_dict[comp], 'medium'))
    low_bugs = len(filter_by_severity(component_dict[comp], 'low'))

    row = 2 + idx
    column = 1

    g.update_sheet(row, column, comp)
    g.update_sheet(row, column + 1, urgent_bugs)
    g.update_sheet(row, column + 2, high_bugs)
    g.update_sheet(row, column + 3, medium_bugs)
    g.update_sheet(row, column + 4, low_bugs)
