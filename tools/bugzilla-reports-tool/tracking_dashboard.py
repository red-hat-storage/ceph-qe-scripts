#!/usr/bin/env python
import time
from helpers import *
import datetime

now = datetime.datetime.now()
g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "QE tracking dashboard")

deployment_blockers = sort_by_pm_score(get_deployment_blockers())
for idx, bug in enumerate(deployment_blockers):
    row = 6 + idx
    column = 2
    g.update_sheet(
        row,
        column,
        (
            f'=HYPERLINK("https://bugzilla.redhat.com/show_bug'
            f'.cgi?id={bug.bug_id}", "{bug.bug_id}")'
        )
    )
    g.update_sheet(row, column+1, bug.summary)
    g.update_sheet(row, column+6, bug.status)
    g.update_sheet(row, column+7, bug.component)
    g.update_sheet(row, column+8, bug.severity)
    converted = datetime.datetime.strptime(
        bug.creation_time.value, "%Y%m%dT%H:%M:%S"
    )
    g.update_sheet(row, column + 9, (now - converted).days)

g.clean_rows(2, 6 + len(deployment_blockers), 15)
# Sleep to ensure no exception will raise from Google API due to writes limit
time.sleep(40)

feature_blockers = sort_by_pm_score(get_feature_blockers())
for idx, bug in enumerate(feature_blockers):
    row = 19 + idx
    column = 2
    g.update_sheet(
        row,
        column,
        (
            f'=HYPERLINK("https://bugzilla.redhat.com/show_bug'
            f'.cgi?id={bug.bug_id}", "{bug.bug_id}")'
        )
    )
    g.update_sheet(row, column+1, bug.summary)
    g.update_sheet(row, column+6, bug.status)
    g.update_sheet(row, column+7, bug.component)
    g.update_sheet(row, column+8, bug.severity)
    converted = datetime.datetime.strptime(
        bug.creation_time.value, "%Y%m%dT%H:%M:%S"
    )
    g.update_sheet(row, column + 9, (now - converted).days)

g.clean_rows(2, 19 + len(feature_blockers), 28)
# Sleep to ensure no exception will raise from Google API due to writes limit
time.sleep(60)

stability_bugs = sort_by_pm_score(get_stability_bugs())
for idx, bug in enumerate(stability_bugs):
    row = 32 + idx
    column = 2
    g.update_sheet(
        row,
        column,
        (
            f'=HYPERLINK("https://bugzilla.redhat.com/show_bug'
            f'.cgi?id={bug.bug_id}", "{bug.bug_id}")'
        )
    )
    g.update_sheet(row, column+1, bug.summary)
    g.update_sheet(row, column+6, bug.status)
    g.update_sheet(row, column+7, bug.component)
    g.update_sheet(row, column+8, bug.severity)
    converted = datetime.datetime.strptime(
        bug.creation_time.value, "%Y%m%dT%H:%M:%S"
    )
    g.update_sheet(row, column + 9, (now - converted).days)

g.clean_rows(2, 32 + len(stability_bugs), 46)

time.sleep(60)

stability_bugs = sort_by_pm_score(get_testing_blockers())
for idx, bug in enumerate(stability_bugs):
    row = 51 + idx
    column = 2
    g.update_sheet(
        row,
        column,
        (
            f'=HYPERLINK("https://bugzilla.redhat.com/show_bug'
            f'.cgi?id={bug.bug_id}", "{bug.bug_id}")'
        )
    )
    g.update_sheet(row, column+1, bug.summary)
    g.update_sheet(row, column+6, bug.status)
    g.update_sheet(row, column+7, bug.component)
    g.update_sheet(row, column+8, bug.severity)
    converted = datetime.datetime.strptime(
        bug.creation_time.value, "%Y%m%dT%H:%M:%S"
    )
    g.update_sheet(row, column + 9, (now - converted).days)

g.clean_rows(2, 61 + len(stability_bugs), 65)

g.update_sheet(1, 1, f'Last update: {now.strftime("%Y-%m-%d %H:%M")}')
