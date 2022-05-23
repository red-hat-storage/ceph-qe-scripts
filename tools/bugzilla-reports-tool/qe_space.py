#!/usr/bin/env python
from helpers import *
from datetime import datetime

now = datetime.today()
g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "QE Space")

bugs_per_member = list()
bug_to_member = dict()
layered_product_bug_to_member = dict()
for member in TEAM_MEMBERS:
    bug_to_member[member] = {
        'product_bugs': None,
        'layered_bugs': None,
    }
    qe_backlog = get_bugs_per_member(
        member, BUGZILLA_PRODUCT, version=BUGZILLA_VERSION_FLAG
    )
    bug_to_member[member]['product_bugs'] = qe_backlog if qe_backlog else []
    if LAYERED_PRODUCT:
        layered_qe_backlog = get_bugs_per_member(member, LAYERED_PRODUCT)
        bug_to_member[member][
            'layered_bugs'
        ] = layered_qe_backlog if layered_qe_backlog else []
row = 4
col = 2
for member, bugs in bug_to_member.items():
    product_bugs = bugs['product_bugs']
    layered_product_bugs = bugs['layered_bugs']
    if not product_bugs and not layered_product_bugs:
        continue
    bugs_distribution = dict()
    bugs_distribution['urgent'] = filter_by_severity(product_bugs, 'urgent')
    bugs_distribution['high'] = filter_by_severity(product_bugs, 'high')
    bugs_distribution['medium'] = filter_by_severity(product_bugs, 'medium')
    bugs_distribution['low'] = filter_by_severity(product_bugs, 'low')
    idx = col
    g.update_sheet(row, col, member)
    for severity, bugs_by_severity in bugs_distribution.items():
        idx += 1
        if len(bugs_by_severity) > 0:
            bug_ids = [str(bug.id) for bug in bugs_by_severity]
            link = get_bug_url_link(bug_ids)
            g.update_sheet(
                row, idx,
                f'=HYPERLINK("{str(link)}", "{len(bugs_by_severity)}")'
            )
        else:
            if not g.get_cell_value(row, idx) == '-':
                g.update_sheet(row, idx, '-')
    if layered_product_bugs:
        bug_ids = [str(bug.id) for bug in layered_product_bugs]
        link = get_bug_url_link(bug_ids)
        g.update_sheet(
            row,
            idx + 1,
            f'=HYPERLINK("{str(link)}", '
            f'"{len(layered_product_bugs)}")'
        )
    else:
        if not g.get_cell_value(row, idx + 1) == '-':
            g.update_sheet(row, idx + 1, '-')
    row += 1
for row in range(row, 30 + 1):
    if g.get_cell_value(row, col):
        g.update_sheet(row, col, "")
        g.update_sheet(row, col + 1, "")
        g.update_sheet(row, col + 2, "")
        g.update_sheet(row, col + 3, "")
        g.update_sheet(row, col + 4, "")
        g.update_sheet(row, col + 5, "")
    else:
        break

g.update_sheet(1, 1, f'Last update: {now.strftime("%Y-%m-%d %H:%M")}')