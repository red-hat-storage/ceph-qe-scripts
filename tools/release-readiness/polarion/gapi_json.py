from xml import dom

import pygsheets
from pygsheets.address import Address, GridRange
from pygsheets.utils import format_addr


def _get_range(wc, start_label, end_label=None, rformat="A1"):

    grange = GridRange(worksheet=wc, start=start_label, end=end_label)
    if rformat == "A1":
        return grange.label
    else:
        return grange.to_json()


data = {
    "spec": {
        "title": None,
        "basicChart": {
            "chartType": "LINE",
            "legendPosition": "None",
            "domains": [],
            "headerCount": 1,
            "series": [],
        },
        "titleTextFormat": {"fontFamily": "Roboto"},
        "fontName": "Roboto",
    },
    "position": {"overlayPosition": {"anchorCell": {"rowIndex": 0, "columnIndex": 10}}},
}


def make_json(wc1, title, row_count, domain, ranges):
    """Function to create a basic template with assigned rows and columns position."""
    domains = []

    domains.append(
        {
            "domain": {
                "sourceRange": {
                    "sources": [
                        {
                            "startRowIndex": 3,
                            "endRowIndex": row_count,
                            "startColumnIndex": 0,
                            "endColumnIndex": 0,
                        }
                    ]
                }
            }
        }
    )
    data["spec"]["title"] = title
    data["spec"]["basicChart"]["domains"] = domains
    ranges_request_list = []
    for i in range(len(config.tags)):
        req = {
            "series": {
                "sourceRange": {
                    "sources": [
                        {
                            "startRowIndex": i + 1,
                            "endRowIndex": row_count,
                            "startColumnIndex": 1,
                            "endColumnIndex": 0,
                        }
                    ]
                }
            },
        }
        ranges_request_list.append(req)
    data["spec"]["basicChart"]["series"] = ranges_request_list
    return data
