from gspread import utils


class Chart_json:
    """Represents a chart in a sheet."""

    def __init__(self, title, domain, range, anchorCell, sheetId, chart_sheetId):
        """
        range is list of lists [type,range=[]]
        :param title:           Title of the chart
        :param domain:          Cell range of the desired chart domain in the form of tuple of tuples
        :param range:          Cell ranges of the desired ranges in the form of list of tuple of tuples
        :param anchor_cell:     Position of the left corner of the chart in the form of cell address or cell object
        :param sheetId:      ID of the particular sheet
        :param chart_sheetId: ID of the sheet which contains the charts representing the data
        """
        self._title = title
        self._domain = domain
        self._range = range
        self._anchorCell = anchorCell
        self._sheetId = sheetId
        self._request = dict()
        self._chart_sheetId = chart_sheetId

    def Create_json(self, id):
        """Function to create chart"""
        self._request["addChart"] = dict()

        self._request["addChart"]["chart"] = dict()
        self._request["addChart"]["chart"]["chartId"] = id
        self._request["addChart"]["chart"]["spec"] = dict()
        self._request["addChart"]["chart"]["spec"]["title"] = self._title.capitalize()
        self._request["addChart"]["chart"]["spec"]["backgroundColor"] = dict(
            {
                "red": 0.93,
                "green": 0.93,
                "blue": 0.93,
            }
        )
        self._request["addChart"]["chart"]["spec"]["basicChart"] = dict()
        self._request["addChart"]["chart"]["spec"]["basicChart"]["chartType"] = "COMBO"
        self._request["addChart"]["chart"]["spec"]["basicChart"][
            "legendPosition"
        ] = "RIGHT_LEGEND"
        self._request["addChart"]["chart"]["spec"]["basicChart"]["domains"] = list()
        self._request["addChart"]["chart"]["spec"]["basicChart"]["series"] = list()
        self._request["addChart"]["chart"]["spec"]["basicChart"][
            "stackedType"
        ] = "STACKED"
        self._request["addChart"]["chart"]["spec"]["basicChart"]["axis"] = list()
        self._request["addChart"]["chart"]["spec"]["basicChart"]["axis"] = dict(
            {
                "position": "BOTTOM_AXIS",
                "title": "Tier Classification/Day",
                "titleTextPosition": {"horizontalAlignment": "CENTER"},
            }
        )
        self._request["addChart"]["chart"]["spec"]["basicChart"]["headerCount"] = 1

        self._request["addChart"]["chart"]["spec"]["basicChart"][
            "totalDataLabel"
        ] = dict(
            {
                "type": "DATA",
            }
        )
        self._request["addChart"]["chart"]["position"] = dict()
        self._request["addChart"]["chart"]["position"]["overlayPosition"] = dict()
        self._request["addChart"]["chart"]["position"]["overlayPosition"][
            "anchorCell"
        ] = dict()
        domain_body = dict(
            {
                "domain": {
                    "sourceRange": {
                        "sources": [
                            utils.a1_range_to_grid_range(
                                self._domain, sheet_id=self._sheetId
                            )
                        ]
                    }
                }
            }
        )
        self._request["addChart"]["chart"]["spec"]["basicChart"]["domains"].append(
            domain_body
        )

        for range in self._range:
            chart_type = range[0]
            range_source = range[1]
            range_body = dict(
                {
                    "series": {
                        "sourceRange": {
                            "sources": [
                                utils.a1_range_to_grid_range(
                                    range_source, sheet_id=self._sheetId
                                )
                            ]
                        }
                    },
                    "type": chart_type,
                    "color": range[2],
                }
            )
            if chart_type == "COLUMN":
                range_body["dataLabel"] = dict(
                    {
                        "type": "DATA",
                        "textFormat": dict({"fontSize": 10}),
                        "placement": "BELOW",
                    }
                )
            self._request["addChart"]["chart"]["spec"]["basicChart"]["series"].append(
                range_body
            )
        anchell_body = dict()
        json_body = utils.a1_range_to_grid_range(
            self._anchorCell, sheet_id=self._chart_sheetId
        )
        anchell_body["sheetId"] = json_body["sheetId"]
        anchell_body["rowIndex"] = json_body["endRowIndex"]
        anchell_body["columnIndex"] = json_body["endColumnIndex"]
        self._request["addChart"]["chart"]["position"]["overlayPosition"][
            "anchorCell"
        ] = anchell_body
        return self._request

    def Update_json(self, chart_id):
        """Function to update chart"""
        self._request["updateChartSpec"] = dict()
        self._request["updateChartSpec"]["spec"] = dict()
        self._request["updateChartSpec"]["chartId"] = chart_id
        self._request["updateChartSpec"]["spec"]["title"] = self._title.capitalize()
        self._request["updateChartSpec"]["spec"]["backgroundColor"] = dict(
            {"red": 0.93, "green": 0.93, "blue": 0.93}
        )
        self._request["updateChartSpec"]["spec"]["basicChart"] = dict()
        self._request["updateChartSpec"]["spec"]["basicChart"]["chartType"] = "COMBO"
        self._request["updateChartSpec"]["spec"]["basicChart"][
            "legendPosition"
        ] = "RIGHT_LEGEND"
        self._request["updateChartSpec"]["spec"]["basicChart"]["domains"] = list()
        self._request["updateChartSpec"]["spec"]["basicChart"]["series"] = list()
        self._request["updateChartSpec"]["spec"]["basicChart"][
            "stackedType"
        ] = "STACKED"
        self._request["updateChartSpec"]["spec"]["basicChart"]["axis"] = list()
        self._request["updateChartSpec"]["spec"]["basicChart"]["axis"] = dict(
            {
                "position": "BOTTOM_AXIS",
                "title": "Tier Classification/Day",
                "titleTextPosition": {"horizontalAlignment": "CENTER"},
            }
        )
        self._request["updateChartSpec"]["spec"]["basicChart"]["headerCount"] = 1

        self._request["updateChartSpec"]["spec"]["basicChart"]["totalDataLabel"] = dict(
            {
                "type": "DATA",
            }
        )
        domain_body = dict(
            {
                "domain": {
                    "sourceRange": {
                        "sources": [
                            utils.a1_range_to_grid_range(
                                self._domain, sheet_id=self._sheetId
                            )
                        ]
                    }
                }
            }
        )
        self._request["updateChartSpec"]["spec"]["basicChart"]["domains"].append(
            domain_body
        )

        for range in self._range:
            chart_type = range[0]
            range_source = range[1]
            range_body = dict(
                {
                    "series": {
                        "sourceRange": {
                            "sources": [
                                utils.a1_range_to_grid_range(
                                    range_source, sheet_id=self._sheetId
                                )
                            ]
                        }
                    },
                    "type": chart_type,
                    "color": range[2],
                }
            )
            if chart_type == "COLUMN":
                range_body["dataLabel"] = dict(
                    {
                        "type": "DATA",
                        "textFormat": dict({"fontSize": 10}),
                        "placement": "BELOW",
                    }
                )
            self._request["updateChartSpec"]["spec"]["basicChart"]["series"].append(
                range_body
            )
        anchell_body = dict()
        json_body = utils.a1_range_to_grid_range(
            self._anchorCell, sheet_id=self._sheetId
        )
        anchell_body["sheetId"] = json_body["sheetId"]
        anchell_body["rowIndex"] = json_body["endRowIndex"]
        anchell_body["columnIndex"] = json_body["endColumnIndex"]
        return self._request

    def update_position(self, chart_id, sheet_id):
        """Function to update chart position in a particular sheet"""
        req = dict()
        req["updateEmbeddedObjectPosition"] = dict()
        req["updateEmbeddedObjectPosition"]["objectId"] = chart_id
        req["updateEmbeddedObjectPosition"]["newPosition"] = dict()
        req["updateEmbeddedObjectPosition"]["fields"] = "*"
        req["updateEmbeddedObjectPosition"]["newPosition"]["overlayPosition"] = dict()
        anchell_body = dict()
        json_body = utils.a1_range_to_grid_range(
            self._anchorCell, sheet_id=self._sheetId
        )
        anchell_body["sheetId"] = json_body["sheetId"]
        anchell_body["rowIndex"] = json_body["endRowIndex"]
        anchell_body["columnIndex"] = json_body["endColumnIndex"]
        req["updateEmbeddedObjectPosition"]["newPosition"]["overlayPosition"][
            "anchorCell"
        ] = anchell_body
        return req
