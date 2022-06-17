from urllib import request

from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

READONLY_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
]


class MakeCharts:
    """Module that works with charts."""

    def __init__(self, credentials) -> None:
        self.cred = None
        self.cred = Credentials.from_service_account_file(
            credentials, scopes=DEFAULT_SCOPES
        )

    def create_chart(self, requests, spreadsheet_id):
        """Module to create chart."""
        try:
            service = build("sheets", "v4", credentials=self.cred)

            body = {"requests": requests}
            # Call the Sheets API
            sheet = service.spreadsheets()
            result = sheet.batchUpdate(
                spreadsheetId=spreadsheet_id, body=body
            ).execute()
        except HttpError as err:
            print(err)

    def update_chart(self, requests, spreadsheet_id):
        """Module to update chart."""
        try:
            service = build("sheets", "v4", credentials=self.cred)

            body = {"requests": requests}
            # Call the Sheets API
            sheet = service.spreadsheets()
            result = sheet.batchUpdate(
                spreadsheetId=spreadsheet_id, body=body
            ).execute()
            return result
        except HttpError as err:
            print(err)

    def hide_rows(self, spreadsheet_id, range, sheet_id):
        """Module to hide rows."""
        try:
            service = build("sheets", "v4", credentials=self.cred)
            requests = dict()
            requests["updateDimensionProperties"] = dict()
            requests["updateDimensionProperties"]["properties"] = dict()
            requests["updateDimensionProperties"]["properties"]["hiddenByUser"] = True
            requests["updateDimensionProperties"]["range"] = dict(
                {
                    "sheetId": sheet_id,
                    "dimension": "ROWS",
                    "startIndex": range[0],
                    "endIndex": range[1],
                }
            )
            requests["updateDimensionProperties"]["fields"] = "*"
            body = {"requests": requests}
            # Call the Sheets API
            sheet = service.spreadsheets()
            result = sheet.batchUpdate(
                spreadsheetId=spreadsheet_id, body=body
            ).execute()
            return result
        except HttpError as err:
            print(err)
