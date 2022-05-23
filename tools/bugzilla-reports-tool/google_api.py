"""
API module to interact with Google spreadsheets
In order to create a new spreadsheet, share the spreadsheet with the
'client_email' in your credentials json file with write permissions.


"""
import os
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import time


class GoogleSpreadSheetAPI(object):
    """
    A class to interact with Google Spreadsheet
    """
    def __init__(self, spreadsheet_name, sheet_name):
        # use creds to create a client to interact with the Google Drive API
        scope = [
            'https://spreadsheets.google.com/feeds',
            'https://www.googleapis.com/auth/drive'
        ]
        google_api = os.path.expanduser('~/.gapi/google_api_secret.json')
        creds = ServiceAccountCredentials.from_json_keyfile_name(
            google_api, scope
        )
        client = gspread.authorize(creds)
        self.sheet = client.open(spreadsheet_name).worksheet(sheet_name)

    def update_sheet(self, row, col, value):
        """
        Updates a row:col in a given spreadsheet
        """
        self.sheet.update_cell(row, col, value)

    def print_sheet(self):
        list_of_hashes = self.sheet.get_all_records()
        print(list_of_hashes)

    def get_cell_value(self, row, col):
        return self.sheet.cell(row, col).value

    def insert_row(self, value, row_index=2):
        return self.sheet.insert_row(value, row_index)

    def clean_rows(self, column, initial_row, end_row):
        for row in range(initial_row, end_row + 1):
            if self.get_cell_value(row, column):
                self.update_sheet(row, column, "")
                self.update_sheet(row, column + 1, "")
                self.update_sheet(row, column + 6, "")
                self.update_sheet(row, column + 7, "")
                self.update_sheet(row, column + 8, "")
                self.update_sheet(row, column + 9, "")
            else:
                break
    def needInfo_clean_rows(self, column, initial_row, end_row):
        for row in range(initial_row, end_row + 1):
            if self.get_cell_value(row, column):
                self.update_sheet(row, column, "")
                self.update_sheet(row, column + 1, "")
                self.update_sheet(row, column + 2, "")
                self.update_sheet(row, column + 3, "")
                self.update_sheet(row, column + 4, "")
                self.update_sheet(row, column + 5, "")
                self.update_sheet(row, column + 6, "")
                self.update_sheet(row, column + 7, "")
                self.update_sheet(row, column + 8, "")
                time.sleep(10)
            else:
                break
        