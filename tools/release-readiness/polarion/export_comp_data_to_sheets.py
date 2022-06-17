import datetime
import time
from re import S
from time import sleep

import google_sheet_chart
from chart import ChartJson
from gspread_formatting import *


class ExportData:
    """Module to export data to google sheet"""

    import gspread
    from gspread.exceptions import APIError, SpreadsheetNotFound, WorksheetNotFound

    def __init__(self, config=None) -> None:
        self.config = config
        self.gc = self.gspread.service_account(filename=config.GS_CREDENTIALS)

    def next_available_row(self, worksheet):
        """Function to get next available row in the google sheet"""
        str_list = list(filter(None, worksheet.col_values(1)))
        return str(len(str_list) + 1)

    def format_cell(self, bg={"red": 1, "green": 1, "blue": 1, "alpha": 1}):
        """Function to format cell with background in a sheet"""
        return {
            "horizontalAlignment": "CENTER",
            "backgroundColor": bg,
            "wrapStrategy": "WRAP",
            "borders": {
                "top": {"style": "SOLID", "width": 1},
                "bottom": {"style": "SOLID", "width": 1},
                "left": {"style": "SOLID", "width": 1},
                "right": {"style": "SOLID", "width": 1},
            },
        }

    def format_cell_no_bg(self):
        """Function to format without background in a sheet"""
        return {
            "horizontalAlignment": "CENTER",
            "wrapStrategy": "WRAP",
            "borders": {
                "top": {"style": "SOLID", "width": 1},
                "bottom": {"style": "SOLID", "width": 1},
                "left": {"style": "SOLID", "width": 1},
                "right": {"style": "SOLID", "width": 1},
            },
        }

    def export_compdata_to_sheets(self, data, config):
        """
        Function to export component wise data to new worksheet.
        Args:
            data : component-wise polarion data extracted from the portal
            config: config details
        """
        base_query = config.url + r"/#/workitems?query="
        try:
            sh = self.gc.open(config.file_name)
            ws = sh.worksheet("polarion_component_data_TIER")
        except self.SpreadsheetNotFound:
            print(
                "Spreadsheets in not exits or you have not shared with client email id"
            )
        except self.WorksheetNotFound:
            ws = sh.add_worksheet("polarion_component_data_TIER", rows=100, cols=100)

        if self.next_available_row(ws) == "1":
            self.update_and_check(ws, "A1", "Component")
            ws.format("A1", self.format_cell())
            set_column_width(ws, "A", 150)
            self.update_and_check(ws, "A2", "Tier Classification")
            ws.format("A2", self.format_cell())
            self.update_and_check(ws, "A3", "Day")
            ws.format("A3", self.format_cell())
            self.update_and_check(ws, "B3", "Label")
            ws.format("B3", self.format_cell())
            start_c = "C"

            for component_filter_key in config.component_filter.keys():
                curr_c = start_c
                print("\n Comp keys:", component_filter_key)
                for val in config.component_filter[component_filter_key]["values"]:
                    # Pausing for accomodating the no. of writes per minute.
                    time.sleep(5)
                    print("Component: ", val)
                    print("Current C value:", curr_c)

                    for tier_val in config.tags:
                        print("Tier val:", tier_val)
                        self.update_and_check(ws, curr_c + "2", tier_val)
                        curr_c = self.get_next_col(curr_c)
                        print("current 'c' inside loop:", curr_c)

                    print("Started merging of cells")
                    ws.merge_cells(start_c + "1:" + self.get_prev_col(curr_c) + "1")
                    self.update_and_check(ws, start_c + "1", val)
                    ws.merge_cells(start_c + "3:" + self.get_prev_col(curr_c) + "3")
                    self.update_and_check(ws, start_c + "3", "Automated")
                    ws.format(
                        start_c + "1:" + curr_c + "3",
                        self.format_cell(bg=config.comp_color[val]),
                    )
                    start_c = self.get_next_col(curr_c)
                    curr_c = self.get_next_col(curr_c)

        row_count = self.next_available_row(ws)
        day = str(datetime.datetime.now()).split(".")[0]
        label = (
            str(datetime.datetime.now().month) + "/" + str(datetime.datetime.now().day)
        )
        print("\nRow count :", row_count)
        self.update_and_check(ws, "A" + row_count, day)

        self.update_and_check(ws, "B" + row_count, label)

        start_c = "C"
        for comp in data.keys():
            print("#######################")
            print("Component :", comp)
            for val in data[comp]:
                print("Value in comp:", val)
                self.update_and_check(ws, start_c + row_count, val)
                start_c = self.get_next_col(start_c)
                print("start_c inner for loop:", start_c)
            start_c = self.get_next_col(start_c)
            print("start_c outer for loop:", start_c)
        start_c = self.get_prev_col(start_c)
        print("start_c outside loop:", start_c)
        ws.format("A" + row_count + ":" + start_c + row_count, self.format_cell())

        return row_count

    def generate_automation_delta(self, config, row):
        """
        Function to generate automation delta by comparing the previous row content to the current row content.
        config: config details
        row: current row updated in the sheet.
        """
        try:
            sh = self.gc.open(config.file_name)
            ws = sh.worksheet("polarion_component_data_TIER")
        except self.SpreadsheetNotFound:
            print(
                "Spreadsheets in not exits or you have not shared with client email id"
            )
        curr_values_list = ws.row_values(int(row))
        prev_values_list = ws.row_values(int(row) - 1)
        print(
            "\nCurrent row type and details:", type(curr_values_list), curr_values_list
        )
        print(
            "\nPrevious row type and details:", type(prev_values_list), prev_values_list
        )
        curr_row_details = curr_values_list[2:]
        prev_row_details = prev_values_list[2:]
        diff_list = []
        for cur, prev in zip(curr_row_details, prev_row_details):
            if cur != "":
                diff_list.append(int(cur) - int(prev))
        print("\n Diff list :", diff_list)
        print(len(diff_list))
        diff_dict_created = {}
        start = end = 0

        comp_details = config.component_filter["Automation"]["values"]
        for each in comp_details:
            diff_dict_created[each] = []
            end += len(config.tags)
            diff_dict_created[each] = diff_list[start:end]
            start += len(config.tags)
        return diff_dict_created

    def color_and_border(self, wc, range, color):
        """Create border with color."""
        try:
            wc.format(range, self.format_cell(self.config.colors_for_summary[color]))
        except self.APIError:
            print("sleep for a min")
            sleep(65)
            self.gc = self.gspread.service_account(filename=self.config.GS_CREDENTIALS)
            sh = self.gc.open(self.config.file_name)
            wc = sh.worksheet("polarion_component_data_TIER")
            wc.format(range, self.format_cell(self.config.colors_for_summary[color]))

    def border(self, wc, range):
        "Create border without color."
        try:
            wc.format(range, self.format_cell_no_bg())
        except self.APIError:
            print("sleep for a min")
            sleep(65)
            self.gc = self.gspread.service_account(filename=self.config.GS_CREDENTIALS)
            sh = self.gc.open(self.config.file_name)
            wc = sh.worksheet("polarion_component_data_TIER")
            wc.format(range, self.format_cell_no_bg())

    def get_next_col(self, start_c):
        """Function to get next column in the sheet."""
        if len(start_c) > 1:
            # pass
            if start_c[-1] == "Z":
                start_c = str(chr(ord(start_c[0]) + 1)) + str((len(start_c) - 1) * "A")
            else:
                start_c = start_c[0 : len(start_c) - 1] + chr(ord(start_c[-1]) + 1)
        else:
            if start_c == "Z":
                start_c = "AA"
                return start_c
            start_c = chr(ord(start_c) + 1)
        return start_c

    def get_prev_col(self, start_c):
        """Function to get previous column in the sheet."""
        if start_c == "AA":
            start_c = "Z"
            return start_c
        if len(start_c) == 1:
            start_c = chr(ord(start_c) - 1)
        else:
            if start_c[-1] == "A":
                start_c = str(chr(ord(start_c[0]) - 1)) + str((len(start_c) - 1) * "Z")
            else:
                start_c = start_c[0 : len(start_c) - 1] + chr(ord(start_c[-1]) - 1)
        return start_c

    def update_and_check(self, wc, range, val):
        """Function to update a cell and check if api throws no. of writes per min error."""
        try:
            wc.update_acell(range, val)
        except self.APIError:
            print("sleep for a min")
            sleep(65)
            self.gc = self.gspread.service_account(filename=self.config.GS_CREDENTIALS)
            sh = self.gc.open(self.config.file_name)
            wc = sh.worksheet("polarion_component_data_TIER")
            wc.update_acell(range, val)

    def merge_and_check(self, wc, range):
        """Function to merge cells and check if api throws no. of writes per min error."""
        try:
            wc.merge_cells(range)
        except self.APIError:
            print("sleep for a min")
            sleep(65)
            self.gc = self.gspread.service_account(filename=self.config.GS_CREDENTIALS)
            sh = self.gc.open(self.config.file_name)
            wc = sh.worksheet("polarion_component_data_TIER")
            wc.merge_cells(range)

    def bold_(self, wc, range):
        """Function to bold the text content of a cell."""
        try:
            wc.format(range, {"textFormat": {"bold": True}})
        except self.APIError:
            print("sleep for a min")
            sleep(65)
            self.gc = self.gspread.service_account(filename=self.config.GS_CREDENTIALS)
            sh = self.gc.open(self.config.file_name)
            wc = sh.worksheet("polarion_component_data_TIER")
            wc.format(range, {"textFormat": {"bold": True}})
