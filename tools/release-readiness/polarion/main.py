# import setup  <This can be commented if default .pylero file is created, else we need to import from setup>
import time

import config as cf
import export_comp_data_to_sheets as ects
import export_to_sheets as ets
from extract_from_polarion import polarian_data

print("---Connecting to Polarion---")


def main():
    config = cf.Config()
    config.load()
    pol_obj = polarian_data()

    print("\n-----Extracting from Polarion-----")
    res = []

    data = pol_obj.extract_data(config)
    print("\n Printing type ", type(data))
    print("\nData :", data)
    print("\nFirst part :", data[0])
    print("\nSecond part : ", data[1])
    res.append(data[0])

    print("\n---Exporting in sheets")
    sheets_obj = ets.ExportData(config)
    tier_row_count = sheets_obj.export_sheets(data[0], config, data[1])
    print("\nReturned tier sheet row count is :", tier_row_count)

    time.sleep(30)
    print("\n-----Extracting component wise data from Polarion-----")
    component_data = pol_obj.extract_component_data(config)
    print("\n Printing type of component data", type(component_data))
    print("\nComponent data :", component_data)
    res.append(component_data)

    print("Exporting component data to chart")
    sheets_obj = ects.ExportData(config)
    comp_row_count = sheets_obj.export_compdata_to_sheets(component_data, config)
    print("\nReturned component sheet row count is :", comp_row_count)

    print("\n-----Extracting component wise total testcase from Polarion-----")
    component_total_tc = pol_obj.extract_component_total_tc(config)
    print("\nPrinting type of component total testcases", type(component_total_tc))
    print("\nComponent wise total testcases :", component_total_tc)
    res.append(component_total_tc)

    print("Calculating tier-delta of automation in a week")
    sheets_obj = ets.ExportData(config)
    delta_data = sheets_obj.generate_automation_delta(config, tier_row_count)
    res.append(delta_data)

    print("Calculating component-delta of automation in a week")
    comp_sheets_obj = ects.ExportData(config)
    comp_delta_data = comp_sheets_obj.generate_automation_delta(config, comp_row_count)
    res.append(comp_delta_data)

    print("Fetch all automated tests whose status is NOT Inactive")
    all_component_data = pol_obj.extract_component_allstatus_data(config)
    print("\n Printing type of component data", type(all_component_data))
    print("\nComponent data :", all_component_data)
    res.append(all_component_data)

    print("Generating delta between the approved and notapproved autoamted tests")
    delta_data = pol_obj.generate_delta_automated_all_status(config, res[1], res[5])
    res.append(delta_data)

    print("\nResults: ", res)
    return res


if __name__ == "__main__":
    main()
