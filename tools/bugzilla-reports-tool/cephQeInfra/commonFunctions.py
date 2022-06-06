# -*- coding: utf-8 -*-

# Get the Requstee name from the flags

from helpers import *


def get_requestee_name(flag_list):
    all_team_members = all_members()
    all_team_members = [x[:-1] for x in all_team_members]
    for request in flag_list:
        if 'requestee' in request.keys():
            mailId=request['requestee']
            split_id=mailId.split("@")
            if split_id[0] in all_team_members:
                return split_id[0]
            
            
            
def  get_blocker_status(flag_list):
    for flag in flag_list:
        if flag['name']=='blocker':
            return flag['status']
    return " "    


               
def get_needInfo_creation_date(flag_list):
    for flag in flag_list:
        if flag['name'] == 'needinfo':
            latest_needInfo_date=flag['modification_date']
    return latest_needInfo_date
        
def get_modified_date(bug):
        history=bug.get_history_raw()
        bug_changes=history["bugs"][0]["history"]
        for list_change in bug_changes:
            #after_change=list_change["changes"][0]["added"]
            bug_changes=list_change["changes"]
            for bug_change_status in bug_changes:
                if(bug_change_status["added"] == "ON_QA"):
                    OnQa_Date=list_change["when"]
        return OnQa_Date         