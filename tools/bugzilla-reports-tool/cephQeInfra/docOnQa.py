	#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 25 05:24:11 2021

@author: skanta
"""
import sys
import time
from jinja2 import Environment, FileSystemLoader,select_autoescape
from jinja_markdown import MarkdownExtension
from cephQeInfra import commonFunctions
import datetime
import pytz

sys.path.append(".")
from helpers import *
import bugzilla




class DocOnQaCls():
    
    
    def get_modified_date(self,bug):
        history=bug.get_history_raw()
        bug_changes=history["bugs"][0]["history"]
        for list_change in bug_changes:
            after_change=list_change["changes"][0]["added"]
            if(after_change == "ON_QA"):
                onQa_date=list_change["when"]
                
        return(onQa_date)
             
        
        
    
    
    def get_Doc_bugs(self):
        
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME,"DocBugs")
        IST = pytz.timezone('Asia/Kolkata')
        current_time = datetime.datetime.now(IST)
        now=datetime.datetime.strptime(str(current_time),"%Y-%m-%d %H:%M:%S.%f+05:30")
        g.needInfo_clean_rows(2,5,50) 
        bugs = get_OnQa_doc_bugs()
        target=""
        items=[]

        for  idx, bug in enumerate(bugs):
           row = 5 + idx
           column = 4
           g.update_sheet(
                    row,
                    column,
                        (
                            f'=HYPERLINK("https://bugzilla.redhat.com/show_bug'f'.cgi?id={bug.bug_id}", "{bug.bug_id}")'
                        )
                     )
           g.update_sheet(row, column+1, bug.summary)
           g.update_sheet(row, column+2, bug.severity)
           g.update_sheet(row, column+3, bug.version)
           target_list=[*bug.target_release]
           target=target.join(target_list)
           OnQaDateNotFormat=commonFunctions.get_modified_date(bug)
           converted = datetime.datetime.strptime(
                str(OnQaDateNotFormat), "%Y%m%dT%H:%M:%S")
           age=(now - converted).days
           g.update_sheet(row, column+4, *bug.target_release)
           time.sleep(10)
           an_item = dict(bug_id=bug.bug_id,summary=bug.summary,
                   severity=bug.severity,qaContact=bug.qa_contact,
                   version=bug.version,target_release=target,age=age
                   )
           items.append(an_item)
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("Doc_onqa.html")
        html = template.render(items=items)
           
        return html   
        
        

