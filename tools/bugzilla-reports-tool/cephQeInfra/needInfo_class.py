#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 25 05:24:11 2021

@author: skanta
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jun 25 05:24:11 2021

@author: skanta
"""
import datetime
import sys
import time

from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja_markdown import MarkdownExtension

sys.path.append(".")
import pytz
from cephQeInfra import commonFunctions
from helpers import *


class needInfoCls():
     
    def get_NeedInfo_bugs(self):
        
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        
        g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "Need Info")
        IST = pytz.timezone('Asia/Kolkata')
        current_time = str(datetime.datetime.now(IST))
        now=datetime.datetime.strptime(str(current_time),"%Y-%m-%d %H:%M:%S.%f+05:30")
        all_team_members = all_members()
        # Deleting the rows in google sheets
        g.needInfo_clean_rows(2,5,50)  
        bugs = get_needinfos_bugs()
        items=[]
        target=""
        for  idx, bug in enumerate(bugs):
            
            requestee_name=commonFunctions.get_requestee_name(bug.flags)
            row = 5 + idx
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
            g.update_sheet(row, column+2, bug.status)
            g.update_sheet(row, column+3, bug.component)
            g.update_sheet(row, column+4, bug.severity)
            g.update_sheet(row, column+5, requestee_name)
            g.update_sheet(row, column+6, bug.version)
            
            target_list=[*bug.target_release]
            target=target.join(target_list)
            g.update_sheet(row, column+7, *bug.target_release)
            needInfo_time=str(commonFunctions.get_needInfo_creation_date(bug.flags))
            converted = datetime.datetime.strptime(
                needInfo_time, "%Y%m%dT%H:%M:%S")
            age=(now - converted).days
            g.update_sheet(row, column+8, (now - converted).days)
            time.sleep(10)
            an_item = dict(bug_id=bug.bug_id,summary=bug.summary, status=bug.status,
                   component=bug.component,severity=bug.severity,
                   requestee_name=requestee_name,version=bug.version,
                   target_release=target,age=age
                   )
            items.append(an_item)
            
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("need_info.html")
        html = template.render(items=items)
            
        return html

      
