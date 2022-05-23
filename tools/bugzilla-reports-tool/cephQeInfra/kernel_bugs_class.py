#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 7 04:07 2022

@author: hmaheswa
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat May 7 04:07 2022

@author: hmaheswa
"""
import sys
import time
import datetime
from jinja2 import Environment, FileSystemLoader,select_autoescape
from jinja_markdown import MarkdownExtension
sys.path.append(".")
from helpers import *
import pytz



class kernelBugsCls():
     
    def getKernelBugs(self):
        
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")

        IST = pytz.timezone('Asia/Kolkata')
        current_time = str(datetime.datetime.now(IST))
        now=datetime.datetime.strptime(str(current_time),"%Y-%m-%d %H:%M:%S.%f+05:30")
        bugs = get_kernel_bugs()
        items=[]
        for  idx, bug in enumerate(bugs):
            an_item = dict(bug_id=bug.bug_id,summary=bug.summary,qa_contact=bug.qa_contact,
                   component=bug.component,status=bug.status,flags=[flag['name'] for flag in bug.flags],version=bug.version,target_release=bug.target_release
                   )
            items.append(an_item)
            
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("Kernel.html")
        html = template.render(items=items)
            
        return html

      
