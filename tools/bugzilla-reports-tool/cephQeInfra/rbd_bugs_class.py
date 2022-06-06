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
import datetime
import sys
import time

from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja_markdown import MarkdownExtension

sys.path.append(".")
import pytz
from helpers import *


class rbdBugsCls():
     
    def getRbdBugs(self):
        
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        IST = pytz.timezone('Asia/Kolkata')
        current_time = str(datetime.datetime.now(IST))
        now=datetime.datetime.strptime(str(current_time),"%Y-%m-%d %H:%M:%S.%f+05:30")
        bugs = get_action_item_rbd_rbd_mirror_bugs()
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("Rbd.html")
        html = template.render(items=bugs)
            
        return html

      
