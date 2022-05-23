# -*- coding: utf-8 -*-


"""
Created on Fri Aug 06 05:24:11 2021

@author: skanta
"""

import sys
import time
from jinja2 import Environment, FileSystemLoader,select_autoescape
from jinja_markdown import MarkdownExtension
import datetime

sys.path.append(".")
from helpers import *
import bugzilla
from cephQeInfra import commonFunctions



class QaAckCls():
    def get_QaAck_bugs(self):
        items=[]
        target=""

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        bugs = get_onAck_bugs()
        
        for  idx, bug in enumerate(bugs):
            target_list=[*bug.target_release]
            target=target.join(target_list)
            an_item = dict(bug_id=bug.bug_id,summary=bug.summary,
                   qaContact=bug.qa_contact,component=bug.component,
                   target_release=target,status=bug.status,severity=bug.severity
                   )
            items.append(an_item) 
           
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("qaAck.html")
        html = template.render(items=items)
           
        return html   
