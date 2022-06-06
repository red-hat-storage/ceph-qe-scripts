# -*- coding: utf-8 -*-


"""
@author: skanta
"""

import datetime
import sys
import time

from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja_markdown import MarkdownExtension

sys.path.append(".")
import bugzilla
from cephQeInfra import commonFunctions
from helpers import *


class unspecified_severity_cls():
    def get_unspecified_severity_bugs(self):
        items=[]
        target=""

        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        bugs = get_unspec_sev_bugs()
        if (len(bugs) != 0):
            for  idx, bug in enumerate(bugs):
                target_list=[*bug.target_release]
                target=target.join(target_list)
                an_item = dict(bug_id=bug.bug_id,summary=bug.summary,
                        reporter=bug.creator,qaContact=bug.qa_contact,
                        component=bug.component,target_release=target
                        )
                items.append(an_item) 
               
            jinja_env = Environment(extensions=[MarkdownExtension],
                                        loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"]),
                )
            template = jinja_env.get_template("unspecified_severity.html")
            html = template.render(items=items)
               
            return html
        else:
            return None
