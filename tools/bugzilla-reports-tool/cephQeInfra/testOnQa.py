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
from collections import defaultdict

class TestOnQaCls():
    
    def get_test_OnQa_bugs(self):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool/html_template")
        
        all_team_members = all_members()
        all_team_members = [x[:-1] for x in all_team_members]
        #Varibale decleration
        target=""
        version_list = set()
        bug_to_targetRel=defaultdict(lambda: defaultdict(list))
        items=[]
        count_buglist=[]
        bug_list=[]
        
        for member in all_team_members:
            bugs = get_ceph_bugs_per_member(member)
            if (len(bugs) != 0):
                for  idx, bug in enumerate(bugs):
                    target_list=[*bug.target_release]
                    target=target.join(target_list)
                    bug_to_targetRel[member][target].append(bug.bug_id)
    

        for name, info in bug_to_targetRel.items():
            for key in info:
                version_list.add(key)
                
        version_list = sorted(version_list) 
        reporter_versions=list()
        
        for QaContact, info in bug_to_targetRel.items():
    
            bug_count=0
            count_buglist=[]
            for ver in version_list:
                bug_list=[]
                if ver in info.keys():
                    bug_count = len(info[ver])
                    bug_list = info[ver]
                else:
                    bug_count = 0
                    buglist = []
                count_buglist.append([bug_count,bug_list,ver])              
            an_item = dict(name=QaContact,detils=count_buglist)
            items.append(an_item) 
        jinja_env = Environment(extensions=[MarkdownExtension],
                                    loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
            )
        template = jinja_env.get_template("test_onQA.html")
        html = template.render(columns=version_list,items=items)
        return html  
            
