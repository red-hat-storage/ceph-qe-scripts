import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from jinja2 import Environment, FileSystemLoader, select_autoescape
from jinja_markdown import MarkdownExtension


class htmlPrep():
    html=''
    def set_html_data(self,items,flag,htmlFilename="email.html"):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        print(project_dir)
        template_dir=os.path.join(project_dir, "../bugzilla-reports-tool-master/html_template")
       
        print(template_dir)
        
        jinja_env = Environment(extensions=[MarkdownExtension],
                                loader=FileSystemLoader(template_dir),
                                autoescape=select_autoescape(["html", "xml"]),
        )
        #template = jinja_env.get_template("new_need_info_file.html")
        template = jinja_env.get_template(htmlFilename)
        if (flag == "Doc_QA"):
            self.html = template.render(doc_items=items)
        if(flag == "needInfo"):
            self.html = template.render(items=items)
        
        
    def send_email(self,start_time):
        print(self.html)
        sender = "skanta@redhat.com"
        recipients = ["skanta@redhat.com"]

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Bugzilla action items on QE -Auto generated at "\
                    + start_time +"[IST]"
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        part1 = MIMEText(self.html, "html")
        msg.attach(part1)
        

        try:
            s = smtplib.SMTP("localhost")
            s.sendmail(sender, recipients, msg.as_string())
            s.quit()
            print(
                "Results have been emailed to {recipients}".format(
                    recipients=recipients
                )
            )

        except Exception as e:
            print("\n")
            #log.exception(e)
    
    
    
    
    









