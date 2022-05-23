#!/usr/bin/env python
from helpers import *
from datetime import datetime

REGRESSION = 15
BLOCKER = 30
TEST_BLOCKER = 20


now = datetime.today()
g = gapi.GoogleSpreadSheetAPI(SPREADSHEET_NAME, "average_quality_score_data")

all_bugs = get_overall_backlog()
# if len(all_bugs) > 0:
#     all_qa_scores = [get_quality_score(b) for b in all_bugs]
#     all_qa_scores = list(filter(lambda a: a != -1, all_qa_scores))
#     avarage_qa_score = 100 - sum(all_qa_scores) / len(all_qa_scores)
g.insert_row(
    [now.strftime("%Y-%m-%d"), len(all_bugs)]
)
