#!/usr/bin/env python
from helpers import *

SEVERITY_SCORE = {
    'urgent': 35,
    'high': 20,
    'medium': 10,
    'low': 5,
    'unspecified': 0
}
REGRESSION = 15
BLOCKER = 30
TEST_BLOCKER = 20


class BugScore(object):
    def __init__(self, bz):
        self.bug = bzapi.getbug(bz.bug_id)

    def calc_regression(self):
        score = 0
        if 'Regression' in self.bug.keywords:
            score = REGRESSION
        return score

    def calc_blocker(self):
        score = 0
        if self.bug.get_flag_status('blocker') is not None:
            score = BLOCKER
        return score

    def calc_test_blocker(self):
        score = 0
        if 'TestBlocker' in self.bug.keywords:
            score = TEST_BLOCKER
        return score

    def calc_severity(self):
        return SEVERITY_SCORE[self.bug.severity]

    def calc_score(self):
        score = []
        score.append(self.calc_regression())
        score.append(self.calc_blocker())
        score.append(self.calc_severity())
        score.append(self.calc_test_blocker())
        return sum(score)

    def update(self):
        score = self.calc_score()
        qa_wb = self.bug.cf_qa_whiteboard
        qa_score = get_quality_score(self.bug)
        if qa_score != -1:
            if qa_score != score:
                qa_wb = qa_wb.replace(
                    QUALITY_IMPACT + str(qa_score), QUALITY_IMPACT + str(score)
                )
                bzapi.update_bugs(
                    self.bug.id, {'cf_qa_whiteboard': '\n' + qa_wb, 'nomail': 1}
                )
        else:
            bzapi.update_bugs(
                self.bug.id, {
                    'cf_qa_whiteboard': (
                        qa_wb + '\n' + QUALITY_IMPACT + str(score)
                    ), 'nomail': 1
                }
            )


last_hour_bugs = get_changed_bugs_in_the_past_x_time()
for bug in last_hour_bugs:
    bz = BugScore(bug)
    bz.update()
