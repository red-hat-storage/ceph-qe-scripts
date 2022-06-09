usage = """Parse Polarion stats from test suites.


In the context of CephCI,
    path     full path to suites directory

  Example:
    python parse_polarion_data.py <path> --exclude luminous,nautilus

Usage:
  parse_polarion_data.py <path> [--exclude <str>]
  parse_polarion_data.py -h | --help

Options:
  --exclude <pattern>   patterns to be excluded
  -h --help             Show this screen

"""
import logging
import sys
from os import walk
from os.path import join

from docopt import docopt
from yaml import dump, safe_load


def is_excluded(regex, string):
    """Return true if one of the excluded pattern matches.

    Args:
        regex: patterns for comparison
        string
    Returns:
        boolean True if matches else False
    """
    for exc in regex:
        if exc in string:
            return True
    return False


def retrieve_polarion_data(file_string):
    """Retrieve polarion data

    Return Test cases
    - with multiple Ids along with test case name, file
    - with no Ids along with test case name, file

          - test:
              name: Install ceph pre-requisites
              desc: installation of ceph pre-requisites
              module: install_prereq.py
              abort-on-fail: true

    Args:
        file_string: file path
    """

    multiple_ids = []
    missing_ids = []
    good = []
    _total = 0

    with open(file_string, "r") as fs:
        print(file_string)
        ts = safe_load(fs)
        for tc in ts["tests"]:
            _tc = tc["test"]
            print(_tc)
            if not _tc or "install_prereq.py" in _tc.get("module", "NO_MODULE_DEFINED"):
                continue
            _total += 1

            tc_name = _tc.get("name", f"NO-TESTNAME-{file_string}")

            if not _tc.get("polarion-id"):
                missing_ids.append(tc_name)
                continue
            pol_ids = _tc["polarion-id"]
            pol_ids = pol_ids.split(",")

            if len(pol_ids) > 1:
                multiple_ids.append({tc_name: pol_ids})
            else:
                good.append({tc_name: pol_ids[-1]})

    return {
        "multiple_ids": multiple_ids,
        "missing_ids": missing_ids,
        "good": good,
        "total": _total,
    }


if __name__ == "__main__":
    logging.basicConfig(
        handlers=[logging.StreamHandler(sys.stdout)],
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
    )

    _args = docopt(usage)
    suite_path = _args["<path>"]
    excludes = None
    if _args.get("--exclude"):
        excludes = _args["--exclude"]
        excludes = excludes.split(",")

    test_suites = []
    test_data = {}
    total_count = 0
    missing_id_count = 0
    multiple_id_count = 0

    for _root, _dir, _files in walk(suite_path):
        if not _files:
            continue
        if excludes and is_excluded(excludes, _root):
            continue

        for _file in _files:
            if ".yaml" in _file:
                __file = join(_root, _file)
                test_suites.append(__file)
                _data = retrieve_polarion_data(__file)
                total_count += _data["total"]
                missing_id_count += len(_data["missing_ids"])
                multiple_id_count += len(_data["multiple_ids"])

                test_data.update({__file: retrieve_polarion_data(__file)})
    logging.info("\n".join(test_suites))
    logging.info(test_data)

    test_data.update(
        {
            "total_test_cases": total_count,
            "missing_polarion_id_count": missing_id_count,
            "testcases_with_multiple_ids": multiple_id_count,
        }
    )

    with open("polarion_data.yaml", "w") as outfile:
        dump(test_data, outfile, indent=4, default_flow_style=False)
