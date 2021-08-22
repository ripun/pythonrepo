#!/usr/bin/python3

####LogParserElb.py: Python script to parse elb logs and analyze them based on elb logs fields

__author__      = "Ripunjay Godhani"


import re
import os
from pathlib import Path, PureWindowsPath
import glob
import sys
import platform
import sysconfig

fields = [
    "type", "time", "elb", "client_ip", "client_port", "target_ip",
    "target_port", "request_processing_time", "target_processing_time",
    "response_processing_time", "elb_status_code", "target_status_code",
    "received_bytes", "sent_bytes", "request_type", "request_url",
    "request_protocol", "user_agent_browser", "ssl_cipher", "ssl_protocol",
    "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn",
    "matched_rule_priority", "request_creation_time", "actions_executed",
    "redirect_url", "lambda_error_reason", "target_port_list",
    "target_status_code_list", "classification", "classification_reason"
]

regex = r'([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\s]+?)\" \"([^\s]+)\" \"([^ ]*)\" \"([^ ]*)\"'

def ParseLogFile():
    resultDict = {}
    directories = []
    for f in p.iterdir():
        if f.is_dir():
            directories.append(f)
    for item in directories:
        files = glob.glob(str(item)+ logpattern)
        for file in files:
            with open(file, 'r') as log:
                line = log.readline()
                while line:
                    line_split = re.split(regex, line)
                    line_split = line_split[1:len(line_split) - 1]
                    index = fields.index(field)
                    if len(line_split) != 0:
                        val = line_split[index]
                        resultDict.setdefault(val, 0)
                        resultDict[val] += 1
                    line = log.readline()
    return resultDict

if __name__ == '__main__':
    field = str(input("Please enter ELB field type to be anlayzed: "))
    topn = int(input("How many top N records you need, please enter: "))
    p = Path(input("Enter the directory "))
    #p = Path("C:\\homepath\\elblogs")
    osp = sys.platform
    if osp == "linux":
       logpattern = '/*.log'
    else:
       logpattern = '\*.log'

    result = ParseLogFile()
    result=sorted(result.items(), reverse=True, key=lambda y: y[1])[:topn]
    print(result)

