"""
Gzilla
"""

import argparse
from compiletools import execute_yaml

parser = argparse.ArgumentParser(description="gzilla")
parser.add_argument("filename", type=str, help="The yaml to execute.")

args = parser.parse_args()

execute_yaml(args.filename)
