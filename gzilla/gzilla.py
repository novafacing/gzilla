"""
Gzilla
"""

import argparse
from compiletools import execute_yaml
import coloredlogs
import logging

logger = logging.getLogger(__name__)
coloredlogs.install(fmt="%(name)s [%(levelname)s]: %(message)s", level="DEBUG")
logger.setLevel("DEBUG")

parser = argparse.ArgumentParser(description="gzilla")
parser.add_argument("filename", type=str, help="The yaml to execute.")

args = parser.parse_args()

execute_yaml(args.filename)
