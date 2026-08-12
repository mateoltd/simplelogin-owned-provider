"""Health check for a child supervised by log_wrapper.py."""

import argparse
import os
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("pid_file", type=Path)
args = parser.parse_args()
pid = int(args.pid_file.read_text().strip())
os.kill(pid, 0)
