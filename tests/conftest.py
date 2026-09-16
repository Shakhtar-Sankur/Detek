"""Test environment: a region and credentials that go nowhere.

The collectors build their boto3 clients in `__init__`, and boto3 refuses to
build a client without a region — so even parsing a log line, which never calls
AWS, needs these set. They are deliberately invalid: if a test ever did reach
the network, it would fail loudly rather than touch a real account.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")

# The modules sit at the repository root, not in a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
