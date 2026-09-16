"""VPC Flow Log parsing — the boundary where AWS text becomes our data.

A flow log line is a fixed-order string of fourteen fields. Everything
downstream trusts the dictionary this produces, so the parser has to be strict
about what it accepts and honest (None) about what it cannot read. No AWS
credentials are needed: only the parsing is exercised.
"""

import pytest

boto3 = pytest.importorskip("boto3")

from vpc_flow_collector import VPCFlowCollector


ACCEPTED = ("2 123456789012 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 "
            "20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK")
REJECTED = ("2 123456789012 eni-1235b8ca123456789 172.31.9.69 172.31.9.12 "
            "49761 3389 6 20 4249 1418530010 1418530070 REJECT OK")
NO_DATA = "2 123456789012 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA"


@pytest.fixture
def collector():
    # The constructor only stores the stream name; nothing is called on AWS here.
    return VPCFlowCollector("test-stream")


def test_an_accepted_flow_parses_into_typed_fields(collector):
    row = collector.parse_flow_log(ACCEPTED)

    assert row is not None
    assert row["src_ip"] == "172.31.16.139"
    assert row["dst_ip"] == "172.31.16.21"
    assert row["dst_port"] == 22 and isinstance(row["dst_port"], int)
    assert row["protocol"] == 6, "6 is TCP"
    assert row["bytes"] == 4249 and row["packets"] == 20
    assert row["action"] == "ACCEPT"
    assert row["end_time"] > row["start_time"]
    assert "collected_at" in row


def test_a_rejected_flow_keeps_its_action(collector):
    assert collector.parse_flow_log(REJECTED)["action"] == "REJECT"


def test_a_nodata_line_is_refused_rather_than_guessed(collector):
    """Dashes are not ports. Returning None is the honest answer."""
    assert collector.parse_flow_log(NO_DATA) is None


def test_a_truncated_line_is_refused(collector):
    assert collector.parse_flow_log("2 123456789012 eni-1 172.31.16.139") is None


def test_an_empty_line_is_refused(collector):
    assert collector.parse_flow_log("") is None
    assert collector.parse_flow_log("   ") is None


def test_a_non_numeric_port_is_refused(collector):
    broken = ACCEPTED.replace(" 20641 ", " not-a-port ")
    assert collector.parse_flow_log(broken) is None


def test_extra_trailing_fields_do_not_break_parsing(collector):
    """AWS adds fields to newer flow-log versions; the first fourteen still hold."""
    row = collector.parse_flow_log(ACCEPTED + " extra1 extra2")
    assert row is not None and row["action"] == "ACCEPT"
