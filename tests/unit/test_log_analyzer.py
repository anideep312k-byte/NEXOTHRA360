"""Log analyzer tests."""
from kavach360.analyzers import LogAnalyzer


def test_cloudtrail():
    a = LogAnalyzer()
    line = '{"eventName":"CreateUser","userIdentity":{"userName":"root"},"sourceIPAddress":"1.2.3.4","eventTime":"2024-01-01T00:00:00Z","eventSource":"iam.amazonaws.com"}'
    r = a.parse_line(line)
    assert r.format == "cloudtrail"


def test_access_log():
    a = LogAnalyzer()
    line = '1.2.3.4 - - [01/Jan/2024:00:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl"'
    r = a.parse_line(line)
    assert r.format == "access"


def test_syslog():
    a = LogAnalyzer()
    line = "<34>1 2024-01-01T00:00:00Z host app 123 - - message"
    r = a.parse_line(line)
    assert r.format == "rfc5424"
