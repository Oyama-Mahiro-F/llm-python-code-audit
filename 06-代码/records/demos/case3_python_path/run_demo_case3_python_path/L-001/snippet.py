REPORT_DIR = "/var/app/reports"

def read_report(report_name):
    path = REPORT_DIR + "/" + report_name
    with open(path) as f:
        return f.read()
