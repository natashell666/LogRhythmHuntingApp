from datetime import datetime


class MISPEvent:
    def __init__(self, misp_event):
        self.attrs = []
        self.misp_event = misp_event
        self.start_time = datetime.now().timestamp()
