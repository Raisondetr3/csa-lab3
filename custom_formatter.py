import logging

class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.msg.startswith(" "):
            record.msg = record.msg[1:]
        return super().format(record)
