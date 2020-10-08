import logging

class ColorLogger(logging.StreamHandler):
    def emit(self, record):
        try:
            color_start = {
                logging.DEBUG: "\033[2m",
                logging.WARNING: "\033[33m",
                logging.ERROR: "\033[31m",
                logging.CRITICAL: "\033[1;31m",
            }.get(record.levelno, "")

            color_end = "\033[0m"

            msg = self.format(record)
            stream = self.stream
            stream.write(color_start + msg + color_end + self.terminator)
            self.flush()
        except Exception as e:
            self.handleError(record)
