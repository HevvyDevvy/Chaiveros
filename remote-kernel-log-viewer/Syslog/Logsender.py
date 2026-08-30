import logging
import logging.handlers
import time

# Configure logging
syslog_handler = logging.handlers.SysLogHandler(address=('your_syslog_server', 514))
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
syslog_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(syslog_handler)

# Example function to log kernel events
def log_kernel_event(event_message):
    logger.info(event_message)

# Simulate logging kernel events
if __name__ == "__main__":
    while True:
        log_kernel_event("Encryption key created.")
        time.sleep(10)  # Log every 10 seconds
