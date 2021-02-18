import os, sys, logging

# Retrieve package logger
log = logging.getLogger(__package__)
log.setLevel(logging.DEBUG)

# Configure stream logging
formatter = logging.Formatter("%(message)s")
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
log.addHandler(handler)

