# utils/logger.py

import logging
import os
from pathlib import Path
from datetime import datetime

def get_logger(name: str):

    # Create a logger object with the given name
    logger = logging.getLogger(name)

    # If this logger was already set up before, just return it
    # This prevents duplicate log messages
    if logger.handlers:
        return logger

    # Set the minimum level of messages to show
    # DEBUG < INFO < WARNING < ERROR < CRITICAL
    logger.setLevel(logging.INFO)

    # --- Console Handler ---
    # This prints log messages to your terminal
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Format: [TIME] LEVEL  name — message
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    # --- File Handler ---
    # This saves log messages to a file in your logs/ folder
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # File name includes today's date e.g. pipeline_20240315.log
    log_file = log_dir / f"pipeline_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Attach both handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger