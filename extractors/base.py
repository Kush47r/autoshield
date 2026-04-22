# extractors/base.py

import pandas as pd
from utils.logger import get_logger

class BaseExtractor:
    """
    Every extractor inherits from this class.
    This means every extractor automatically gets
    the logger and the run() method for free.
    """

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)
        self.source_name = "unknown"

    def extract(self) -> pd.DataFrame:
        """
        This method MUST be overridden by every extractor.
        If someone forgets, they get a clear error message.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement extract()"
        )

    def run(self) -> pd.DataFrame:
        """
        Wraps extract() with logging and error handling.
        Every extractor calls run() not extract() directly.
        """
        import time

        self.logger.info(f"Starting extraction from [{self.source_name}]")
        start = time.time()

        try:
            df = self.extract()
            elapsed = round(time.time() - start, 2)
            self.logger.info(
                f"Finished [{self.source_name}] — "
                f"{len(df)} records in {elapsed}s"
            )
            return df

        except Exception as e:
            self.logger.error(
                f"Extraction failed for [{self.source_name}]: {e}"
            )
            raise