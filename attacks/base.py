from abc import ABC, abstractmethod
import threading
import logging


class BaseAttack(ABC):
    """כל attack יורש מכאן — interface אחיד ל-CLI ול-logging/stats."""

    def __init__(self, iface: str, logger: logging.Logger = None):
        self.iface = iface
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._stop_event = threading.Event()
        self.stats = {}

    @abstractmethod
    def run(self):
        """הלוגיקה של ה-attack עצמו — כל attack ממש את זה."""
        raise NotImplementedError

    def stop(self):
        self._stop_event.set()
        self.logger.info("Stop signal received")

    @property
    def stopped(self):
        return self._stop_event.is_set()

    def print_summary(self):
        self.logger.info("=== Summary ===")
        for key, value in self.stats.items():
            self.logger.info("  %s: %s", key, value)

    # --- CLI integration points — כל attack דורס אם צריך ---

    @classmethod
    def configure_parser(cls, parser):
        """כל attack מוסיף כאן רק את הארגומנטים הייחודיים לו.
        -i/--iface ו- -v/--verbose כבר מגיעים מה-subparser הכללי."""
        pass

    @classmethod
    def from_args(cls, args):
        """בונה instance מתוך args שנאספו. ברירת מחדל: רק iface."""
        return cls(iface=args.iface)
