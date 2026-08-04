"""ARIA copilot compatibility package.

The runtime entry point is ``aria.copilot.engine``. This package intentionally
avoids eager engine construction so utility and contract modules can be imported
without initialising live clients.
"""

__all__: list[str] = []
