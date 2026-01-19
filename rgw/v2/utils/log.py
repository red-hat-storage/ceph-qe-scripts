import logging
import os
import sys
import tempfile

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))


def _get_writable_log_dir():
    """
    Get a writable log directory, falling back to user-writable locations if needed.
    Returns the path to a writable log directory.
    """
    # Try the default log directory first
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR, mode=0o755, exist_ok=True)
        if os.access(LOG_DIR, os.W_OK):
            return LOG_DIR
    except (OSError, PermissionError):
        pass

    # Fall back to user's home directory
    try:
        home_dir = os.path.expanduser("~")
        fallback_dir = os.path.join(home_dir, "rgw_test_logs")
        if not os.path.exists(fallback_dir):
            os.makedirs(fallback_dir, mode=0o755, exist_ok=True)
        if os.access(fallback_dir, os.W_OK):
            return fallback_dir
    except (OSError, PermissionError):
        pass

    # Last resort: use temp directory
    try:
        temp_dir = os.path.join(tempfile.gettempdir(), "rgw_test_logs")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, mode=0o755, exist_ok=True)
        if os.access(temp_dir, os.W_OK):
            return temp_dir
    except (OSError, PermissionError):
        pass

    # If all else fails, raise an error
    raise PermissionError(
        f"Failed to find or create a writable log directory. "
        f"Tried: {LOG_DIR}, ~/rgw_test_logs, and {tempfile.gettempdir()}/rgw_test_logs"
    )


def configure_logging(f_name="rgw_test", set_level="info"):

    set_level = logging.getLevelName(set_level.upper())
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

    # Get a writable log directory
    log_dir = _get_writable_log_dir()
    
    # Log which directory is being used (especially if it's a fallback)
    if log_dir != LOG_DIR:
        # Use stderr to avoid circular dependency with logging
        print(f"WARNING: Using fallback log directory: {log_dir} (default: {LOG_DIR} is not writable)", file=sys.stderr)

    c_fnane = os.path.join(log_dir, f_name + ".console.log")
    v_fname = os.path.join(log_dir, f_name + ".verbose.log")

    if os.path.exists(c_fnane):
        os.unlink(c_fnane)
    if os.path.exists(v_fname):
        os.unlink(v_fname)

    log = logging.getLogger()
    log.setLevel(logging.DEBUG)

    # file handler settings for verbose_file
    # logging_level is set to DEBUG
    try:
        file_handler = logging.FileHandler(v_fname)
        file_handler.setFormatter(formatter)
    except (OSError, PermissionError) as e:
        raise PermissionError(
            f"Failed to create log file '{v_fname}': {e}. "
            f"Please check write permissions for the log directory."
        )

    # handler settings for simple log file as well as console
    # logging level can be set for both the handlers
    try:
        file_handler2 = logging.FileHandler(c_fnane)
        file_handler2.setFormatter(formatter)
        file_handler2.setLevel(set_level)
    except (OSError, PermissionError) as e:
        raise PermissionError(
            f"Failed to create log file '{c_fnane}': {e}. "
            f"Please check write permissions for the log directory."
        )

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(set_level)

    log.addHandler(stream_handler)
    log.addHandler(file_handler)
    log.addHandler(file_handler2)
