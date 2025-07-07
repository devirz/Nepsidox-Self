from loguru import logger
import sys
import os

LOG_PATH = "logs"
LOG_FILE = f"{LOG_PATH}/selfbot.log"

# ساخت پوشه لاگ اگر وجود نداشت
os.makedirs(LOG_PATH, exist_ok=True)

# پاک‌سازی خروجی‌های قبلی
logger.remove()

# خروجی به ترمینال با رنگ و فرمت حرفه‌ای
logger.add(sys.stderr, level="DEBUG",
           format="<green>{time:HH:mm:ss}</green> | "
                  "<level>{level: <8}</level> | "
                  "<cyan>{module}</cyan>:<cyan>{line}</cyan> - "
                  "<level>{message}</level>")

# خروجی به فایل با چرخش روزانه و نگه‌داری لاگ‌های اخیر
logger.add(LOG_FILE, rotation="1 day", retention="7 days", level="INFO",
           encoding="utf-8", enqueue=True)

# هندل ارورها و نمایش استثناها کامل در لاگ
def install_global_handler():
    import sys
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logger.opt(exception=(exc_type, exc_value, exc_traceback)).error("Unhandled Exception")
    sys.excepthook = handle_exception
