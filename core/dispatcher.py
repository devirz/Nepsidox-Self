# یک لیست جهانی برای ذخیره همه‌ی دستورها و هندلرها
COMMAND_HANDLERS = []

def register_command(pattern):
    def decorator(func):
        COMMAND_HANDLERS.append((pattern, func))
        return func
    return decorator
