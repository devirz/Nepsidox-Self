# plugins/calculator.py

from telethon import events
from client import client
import re
import math

@client.on(events.NewMessage(pattern=r"\.calc(?:\s+(.+))?", outgoing=True))
async def calculator(event):
    expression = event.pattern_match.group(1)
    reply = await event.get_reply_message()

    # اگر عبارت به صورت ریپلای ارسال شده
    if not expression and reply:
        expression = reply.message.strip()

    if not expression:
        await event.reply("""
🧮 **ماشین حساب**
━━━━━━━━━━━━━━━━━━
**استفاده:** `.calc عبارت ریاضی`

**مثال‌ها:**
`.calc 2 + 3 * 4`
`.calc sqrt(16)`
`.calc sin(30)`
`.calc 2^3`
`.calc log(100)`

**توابع پشتیبانی شده:**
sin, cos, tan, sqrt, log, exp, abs, pow
        """.strip())
        return

    await event.edit("🔢 در حال محاسبه...")

    try:
        # تمیز کردن عبارت
        expression = expression.replace('^', '**')  # تبدیل ^ به **
        expression = expression.replace('×', '*')   # تبدیل × به *
        expression = expression.replace('÷', '/')   # تبدیل ÷ به /
        
        # تعریف توابع مجاز
        allowed_names = {
            k: v for k, v in math.__dict__.items() if not k.startswith("__")
        }
        allowed_names.update({"abs": abs, "round": round})
        
        # بررسی امنیت عبارت
        if re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', expression):
            # بررسی اینکه فقط توابع مجاز استفاده شده
            functions = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', expression)
            for func in functions:
                if func not in allowed_names:
                    await event.edit(f"⚠️ تابع `{func}` مجاز نیست!")
                    return

        # محاسبه
        result = eval(expression, {"__builtins__": {}}, allowed_names)
        
        # فرمت کردن نتیجه
        if isinstance(result, float):
            if result.is_integer():
                result = int(result)
            else:
                result = round(result, 8)

        msg = f"""
🧮 **نتیجه محاسبه**
━━━━━━━━━━━━━━━━━━
📝 **عبارت:** `{event.pattern_match.group(1)}`
🔢 **نتیجه:** `{result}`
━━━━━━━━━━━━━━━━━━
        """.strip()
        
        await event.edit(msg)

    except ZeroDivisionError:
        await event.edit("⚠️ خطا: تقسیم بر صفر!")
    except ValueError as e:
        await event.edit(f"⚠️ خطا در مقدار: {e}")
    except SyntaxError:
        await event.edit("⚠️ خطا: عبارت ریاضی نامعتبر!")
    except Exception as e:
        await event.edit(f"⚠️ خطا: {e}")
