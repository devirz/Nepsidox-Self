# 🤖 Nepsidox-Self | Telegram Selfbot

A modern, modular, and easy-to-use Telegram selfbot written in Python.  
**⚠️ Use responsibly! Selfbots can violate Telegram’s Terms of Service.**

---

## ✨ Features

- Fast and lightweight Python core 🐍
- Modular plugin support 🧩
- Easy setup and configuration ⚙️
- Actively maintained and open source 🚀

---

## 📦 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/devirz/Nepsidox-Self.git
   cd Nepsidox-Self
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## ⚙️ Configuration

Before running the selfbot, set your credentials and preferences in the `config.py` file:

```python
API_ID = 123456         # Get this from https://my.telegram.org
API_HASH = 'your_api_hash'  # Get this from https://my.telegram.org
OWNER_ID = 123456789    # Your Telegram user ID; the bot only responds to this account
SESSION_NAME = 'NepsidoxSelf'  # Session name for Telethon
```

**How to get your API ID and API Hash:**  
Go to [my.telegram.org](https://my.telegram.org), log in, click on ‘API development tools’, and create a new application.

---

## ▶️ Running the Bot

Just run:

```bash
python bot.py
```

The bot will start using the configuration provided in `config.py`.

---

## 📁 Plugins & Extensions

- Drop your custom plugins in the `plugins/` directory.
- Utilities and helpers are in the `utils/` directory.
- Core logic is in the `core/` directory.

Browse all files and folders here: [Repository Content](https://github.com/devirz/Nepsidox-Self/contents/)

---

## 🛡️ Disclaimer

> **Warning:** Selfbots are against the Terms of Service of Telegram and may result in account suspension or termination. Use at your own risk.

---

## 📝 License

This project is open source and available under the MIT License.
