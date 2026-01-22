import os
import json
import time
import base64
import hashlib
import re
import logging
import asyncio
from datetime import datetime, timezone
from dotenv import load_dotenv

# Cryptography
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

# Telegram Bot
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

# 1. Завантаження налаштувань (Універсальний метод)
# Якщо файл .env існує (локально), він завантажиться. 
# На Railway змінні будуть братися безпосередньо з системи.
if os.path.exists('.env'):
    load_dotenv()
    print("✅ Локальний файл .env знайдено та завантажено.")

# 2. Налаштування логування для Railway
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 МОДУЛЬ ШИФРУВАННЯ MEXC (Dolos)
# ==========================================

KEY_B = "1b8c71b668084dda9dc0285171ccf753".encode("utf-8")
MEXC_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqpMCeNv7qfsKe09xwE5o05ZCq/qJvTok6WbqYZOXA16UQqR+sHH0XXfnWxLSEvCviP9qjZjruHWdpMmC4i/yQJe7MJ66YoNloeNtmMgtqEIjOvSxRktmAxywul/eJolrhDnRPXYll4fA5+24t1g6L5fgo/p66yLtZRg4fC1s3rAF1WPe6dSJQx7jQ/xhy8Z0WojmzIeaoBa0m8qswx0DMIdzXfswH+gwMYCQGR3F/NAlxyvlWPMBlpFEuHZWkp9TXlTtbLf+YL8vYjV5HNqIdNjVzrIvg/Bis49ktfsWuQxT/RIyCsTEuHmZyZR6NJAMPZUE5DBnVWdLShb6KuyqwIDAQAB
-----END PUBLIC KEY-----"""

class MexcCrypto:
    def __init__(self):
        self.mtoken = os.urandom(16).hex()
    
    def sigma_decrypt(self, cfg0_b64):
        try:
            raw = base64.b64decode(cfg0_b64)
            iv  = raw[:12]
            tag = raw[-16:]
            ct  = raw[12:-16]
            cipher = AES.new(KEY_B, AES.MODE_GCM, nonce=iv)
            plaintext = cipher.decrypt_and_verify(ct, tag)
            return json.loads(plaintext.decode("utf-8"))
        except Exception as e:
            logging.error(f"Помилка розшифровки конфігу: {e}")
            return None

    def encrypt_request(self, params_dict):
        c = os.urandom(16).hex()
        aes_key = c.encode("utf-8")
        # Використовуємо separators=(",", ":") для максимально компактного JSON без пробілів
        plaintext = json.dumps(params_dict, separators=(",", ":")).encode("utf-8")
        
        iv = os.urandom(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        p0 = base64.b64encode(iv + ciphertext + tag).decode("ascii")
        
        rsa_public = RSA.import_key(MEXC_PUBKEY_PEM)
        cipher_rsa_pub = PKCS1_v1_5.new(rsa_public)
        encrypted_c = cipher_rsa_pub.encrypt(c.encode("utf-8"))
        k0 = base64.b64encode(encrypted_c).decode("ascii")
        
        return p0, k0

# ==========================================
# 🌐 КЛІЄНТ ДЛЯ MEXC (WEB API)
# ==========================================

class MexcWebClient:
    def __init__(self, token):
        self.token = token
        self.crypto = MexcCrypto()
        self.session = requests.Session()
        self.config_obj = None
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Content-Type": "application/json",
            "mtoken": self.crypto.mtoken,
            "authorization": self.token,
            "Origin": "https://www.mexc.com",
            "Referer": "https://www.mexc.com/"
        }
        self.session.cookies.set("uc_token", self.token, domain=".mexc.com")
        self.session.cookies.set("u_id", self.token, domain=".mexc.com")
        self.refresh_config()

    def refresh_config(self):
        try:
            ts = int(time.time() * 1000)
            payload = {"ts": ts, "platform_type": 3, "product_type": 0, "app_v": "", "sdk_v": "0.0.17", "mtoken": ""}
            url = "https://www.mexc.com/ucgateway/device_api/dolos/all_biz_config"
            resp = self.session.post(url, json=payload, headers=self.base_headers)
            data = resp.json()
            decrypted = self.crypto.sigma_decrypt(data["data"])
            self.config_obj = decrypted[27] 
            logging.info(f"✅ MEXC Конфіг отримано. Chash: ...{self.config_obj.get('chash')[-8:]}")
        except Exception as e:
            logging.error(f"❌ Не вдалося оновити конфіг MEXC: {e}")

    def get_wallet_balance(self):
        try:
            ts = int(time.time() * 1000)
            url = "https://www.mexc.com/api/platform/asset/api/v1/private/asset/account/detail?currency=USDT"
            headers = self.base_headers.copy()
            headers["x-mxc-nonce"] = str(ts)
            resp = self.session.get(url, headers=headers)
            if resp.status_code == 200:
                balances = resp.json().get("data", {}).get("balances", [])
                for b in balances:
                    if b["currency"] == "USDT":
                        return float(b.get("available", 0))
            return 100.0 # Заглушка, якщо баланс недоступний
        except:
            return 100.0

    def place_order(self, symbol, direction, quantity, leverage):
        if not self.config_obj: self.refresh_config()
        ts = int(time.time() * 1000)
        nonce = str(ts)
        mhash = hashlib.md5(self.crypto.mtoken.encode("utf-8")).hexdigest()
        
        preplaintext = {
            "hostname": "www.mexc.com", "member_id": "", "mhash": mhash, "mtoken": self.crypto.mtoken,
            "platform_type": 3, "product_type": 0, "request_id": "", "sys": "Linux", "sys_ver": ""
        }
        p0, k0 = self.crypto.encrypt_request(preplaintext)
        
        side = 1 if direction == "LONG" else 3 
        body_dict = {
            "symbol": symbol, "side": side, "openType": 1, "type": "5", "vol": quantity,
            "leverage": leverage, "marketCeiling": False, "priceProtect": "0",
            "p0": p0, "k0": k0, "chash": self.config_obj["chash"],
            "mtoken": self.crypto.mtoken, "ts": str(ts), "mhash": mhash
        }
        
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + nonce).encode("utf-8")).hexdigest()[7:]
        x_mxc_sign = hashlib.md5((nonce + body_json + inner).encode("utf-8")).hexdigest()
        
        headers = self.base_headers.copy()
        headers.update({"x-mxc-nonce": nonce, "x-mxc-sign": x_mxc_sign})
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            return {"success": True, "dry_run": True}

        url = "https://www.mexc.com/api/platform/futures/api/v1/private/order/create"
        resp = self.session.post(url, data=body_json, headers=headers)
        return resp.json()

# ==========================================
# 🤖 ЛОГІКА БОТА ТА УПРАВЛІННЯ РИЗИКАМИ
# ==========================================

mexc = MexcWebClient(os.getenv("MEXC_TOKEN"))
active_positions = {}

def is_trading_hour():
    if os.getenv("TRADING_HOURS_ENABLED", "false").lower() != "true": return True
    start = int(os.getenv("TRADING_START_HOUR", 18))
    end = int(os.getenv("TRADING_END_HOUR", 14))
    now = datetime.now(timezone.utc).hour
    return (now >= start or now < end) if start > end else (start <= now < end)

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target_channel_id = os.getenv("SIGNAL_CHANNEL_ID")
    if str(update.effective_chat.id) != str(target_channel_id): return

    msg_text = update.channel_post.text or update.channel_post.caption
    if not msg_text: return

    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    if not json_match: return
        
    try:
        data = json.loads(json_match.group(1))
        symbol, direction, price = data['symbol'], data['direction'], float(data['stats']['lastPrice'])
    except: return

    # Перевірки
    if not is_trading_hour():
        await context.bot.send_message(chat_id=update.effective_chat.id, 
            text=f"⏰ SIGNAL IGNORED\nSymbol: {symbol}\nReason: Outside trading hours\nTrading: {os.getenv('TRADING_START_HOUR')}:00-{os.getenv('TRADING_END_HOUR')}:00")
        return

    if symbol not in os.getenv("ALLOWED_SYMBOLS", "").split(","): return

    if symbol in active_positions:
        await context.bot.send_message(chat_id=update.effective_chat.id, 
            text=f"⏰ SIGNAL IGNORED\nSymbol: {symbol}\nReason: Position already exists")
        return

    # Розрахунок позиції
    balance = mexc.get_wallet_balance()
    risk_pct = float(os.getenv("RISK_PERCENTAGE", 2.5))
    sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.3)) / 100
    tp_pct = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5)) / 100
    leverage = int(os.getenv("LEVERAGE", 20))

    risk_usd = balance * (risk_pct / 100)
    qty = int((risk_usd / sl_pct) / price)
    if qty < 1: qty = 1
    
    tp_price = price * (1 + tp_pct) if direction == "LONG" else price * (1 - tp_pct)
    sl_price = price * (1 - sl_pct) if direction == "LONG" else price * (1 + sl_pct)

    # Виконання
    logging.info(f"🚀 Вхід в угоду: {symbol} {direction}")
    res = mexc.place_order(symbol, direction, qty, leverage)
    
    if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
        active_positions[symbol] = True
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"""
✅ POSITION OPENED
  
  Symbol: {symbol}
  Direction: {'📈 LONG' if direction == 'LONG' else '📉 SHORT'}
  Entry Price: ${price}
  Quantity: {qty}
  Leverage: {leverage}x
  
  🎯 Take Profit: ${tp_price:.4f} (+{tp_pct*100}%)
  🛑 Stop Loss: ${sl_price:.4f} (-{sl_pct*100}%)
  💰 Risk: ${risk_usd:.2f} ({risk_pct}% of balance)
  
  Signal from: {datetime.now().strftime("%m/%d/%Y, %I:%M:%S %p")} UTC
""")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"⚠️ ERROR: {res}")

# ==========================================
# 🏁 ЗАПУСК (MAIN)
# ==========================================

def main():
    # Отримуємо змінні та очищаємо їх від пробілів/переносів
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    mexc_auth = os.getenv("MEXC_TOKEN", "").strip()
    channel_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()

    if not token or not mexc_auth or not channel_id:
        logging.error("❌ CRITICAL: Missing environment variables (Token, MEXC Auth, or Channel ID)!")
        return

    # Створюємо додаток
    # run_polling автоматично ініціалізує, запускає та зупиняє бота
    application = ApplicationBuilder().token(token).build()
    
    # Додаємо обробник повідомлень
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 Бот запускається... Очікування сигналів.")

    # Цей метод ідеальний для Railway: він тримає процес активним 
    # і коректно завершує його при перезавантаженні сервера
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        logging.info("Бот зупинений.")
    except Exception as e:
        logging.error(f"Критична помилка при запуску: {e}")