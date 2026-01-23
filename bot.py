import os
import json
import time
import base64
import hashlib
import re
import logging
from dotenv import load_dotenv

# Cryptography
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

# Telegram Bot
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

# 1. Завантаження налаштувань
if os.path.exists('.env'):
    load_dotenv()

# 2. Логування (DEBUG рівень для пошуку помилок)
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 МОДУЛЬ ШИФРУВАННЯ MEXC
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
            iv, tag, ct = raw[:12], raw[-16:], raw[12:-16]
            cipher = AES.new(KEY_B, AES.MODE_GCM, nonce=iv)
            return json.loads(cipher.decrypt_and_verify(ct, tag).decode("utf-8"))
        except Exception as e:
            logging.error(f"Decrypt error: {e}")
            return None

    def encrypt_request(self, params_dict):
        c = os.urandom(16).hex()
        aes_key = c.encode("utf-8")
        plaintext = json.dumps(params_dict, separators=(",", ":")).encode("utf-8")
        iv = os.urandom(12)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        p0 = base64.b64encode(iv + ciphertext + tag).decode("ascii")
        rsa_public = RSA.import_key(MEXC_PUBKEY_PEM)
        k0 = base64.b64encode(PKCS1_v1_5.new(rsa_public).encrypt(c.encode("utf-8"))).decode("ascii")
        return p0, k0

# ==========================================
# 🌐 КЛІЄНТ MEXC
# ==========================================
class MexcWebClient:
    def __init__(self, token):
        self.token = token.strip() if token else ""
        self.crypto = MexcCrypto()
        self.session = requests.Session()
        self.config_obj = None
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Content-Type": "application/json",
            "mtoken": self.crypto.mtoken,
            "authorization": self.token
        }
        self.refresh_config()

    def refresh_config(self):
        try:
            ts = int(time.time() * 1000)
            url = "https://www.mexc.com/ucgateway/device_api/dolos/all_biz_config"
            payload = {"ts": ts, "platform_type": 3, "product_type": 0, "sdk_v": "0.0.17", "mtoken": ""}
            resp = self.session.post(url, json=payload, headers=self.base_headers, timeout=10)
            data = resp.json()
            decrypted = self.crypto.sigma_decrypt(data["data"])
            self.config_obj = decrypted[27] if len(decrypted) > 27 else decrypted[-1]
            logging.info("✅ MEXC Конфігурація отримана.")
        except Exception as e:
            logging.error(f"❌ Помилка оновлення конфігу: {e}")

    def get_wallet_balance(self):
        try:
            ts = int(time.time() * 1000)
            # ✅ ВИПРАВЛЕНИЙ ШЛЯХ (Ф'ЮЧЕРСНИЙ ГАМАНЕЦЬ)
            url = f"https://www.mexc.com/api/platform/futures/api/v1/private/account/asset/list?ts={ts}"
            
            resp = self.session.get(url, headers=self.base_headers, timeout=10)
            data = resp.json()

            # Якщо помилка доступу або токена
            if data.get("code") != 200:
                logging.warning(f"⚠️ API відповідь балансу: {data}")
                return 0.0

            # Парсинг ф'ючерсного балансу
            # Структура відповіді MEXC Futures відрізняється від Spot
            assets = data.get("data", [])
            if isinstance(assets, list):
                for asset in assets:
                    if asset.get("currency") == "USDT":
                        # availableBalance — це доступні кошти для торгівлі
                        return float(asset.get("availableBalance", 0))
            
            logging.info("ℹ️ USDT не знайдено на ф'ючерсному акаунті.")
            return 0.0

        except Exception as e: 
            logging.error(f"❌ Критична помилка балансу: {e}")
            return 0.0

    def place_order(self, symbol, direction, quantity, leverage):
        if not self.config_obj: self.refresh_config()
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        
        p0, k0 = self.crypto.encrypt_request({
            "hostname": "www.mexc.com", "mhash": mhash, "mtoken": self.crypto.mtoken, "platform_type": 3
        })
        
        body_dict = {
            "symbol": symbol,
            "side": 1 if direction == "LONG" else 3,
            "openType": 1,
            "type": "5",
            "vol": int(quantity),
            "leverage": int(leverage),
            "marketCeiling": False,
            "priceProtect": "0",
            "p0": p0, "k0": k0, "chash": self.config_obj["chash"],
            "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash
        }
        
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
        x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            return {"success": True, "dry_run": True}
        
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        
        try:
            r = self.session.post("https://www.mexc.com/api/platform/futures/api/v1/private/order/create", 
                                data=body_json, headers=headers, timeout=10)
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

# ==========================================
# 🤖 ЛОГІКА БОТА
# ==========================================
active_positions = {}
mexc_client = None

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_client
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    current_id = str(update.effective_chat.id).strip()
    
    # 1. Логуємо факт отримання будь-якого посту
    logging.info(f"📩 POST received. Channel ID: {current_id}")

    if current_id != target_id:
        logging.info(f"⏭ Skipped: Wrong channel ID (Target: {target_id})")
        return

    msg_text = update.channel_post.text or update.channel_post.caption or ""
    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    
    if not json_match:
        logging.info("ℹ️ Skipped: No JSON found in message")
        return
        
    try:
        data = json.loads(json_match.group(1))
        symbol = str(data.get('symbol', '')).upper()
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        logging.info(f"🔎 Processing Signal: {symbol} | Type: {signal_type} | Price: {price}")
        
        # Вибір напрямку
        my_direction = None
        if signal_type == "LONG_FLUSH": my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE": my_direction = "SHORT"
        
        if not my_direction: 
            logging.info(f"⏭ Skipped: Unknown Signal Type {signal_type}")
            return

        # Перевірка фільтрів
        allowed = [s.strip().upper() for s in os.getenv("ALLOWED_SYMBOLS", "").split(",")]
        
        if symbol not in allowed:
            logging.warning(f"🚫 Skipped: {symbol} is not in ALLOWED_SYMBOLS")
            return
            
        if symbol in active_positions:
            logging.warning(f"⏳ Skipped: Position already active for {symbol}")
            return

        # Розрахунок
        balance = mexc_client.get_wallet_balance()
        logging.info(f"💰 Current Balance: {balance} USDT")
        
        if balance < 5:
            logging.error("❌ Balance too low or token expired (Balance = 0)")
            return

        risk_usd = balance * (float(os.getenv("RISK_PERCENTAGE", 2.5)) / 100)
        sl_percent = float(os.getenv("STOP_LOSS_PERCENT", 0.5)) / 100
        qty = int((risk_usd / sl_percent) / price)
        
        if qty < 1: qty = 1
        
        logging.info(f"🚀 Placing Order: {my_direction} {symbol}, Qty: {qty}, Risk: ${risk_usd:.2f}")

        res = mexc_client.place_order(symbol, my_direction, qty, int(os.getenv("LEVERAGE", 20)))
        
        # ЛОГІКА ОБРОБКИ РЕЗУЛЬТАТУ
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            active_positions[symbol] = True
            
            mode_text = "TEST MODE" if res.get("dry_run") else "REAL TRADE"
            await context.bot.send_message(
                chat_id=target_id, 
                text=f"✅ {mode_text}: {my_direction} {symbol}\n💰 Вхід: {price}\n📊 К-ть: {qty}"
            )
            logging.info(f"✅ Order executed successfully: {res}")
        else:
            # ОСЬ ЧОГО НЕ ВИСТАЧАЛО: Логування помилки
            logging.error(f"❌ ORDER FAILED. Exchange response: {res}")
            await context.bot.send_message(
                chat_id=target_id, 
                text=f"❌ Помилка відкриття угоди {symbol}:\n{res.get('msg') or res.get('error') or res}"
            )

    except Exception as e:
        logging.error(f"❌ CRITICAL ERROR in handler: {e}", exc_info=True)

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        try:
            await application.bot.send_message(chat_id=target_id, text="🚀 Бот перезапущено. Debug Mode: ON")
        except Exception as e:
            logging.error(f"Post-init error: {e}")

def main():
    global mexc_client
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    mexc_token = os.getenv("MEXC_TOKEN", "").strip()
    
    if not token: return

    mexc_client = MexcWebClient(mexc_token)
    
    application = ApplicationBuilder().token(token).post_init(post_init).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 System starting...")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()