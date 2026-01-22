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

# 1. Завантаження налаштувань
if os.path.exists('.env'):
    load_dotenv()

# 2. Налаштування логування
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
        except: return None

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
        self.token = token.strip()
        self.crypto = MexcCrypto()
        self.session = requests.Session()
        self.config_obj = None
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "mtoken": self.crypto.mtoken,
            "authorization": self.token
        }
        self.refresh_config()

    def refresh_config(self):
        try:
            ts = int(time.time() * 1000)
            url = "https://www.mexc.com/ucgateway/device_api/dolos/all_biz_config"
            resp = self.session.post(url, json={"ts": ts, "platform_type": 3, "product_type": 0, "sdk_v": "0.0.17", "mtoken": ""}, headers=self.base_headers)
            self.config_obj = self.crypto.sigma_decrypt(resp.json()["data"])[27]
            logging.info(f"✅ MEXC Конфіг отримано.")
        except: logging.error("❌ Помилка конфігу MEXC")

    def get_wallet_balance(self):
        try:
            url = f"https://www.mexc.com/api/platform/asset/api/v1/private/asset/account/detail?currency=USDT&ts={int(time.time()*1000)}"
            resp = self.session.get(url, headers=self.base_headers)
            for b in resp.json().get("data", {}).get("balances", []):
                if b["currency"] == "USDT": return float(b.get("available", 0))
            return 100.0
        except: return 100.0

    def place_order(self, symbol, direction, quantity, leverage):
        if not self.config_obj: self.refresh_config()
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        p0, k0 = self.crypto.encrypt_request({"hostname": "www.mexc.com", "mhash": mhash, "mtoken": self.crypto.mtoken, "platform_type": 3})
        
        body_dict = {
            "symbol": symbol, "side": 1 if direction == "LONG" else 3, "openType": 1, "type": "5", 
            "vol": quantity, "leverage": leverage, "marketCeiling": False, "priceProtect": "0",
            "p0": p0, "k0": k0, "chash": self.config_obj["chash"], "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash
        }
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
        sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
        
        if os.getenv("DRY_RUN", "false").lower() == "true": return {"success": True, "dry_run": True}
        return self.session.post("https://www.mexc.com/api/platform/futures/api/v1/private/order/create", 
                                data=body_json, headers={**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": sign}).json()

# ==========================================
# 🤖 ОБРОБНИК СИГНАЛІВ (REVERSAL STRATEGY)
# ==========================================

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    current_id = str(update.effective_chat.id).strip()
    
    # Перевірка, чи повідомлення з нашого каналу
    if current_id != target_id:
        return

    msg_text = update.channel_post.text or update.channel_post.caption or ""
    
    # Витягуємо JSON з тексту алерту
    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    if not json_match:
        return
        
    try:
        data = json.loads(json_match.group(1))
        symbol = str(data['symbol']).upper()
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        # 🟢 ЛОГІКА ВІДСКОКУ (Mean Reversion)
        my_direction = None
        
        if signal_type == "LONG_FLUSH":
            # Ринок падає -> купуємо відскок вгору
            my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE":
            # Ринок злітає -> продаємо відкат вниз
            my_direction = "SHORT"
        
        if not my_direction:
            logging.info(f"⏭ Пропущено: тип сигналу {signal_type} не підтримується")
            return

        logging.info(f"🎯 СТРАТЕГІЯ: {signal_type} знайдено. Готуємо позицію {my_direction} для {symbol}")

        # 1. Перевірка дозволених монет
        allowed_list = [s.strip().upper() for s in os.getenv("ALLOWED_SYMBOLS", "").split(",")]
        if symbol not in allowed_list:
            logging.info(f"🚫 Монета {symbol} відсутня в ALLOWED_SYMBOLS")
            return

        # 2. Перевірка, чи вже відкрита позиція по цій монеті
        if symbol in active_positions:
            logging.info(f"⏳ {symbol} вже в роботі, ігноруємо дублікат")
            return

        # 3. Розрахунок параметрів угоди
        balance = mexc.get_wallet_balance()
        risk_pct = float(os.getenv("RISK_PERCENTAGE", 2.5))
        sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.5)) / 100
        leverage = int(os.getenv("LEVERAGE", 20))

        # Сума ризику в USDT
        risk_amount_usd = balance * (risk_pct / 100)
        # Об'єм позиції (Qty) = Ризик / %Стоп-Лоссу / Ціна
        quantity = int((risk_amount_usd / sl_pct) / price)
        
        if quantity < 1: quantity = 1

        # 4. Відправка ордеру на MEXC
        res = mexc.place_order(symbol, my_direction, quantity, leverage)
        
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            active_positions[symbol] = True
            
            # Гарне сповіщення про вхід в угоду
            status_text = "🧪 [TEST MODE]" if res.get("dry_run") else "💰 [REAL TRADE]"
            await context.bot.send_message(
                chat_id=target_id,
                text=(
                    f"{status_text}\n"
                    f"⚡️ **ВХІД НА ВІДСКОК**\n\n"
                    f"Монета: #{symbol}\n"
                    f"Тип: {signal_type}\n"
                    f"Напрямок: {my_direction}\n"
                    f"Ціна входу: {price}\n"
                    f"Кількість: {quantity}\n"
                    f"Плече: {leverage}x"
                ),
                parse_mode="Markdown"
            )
            logging.info(f"✅ Успішно відкрито {my_direction} по {symbol}")
        else:
            logging.error(f"❌ Помилка ордеру MEXC: {res}")

    except Exception as e:
        logging.error(f"❌ Критична помилка обробника: {e}")

# ==========================================
# 🚀 ФУНКЦІЯ ПРИВІТАННЯ ПРИ ЗАПУСКУ
# ==========================================

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        try:
            mode = "🧪 DRY RUN (Без реальних грошей)" if os.getenv("DRY_RUN") == "true" else "💰 REAL TRADING"
            await application.bot.send_message(
                chat_id=target_id, 
                text=f"🤖 **MEXC Dolos Trader активований**\n\n"
                     f"📡 Моніторинг каналу: ЗАПУЩЕНО\n"
                     f"⚙️ Режим: {mode}\n"
                     f"📈 Стратегія: Reversal (Flush/Squeeze)\n"
                     f"🛡 Ризик: {os.getenv('RISK_PERCENTAGE')}% на угоду"
            )
        except Exception as e:
            logging.error(f"Не вдалося відправити старт-повідомлення: {e}")

# ==========================================
# 🏁 ГОЛОВНИЙ ЗАПУСК (БЕЗ ASYNCIO.RUN)
# ==========================================
def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        logging.error("❌ Токен не знайдено!")
        return

    # Створюємо додаток через ApplicationBuilder
    application = ApplicationBuilder().token(token).build()
    
    # Додаємо обробник
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 Бот запущено. Очікування сигналів...")
    
    # Використовуємо run_polling (це блокуючий виклик, asyncio.run не потрібен)
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()