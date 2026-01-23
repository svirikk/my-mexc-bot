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

# 2. Логування
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
# 🌐 КЛІЄНТ MEXC (USDT-M Futures)
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
            # Конфіг беремо з основного сайту, це нормально
            url = "https://www.mexc.com/ucgateway/device_api/dolos/all_biz_config"
            payload = {"ts": ts, "platform_type": 3, "product_type": 0, "sdk_v": "0.0.17", "mtoken": ""}
            resp = self.session.post(url, json=payload, headers=self.base_headers, timeout=10)
            data = resp.json()
            decrypted = self.crypto.sigma_decrypt(data["data"])
            self.config_obj = decrypted[27] if len(decrypted) > 27 else decrypted[-1]
            logging.info("✅ MEXC Config Refreshed")
        except Exception as e:
            logging.error(f"❌ Config Refresh Error: {e}")

    def get_wallet_balance(self):
        """
        Отримання балансу через contract.mexc.com
        """
        try:
            if not self.config_obj: self.refresh_config()
            
            ts = str(int(time.time() * 1000))
            mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
            
            # ВАЖЛИВО: hostname має бути contract.mexc.com
            p0, k0 = self.crypto.encrypt_request({
                "hostname": "contract.mexc.com", 
                "mhash": mhash, 
                "mtoken": self.crypto.mtoken, 
                "platform_type": 3,
                "product_type": 0
            })
            
            body_dict = {
                "p0": p0, "k0": k0, "chash": self.config_obj["chash"],
                "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash
            }
            
            # Підпис
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
            
            # URL для Futures
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            
            resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            data = resp.json()
            
            if not data.get("success"):
                logging.warning(f"⚠️ Balance API Warning: {data}")
                return 0.0

            # Парсинг відповіді
            balance_data = data.get("data", [])
            if isinstance(balance_data, list):
                for item in balance_data:
                    if item.get("currency") == "USDT":
                        return float(item.get("availableBalance", 0))
            
            return 0.0
        except Exception as e: 
            logging.error(f"❌ Balance Exception: {e}")
            return 0.0

    def place_order(self, symbol, direction, quantity, leverage):
        if not self.config_obj: self.refresh_config()
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        
        # 1 = LONG, 3 = SHORT
        side = 1 if direction == "LONG" else 3 
        
        # ВАЖЛИВО: hostname для підпису
        p0, k0 = self.crypto.encrypt_request({
            "hostname": "contract.mexc.com", 
            "mhash": mhash, 
            "mtoken": self.crypto.mtoken, 
            "platform_type": 3,
            "product_type": 0
        })
        
        body_dict = {
            "symbol": symbol,
            "side": side,
            "openType": 1, # 1=Isolated, 2=Cross (можна змінити на 2, якщо потрібно Cross)
            "type": "5",   # Market Order
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
            return {"success": True, "dry_run": True, "code": 200}
        
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        
        try:
            # URL для Futures Order
            url = "https://contract.mexc.com/api/v1/private/order/create"
            
            r = self.session.post(url, data=body_json, headers=headers, timeout=10)
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

# ==========================================
# 💰 RISK MANAGEMENT
# ==========================================
def calculate_risk_params(balance, price, direction):
    try:
        risk_pct = float(os.getenv("RISK_PERCENTAGE", 2.5))
        sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.5))
        tp_pct = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5))
        
        risk_amount = balance * (risk_pct / 100)
        
        # Спрощений розрахунок: Ризик / %StopLoss
        # Приклад: $10 ризику при 1% стопі = позиція на $1000
        position_value_usd = risk_amount / (sl_pct / 100)
        qty = int(position_value_usd / price)
        
        if qty < 1: qty = 1
        
        # Ціни
        if direction == "LONG":
            sl_price = price * (1 - sl_pct / 100)
            tp_price = price * (1 + tp_pct / 100)
        else:
            sl_price = price * (1 + sl_pct / 100)
            tp_price = price * (1 - tp_pct / 100)
            
        return {
            "qty": qty, "sl_price": sl_price, "tp_price": tp_price, "risk_amount": risk_amount,
            "sl_pct": sl_pct, "tp_pct": tp_pct
        }
    except Exception as e:
        logging.error(f"Risk Error: {e}")
        return None

# ==========================================
# 🤖 ЛОГІКА БОТА
# ==========================================
active_positions = {}
mexc_client = None

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_client
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    current_id = str(update.effective_chat.id).strip()
    
    if current_id != target_id: return

    msg_text = update.channel_post.text or update.channel_post.caption or ""
    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    
    if not json_match: return
        
    try:
        data = json.loads(json_match.group(1))
        symbol_raw = str(data.get('symbol', '')).upper().replace('_', '').replace('USDT', '')
        symbol_api = f"{symbol_raw}_USDT" # MEXC Futures API потребує формату XXX_USDT
        
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        my_direction = None
        if signal_type == "LONG_FLUSH": my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE": my_direction = "SHORT"
        
        if not my_direction: return

        allowed_str = os.getenv("ALLOWED_SYMBOLS", "").upper()
        if symbol_raw not in allowed_str and f"{symbol_raw}USDT" not in allowed_str:
            return

        if symbol_raw in active_positions:
            return

        balance = mexc_client.get_wallet_balance()
        logging.info(f"💰 Available Futures Balance: {balance} USDT")
        
        if balance < 5:
            logging.error("❌ Balance too low for trade")
            return

        risk = calculate_risk_params(balance, price, my_direction)
        if not risk: return
        
        logging.info(f"🚀 Opening {my_direction} {symbol_api}, Qty: {risk['qty']}")

        res = mexc_client.place_order(symbol_api, my_direction, risk['qty'], int(os.getenv("LEVERAGE", 20)))
        
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            active_positions[symbol_raw] = True
            
            is_dry = res.get("dry_run")
            header = "🧪 <b>DRY RUN</b>" if is_dry else "✅ <b>ORDER EXECUTED</b>"
            emoji = "📈" if my_direction == "LONG" else "📉"
            
            msg = (
                f"{header}\n"
                f"<b>Symbol:</b> {symbol_api}\n"
                f"<b>Side:</b> {emoji} {my_direction}\n"
                f"<b>Price:</b> ${price}\n"
                f"<b>Qty:</b> {risk['qty']}\n\n"
                f"🎯 TP: ${risk['tp_price']:.4f}\n"
                f"🛑 SL: ${risk['sl_price']:.4f}\n"
                f"💸 Risk: ${risk['risk_amount']:.2f}"
            )
            
            await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
        else:
            logging.error(f"❌ Order Failed: {res}")
            await context.bot.send_message(chat_id=target_id, text=f"❌ Error: {res.get('msg') or res}")

    except Exception as e:
        logging.error(f"❌ Handler Error: {e}", exc_info=True)

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        try:
            mode = "🧪 DRY RUN" if os.getenv("DRY_RUN") == "true" else "🔥 REAL TRADING"
            await application.bot.send_message(chat_id=target_id, text=f"🚀 MEXC Bot (Contract API) Online\nMode: {mode}")
        except: pass

def main():
    global mexc_client
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    mexc_token = os.getenv("MEXC_TOKEN", "").strip()
    
    if not token or not mexc_token:
        logging.error("❌ Tokens missing")
        return

    mexc_client = MexcWebClient(mexc_token)
    
    # Тест балансу при старті
    bal = mexc_client.get_wallet_balance()
    logging.info(f"🏁 Startup Futures Balance: {bal} USDT")

    application = ApplicationBuilder().token(token).post_init(post_init).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()