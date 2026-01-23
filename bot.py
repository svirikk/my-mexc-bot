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

if os.path.exists('.env'):
    load_dotenv()

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 ШИФРУВАННЯ
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
            logging.info("✅ MEXC Config Refreshed")
        except Exception as e:
            logging.error(f"❌ Config Refresh Error: {e}")

    def get_wallet_balance(self):
        try:
            if not self.config_obj: self.refresh_config()
            ts = str(int(time.time() * 1000))
            mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
            p0, k0 = self.crypto.encrypt_request({
                "hostname": "contract.mexc.com", "mhash": mhash, "mtoken": self.crypto.mtoken, "platform_type": 3, "product_type": 0
            })
            body_dict = {"p0": p0, "k0": k0, "chash": self.config_obj["chash"], "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash}
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
            resp = self.session.get("https://contract.mexc.com/api/v1/private/account/assets", params=body_dict, headers=headers, timeout=10)
            data = resp.json()
            if not data.get("success"): return 0.0
            for item in data.get("data", []):
                if item.get("currency") == "USDT": return float(item.get("availableBalance", 0))
            return 0.0
        except: return 0.0

    # --- ВХІД У ПОЗИЦІЮ ---
    def place_order(self, symbol, direction, quantity, leverage):
        if not self.config_obj: self.refresh_config()
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        side = 1 if direction == "LONG" else 3 
        p0, k0 = self.crypto.encrypt_request({
            "hostname": "contract.mexc.com", "mhash": mhash, "mtoken": self.crypto.mtoken, "platform_type": 3, "product_type": 0
        })
        body_dict = {
            "symbol": symbol, "side": side, "openType": 1, "type": "5", "vol": int(quantity), "leverage": int(leverage),
            "marketCeiling": False, "priceProtect": "0", "p0": p0, "k0": k0, "chash": self.config_obj["chash"],
            "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash
        }
        return self._send_signed_post("https://contract.mexc.com/api/v1/private/order/create", body_dict, ts)

    # --- ВСТАНОВЛЕННЯ TP / SL (НОВА ФУНКЦІЯ) ---
    def place_plan_order(self, symbol, direction, quantity, trigger_price, is_stop_loss=False):
        """
        Встановлює TP або SL.
        Логіка 'side' для закриття:
        Якщо ми LONG (маємо 1), то закриття - це Side 4 (Close Long).
        Якщо ми SHORT (маємо 3), то закриття - це Side 2 (Close Short).
        """
        if not self.config_obj: self.refresh_config()
        ts = str(int(time.time() * 1000))
        
        # Визначаємо сторону закриття
        close_side = 4 if direction == "LONG" else 2
        
        # Визначаємо Trend (напрямок тригера)
        # Trend 1: Ціна росте >= Trigger (TP для Long, SL для Short)
        # Trend 2: Ціна падає <= Trigger (SL для Long, TP для Short)
        trend = 0
        if direction == "LONG":
            trend = 2 if is_stop_loss else 1
        else: # SHORT
            trend = 1 if is_stop_loss else 2
            
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        p0, k0 = self.crypto.encrypt_request({
            "hostname": "contract.mexc.com", "mhash": mhash, "mtoken": self.crypto.mtoken, "platform_type": 3, "product_type": 0
        })
        
        body_dict = {
            "symbol": symbol,
            "side": close_side,     # Закриваємо позицію
            "openType": 1,          # Isolated
            "type": "1",            # Limit Plan Order (або Market Plan, якщо доступно, але Limit надійніше)
            "vol": int(quantity),
            "triggerPrice": float(trigger_price),
            "price": float(trigger_price), # Виконуємо по ціні тригера (фактично Market Stop)
            "trend": trend,         # 1=Up, 2=Down
            "lossPrice": 0,
            "profitPrice": 0,
            "p0": p0, "k0": k0, "chash": self.config_obj["chash"],
            "mtoken": self.crypto.mtoken, "ts": ts, "mhash": mhash
        }
        
        return self._send_signed_post("https://contract.mexc.com/api/v1/private/plan/place", body_dict, ts)

    def _send_signed_post(self, url, body_dict, ts):
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
        x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            return {"success": True, "dry_run": True, "code": 200}
            
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        try:
            r = self.session.post(url, data=body_json, headers=headers, timeout=10)
            return r.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

# ==========================================
# 💰 ЛОГІКА
# ==========================================
def calculate_risk_params(balance, price, direction):
    try:
        risk_pct = float(os.getenv("RISK_PERCENTAGE", 2.5))
        sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.5))
        tp_pct = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5))
        
        risk_amount = balance * (risk_pct / 100)
        position_value_usd = risk_amount / (sl_pct / 100)
        qty = int(position_value_usd / price)
        if qty < 1: qty = 1
        
        if direction == "LONG":
            sl_price = price * (1 - sl_pct / 100)
            tp_price = price * (1 + tp_pct / 100)
        else:
            sl_price = price * (1 + sl_pct / 100)
            tp_price = price * (1 - tp_pct / 100)
            
        return {"qty": qty, "sl_price": sl_price, "tp_price": tp_price, "risk_amount": risk_amount}
    except: return None

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
        symbol_api = f"{symbol_raw}_USDT"
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        my_direction = None
        if signal_type == "LONG_FLUSH": my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE": my_direction = "SHORT"
        if not my_direction: return

        if symbol_raw in active_positions: return

        balance = mexc_client.get_wallet_balance()
        if balance < 5: 
            logging.error("❌ Low Balance")
            return

        risk = calculate_risk_params(balance, price, my_direction)
        if not risk: return
        
        logging.info(f"🚀 Execution: {my_direction} {symbol_api}")

        # 1. ВХІД (Market Order)
        res = mexc_client.place_order(symbol_api, my_direction, risk['qty'], int(os.getenv("LEVERAGE", 20)))
        
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            active_positions[symbol_raw] = True
            
            # 2. ВСТАНОВЛЕННЯ TP і SL (Якщо не DRY RUN)
            tp_res = None
            sl_res = None
            
            if not res.get("dry_run"):
                logging.info("⚙️ Setting TP/SL orders...")
                time.sleep(1) # Маленька пауза, щоб позиція точно з'явилась
                
                # Take Profit
                tp_res = mexc_client.place_plan_order(symbol_api, my_direction, risk['qty'], risk['tp_price'], is_stop_loss=False)
                
                # Stop Loss
                sl_res = mexc_client.place_plan_order(symbol_api, my_direction, risk['qty'], risk['sl_price'], is_stop_loss=True)
                
                logging.info(f"TP Status: {tp_res.get('success')}, SL Status: {sl_res.get('success')}")

            # 3. ЗВІТ
            header = "🧪 <b>DRY RUN</b>" if res.get("dry_run") else "✅ <b>ORDER EXECUTED</b>"
            emoji = "📈" if my_direction == "LONG" else "📉"
            tp_status = "✅ Set" if tp_res and (tp_res.get("success") or tp_res.get("code")==200) else "⚠️ Failed/Manual"
            sl_status = "✅ Set" if sl_res and (sl_res.get("success") or sl_res.get("code")==200) else "⚠️ Failed/Manual"
            
            msg = (
                f"{header}\n"
                f"<b>Symbol:</b> {symbol_api}\n"
                f"<b>Side:</b> {emoji} {my_direction}\n"
                f"<b>Entry:</b> ${price}\n"
                f"<b>Qty:</b> {risk['qty']}\n\n"
                f"🎯 <b>TP:</b> ${risk['tp_price']:.4f} ({tp_status})\n"
                f"🛑 <b>SL:</b> ${risk['sl_price']:.4f} ({sl_status})\n"
                f"💸 Risk: ${risk['risk_amount']:.2f}"
            )
            await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
            
        else:
            logging.error(f"❌ Order Failed: {res}")

    except Exception as e:
        logging.error(f"❌ Handler Error: {e}", exc_info=True)

async def post_init(application):
    try:
        await application.bot.send_message(
            chat_id=os.getenv("SIGNAL_CHANNEL_ID", ""), 
            text="🚀 MEXC Bot Updated (Auto TP/SL Enabled)"
        )
    except: pass

def main():
    global mexc_client
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    mexc_token = os.getenv("MEXC_TOKEN", "").strip()
    if not token or not mexc_token: return
    mexc_client = MexcWebClient(mexc_token)
    application = ApplicationBuilder().token(token).post_init(post_init).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()