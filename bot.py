import os
import json
import time
import base64
import hashlib
import re
import logging
import asyncio
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict
from dotenv import load_dotenv

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

if os.path.exists('.env'):
    load_dotenv()

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 MEXC CRYPTO (WEB TOKEN)
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
# 🌐 MEXC WEB CLIENT (TRADING)
# ==========================================
class MexcWebClient:
    def __init__(self, web_token):
        self.token = web_token.strip() if web_token else ""
        self.crypto = MexcCrypto()
        self.session = requests.Session()
        self.config_obj = None
        # Базові заголовки (імітуємо додаток/веб)
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
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
            logging.info("✅ Web Config Loaded")
        except Exception as e:
            logging.error(f"❌ Config Error: {e}")

    def _make_signed_request(self, url, body_dict, method="POST"):
        try:
            if not self.config_obj:
                self.refresh_config()
            
            ts = str(int(time.time() * 1000))
            mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
            
            p0, k0 = self.crypto.encrypt_request({
                "hostname": "contract.mexc.com",
                "mhash": mhash,
                "mtoken": self.crypto.mtoken,
                "platform_type": 3,
                "product_type": 0
            })
            
            body_dict.update({
                "p0": p0, "k0": k0,
                "chash": self.config_obj["chash"],
                "mtoken": self.crypto.mtoken,
                "ts": ts,
                "mhash": mhash
            })
            
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
            
            logging.info(f"🔗 Request: {method} {url}")
            
            if method == "GET":
                resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, data=body_json, headers=headers, timeout=10)
            
            logging.info(f"📥 Response status: {resp.status_code}")
            
            if resp.status_code == 403:
                logging.error("❌ 403 Access Denied")
                return {"success": False, "error": "403 Access Denied"}

            if not resp.text.strip():
                return {"success": False, "error": "Empty response"}
            
            try:
                return resp.json()
            except json.JSONDecodeError:
                return {"success": False, "error": "Invalid JSON"}
            
        except Exception as e:
            logging.error(f"❌ Request error: {e}")
            return {"success": False, "error": str(e)}

    def get_balance(self):
        try:
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            result = self._make_signed_request(url, {}, method="GET")
            if not result.get("success"): return 0.0
            for item in result.get("data", []):
                if item.get("currency") == "USDT":
                    return float(item.get("availableBalance", 0))
            return 0.0
        except:
            return 0.0

    def get_open_positions(self):
        try:
            url = "https://contract.mexc.com/api/v1/private/position/open_positions"
            result = self._make_signed_request(url, {}, method="GET")
            return result.get("data", []) if result.get("success") else []
        except:
            return []

    def place_market_order(self, symbol, direction, quantity, leverage):
        side = 1 if direction == "LONG" else 3
        if isinstance(quantity, float) and quantity.is_integer():
            quantity = int(quantity)
        
        body_dict = {
            "symbol": symbol,
            "side": side,
            "openType": 1,
            "type": "5",
            "vol": quantity,
            "leverage": int(leverage),
            "marketCeiling": False,
            "priceProtect": "0"
        }
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            return {"success": True, "dry_run": True}
        
        url = "https://contract.mexc.com/api/v1/private/order/create"
        return self._make_signed_request(url, body_dict)

    def place_plan_order(self, symbol, side, trigger_price, quantity, trend, position_id=None):
        """
        Виставлення Plan Order (Trigger Order) з обов'язковим параметром TREND
        """
        if isinstance(quantity, float) and quantity.is_integer():
            quantity = int(quantity)
        
        # ✅ ОНОВЛЕНИЙ PAYLOAD ДЛЯ STOPORDER
        # trend: 1 = Ціна росте до тригера (Up)
        # trend: 2 = Ціна падає до тригера (Down)
        # type: 2 = Market Execution (виконати по ринку, коли ціна дійде)
        body_dict = {
            "symbol": symbol,
            "side": side,          # 2=Close Long, 4=Close Short
            "openType": 1,         # Isolated
            "vol": quantity,
            "triggerPrice": trigger_price, # ✅ Використовуємо triggerPrice
            "triggerType": 1,      # Зазвичай 1 (Latest Price)
            "trend": trend,        # ✅ КРИТИЧНО ВАЖЛИВИЙ ПАРАМЕТР
            "type": 2,             # 2 = Market execution
            "lossPrice": trigger_price # Деякі версії API хочуть дублювання тут
        }
        
        if position_id:
            body_dict["positionId"] = position_id
        
        logging.info(f"📤 Setting Trigger Order: Price={trigger_price}, Trend={trend}, Side={side}")
        
        url = "https://contract.mexc.com/api/v1/private/stoporder/place"
        result = self._make_signed_request(url, body_dict)
        logging.info(f"📥 Trigger Response: {result}")
        return result

    def set_sl_tp_for_position(self, symbol, direction, quantity, entry_price, sl_price, tp_price):
        results = {"tp": None, "sl": None}
        close_side = 2 if direction == "LONG" else 4
        
        try:
            logging.info(f"⏳ Waiting 3 seconds for position {symbol} to settle...")
            time.sleep(3)
            
            positions = self.get_open_positions()
            target_position = None
            
            for pos in positions:
                if pos.get("symbol") == symbol and abs(float(pos.get("holdVol", 0))) > 0:
                    target_position = pos
                    break
            
            if not target_position:
                logging.error(f"❌ Position {symbol} not found")
                return {"tp": {"success": False, "error": "Not found"}, "sl": {"success": False, "error": "Not found"}}
            
            position_id = target_position.get("positionId")
            actual_volume = abs(float(target_position.get("holdVol", quantity)))
            
            logging.info(f"🎯 Setting TP/SL for ID={position_id}")
            
            # --- ЛОГІКА НАПРЯМКУ (TREND) ---
            # Trend 1 = UP (Вгору)
            # Trend 2 = DOWN (Вниз)
            
            tp_trend = 0
            sl_trend = 0
            
            if direction == "LONG":
                # TP для Long (продаємо дорожче): Ціна йде ВГОРУ -> Trend 1
                tp_trend = 1
                # SL для Long (продаємо дешевше): Ціна йде ВНИЗ -> Trend 2
                sl_trend = 2
            else: # SHORT
                # TP для Short (відкуповуємо дешевше): Ціна йде ВНИЗ -> Trend 2
                tp_trend = 2
                # SL для Short (відкуповуємо дорожче): Ціна йде ВГОРУ -> Trend 1
                sl_trend = 1
            
            # --- Setting TP ---
            results["tp"] = self.place_plan_order(
                symbol, close_side, tp_price, actual_volume, tp_trend, position_id
            )
            
            time.sleep(0.5)
            
            # --- Setting SL ---
            results["sl"] = self.place_plan_order(
                symbol, close_side, sl_price, actual_volume, sl_trend, position_id
            )
                
        except Exception as e:
            logging.error(f"❌ SL/TP Exception: {e}", exc_info=True)
        
        return results

# ==========================================
# 🎯 STATE MACHINE & MANAGER
# ==========================================
class PositionState(Enum):
    NO_POSITION = "no_position"
    OPENING = "opening"
    POSITION_DETECTED = "position_detected"
    SL_TP_SET = "sl_tp_set"

@dataclass
class ManagedPosition:
    symbol: str
    state: PositionState
    signal_direction: str
    signal_time: float
    current_size: float = 0.0
    entry_price: float = 0.0
    target_sl: float = 0.0
    target_tp: float = 0.0
    sl_order_placed: bool = False

class PositionManager:
    def __init__(self):
        self.positions: Dict[str, ManagedPosition] = {}
    
    def add_signal(self, symbol, direction, sl, tp):
        self.positions[symbol] = ManagedPosition(
            symbol=symbol, state=PositionState.OPENING,
            signal_direction=direction, signal_time=time.time(),
            target_sl=sl, target_tp=tp
        )

    def update_from_exchange(self, exchange_positions):
        exchange_symbols = {p["symbol"]: p for p in exchange_positions if abs(float(p.get("holdVol", 0))) > 0}
        
        for symbol, managed in list(self.positions.items()):
            if managed.state == PositionState.OPENING:
                if symbol in exchange_symbols:
                    ex_pos = exchange_symbols[symbol]
                    managed.state = PositionState.POSITION_DETECTED
                    managed.current_size = abs(float(ex_pos.get("holdVol")))
                    managed.entry_price = float(ex_pos.get("openAvgPrice"))
                    logging.info(f"✅ POSITION DETECTED: {symbol}")
                elif time.time() - managed.signal_time > 30:
                    del self.positions[symbol]
            elif managed.state in [PositionState.POSITION_DETECTED, PositionState.SL_TP_SET]:
                if symbol not in exchange_symbols:
                    del self.positions[symbol]

# ==========================================
# 🔄 MONITORING LOOP
# ==========================================
async def position_monitoring_loop(web_client: MexcWebClient, manager: PositionManager, context):
    logging.info("🔄 Monitoring started")
    while True:
        try:
            if not manager.positions:
                await asyncio.sleep(5)
                continue
            
            exchange_positions = web_client.get_open_positions()
            manager.update_from_exchange(exchange_positions)
            
            for symbol, managed in list(manager.positions.items()):
                if managed.state == PositionState.POSITION_DETECTED and not managed.sl_order_placed:
                    
                    # 🔥 RECALCULATE TP/SL WITH PRECISION 🔥
                    entry = managed.entry_price
                    sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.5)) / 100
                    tp_pct = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5)) / 100
                    
                    def get_prec(price):
                        return len(f"{price:.10f}".rstrip('0').split('.')[1]) if '.' in str(price) else 4
                    prec = get_prec(entry)
                    
                    if managed.signal_direction == "LONG":
                        new_tp = round(entry * (1 + tp_pct), prec)
                        new_sl = round(entry * (1 - sl_pct), prec)
                    else: # SHORT
                        new_tp = round(entry * (1 - tp_pct), prec)
                        new_sl = round(entry * (1 + sl_pct), prec)
                    
                    managed.target_tp = new_tp
                    managed.target_sl = new_sl
                    
                    logging.info(f"🎯 Setting TP={new_tp}, SL={new_sl} for {symbol}")

                    res = web_client.set_sl_tp_for_position(
                        symbol, managed.signal_direction, managed.current_size,
                        entry, new_sl, new_tp
                    )
                    
                    managed.sl_order_placed = True
                    managed.state = PositionState.SL_TP_SET
                    
                    # Report
                    target_id = os.getenv("SIGNAL_CHANNEL_ID")
                    msg = (
                        f"✅ <b>POSITION CONFIRMED</b>\n"
                        f"Symbol: {symbol}\nSide: {managed.signal_direction}\n"
                        f"Entry: {entry}\nTP: {new_tp}\nSL: {new_sl}\n"
                        f"TP Set: {'✅' if res['tp'].get('success') else '❌'}\n"
                        f"SL Set: {'✅' if res['sl'].get('success') else '❌'}"
                    )
                    
                    if not res['tp'].get('success'):
                         msg += f"\nTP Err: {res['tp'].get('message')}"
                    if not res['sl'].get('success'):
                         msg += f"\nSL Err: {res['sl'].get('message')}"
                         
                    await context.bot.send_message(target_id, msg, parse_mode="HTML")
            
            await asyncio.sleep(5)
        except Exception as e:
            logging.error(f"Loop error: {e}")
            await asyncio.sleep(5)

# ==========================================
# 🚀 MAIN SETUP
# ==========================================
position_manager = None
mexc_web = None

def calculate_risk_params(balance, price, direction):
    # Simplified for brevity
    try:
        qty = int((balance * 0.025 * 200) / price) # Approx risk logic
        if qty < 1: qty = 1
        return {"qty": qty, "sl_price": 0, "tp_price": 0} # Prices recalc later
    except: return None

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_web, position_manager
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    if str(update.effective_chat.id).strip() != target_id: return

    msg = update.channel_post.text or ""
    if "signalType" not in msg: return
    
    try:
        data = json.loads(re.search(r'(\{.*\})', msg, re.DOTALL).group(1))
        symbol = data['symbol'].replace('_','').replace('USDT','') + "_USDT"
        direction = "LONG" if "LONG" in data['signalType'] else "SHORT"
        price = float(data['stats']['lastPrice'])
        
        if not position_manager or symbol in position_manager.positions: return
        
        risk = calculate_risk_params(mexc_web.get_balance(), price, direction)
        position_manager.add_signal(symbol, direction, 0, 0)
        
        logging.info(f"🚀 {direction} {symbol}")
        mexc_web.place_market_order(symbol, direction, risk['qty'], 20)
        await context.bot.send_message(target_id, f"✅ Order Sent: {symbol} {direction}")
        
    except Exception as e:
        logging.error(f"Handle error: {e}")

def main():
    global mexc_web, position_manager
    mexc_web = MexcWebClient(os.getenv("MEXC_TOKEN"))
    position_manager = PositionManager()
    
    app = ApplicationBuilder().token(os.getenv("TELEGRAM_BOT_TOKEN")).build()
    app.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    loop = asyncio.get_event_loop()
    loop.create_task(position_monitoring_loop(mexc_web, position_manager, app))
    
    logging.info("🤖 Bot Started")
    app.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()