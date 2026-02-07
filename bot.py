import os
import json
import time
import base64
import hashlib
import re
import logging
import asyncio
import html  # ✅ Додано для безпечної відправки тексту в Telegram
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
    """Відкриття позицій + TP/SL через web token"""
    
    def __init__(self, web_token):
        self.token = web_token.strip() if web_token else ""
        self.crypto = MexcCrypto()
        self.session = requests.Session()
        self.config_obj = None
        
        # ✅ FIX 403: Додаємо заголовки, щоб виглядати як браузер
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://futures.mexc.com",
            "Referer": "https://futures.mexc.com/",
            "mtoken": self.crypto.mtoken,
            "authorization": self.token,
            # Іноді потрібен хоча б пустий Cookie або u_id
            "Cookie": f"u_id={self.crypto.mtoken}" 
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
        """Універсальний підписаний запит"""
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
            # logging.debug(f"🔗 Payload: {body_dict}")
            
            if method == "GET":
                resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, data=body_json, headers=headers, timeout=10)
            
            logging.info(f"📥 Response status: {resp.status_code}")
            
            if resp.status_code == 403:
                logging.error("❌ 403 Access Denied. WAF Blocked.")
                return {"success": False, "error": f"Access Denied (403): {resp.text[:100]}"}

            if not resp.text.strip():
                logging.error("❌ Empty response from server")
                return {"success": False, "error": "Empty response"}
            
            try:
                return resp.json()
            except json.JSONDecodeError as e:
                # ✅ Логуємо raw text, але повертаємо безпечну помилку
                logging.error(f"❌ JSON decode error. Response was: {resp.text[:200]}")
                return {"success": False, "error": f"Invalid JSON response (Status {resp.status_code})"}
            
        except Exception as e:
            logging.error(f"❌ Request error: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def get_balance(self):
        """Баланс ТІЛЬКИ Futures USDT"""
        try:
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            result = self._make_signed_request(url, {}, method="GET")
            
            if not result.get("success"):
                logging.warning(f"⚠️ Balance API: {result}")
                return 0.0

            data = result.get("data", [])
            
            if isinstance(data, list):
                for item in data:
                    if item.get("currency") == "USDT":
                        bal = float(item.get("availableBalance", 0))
                        logging.info(f"💰 Futures Balance: {bal} USDT")
                        return bal
            
            logging.warning("⚠️ USDT not found in response")
            return 0.0
            
        except Exception as e:
            logging.error(f"❌ Balance error: {e}")
            return 0.0

    def get_open_positions(self):
        """Відкриті позиції через Web API"""
        try:
            url = "https://contract.mexc.com/api/v1/private/position/open_positions"
            result = self._make_signed_request(url, {}, method="GET")
            
            if not result.get("success"):
                return []
            
            return result.get("data", [])
            
        except Exception as e:
            logging.error(f"❌ Positions error: {e}")
            return []

    def place_market_order(self, symbol, direction, quantity, leverage):
        """Відкриття позиції Market ордером"""
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
        
        logging.info(f"📤 Market Order Payload: {body_dict}")
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            return {"success": True, "dry_run": True}
        
        url = "https://contract.mexc.com/api/v1/private/order/create"
        result = self._make_signed_request(url, body_dict)
        return result

    def place_plan_order(self, symbol, side, trigger_price, quantity, position_id=None, order_type="tp"):
        """TP/SL ордер через stoporder/place endpoint"""
        if isinstance(quantity, float) and quantity.is_integer():
            quantity = int(quantity)
        
        body_dict = {
            "symbol": symbol,
            "side": side,
            "openType": 1,
            "vol": quantity,
            "stopLossPrice": trigger_price if order_type == "sl" else 0,
            "takeProfitPrice": trigger_price if order_type == "tp" else 0,
        }
        
        if position_id:
            body_dict["positionId"] = position_id
        
        logging.info(f"📤 [{order_type.upper()}] Setting {order_type.upper()} @ {trigger_price}")
        
        url = "https://contract.mexc.com/api/v1/private/stoporder/place"
        result = self._make_signed_request(url, body_dict)
        return result

    def set_sl_tp_for_position(self, symbol, direction, quantity, entry_price, sl_price, tp_price):
        """Виставлення TP і SL після відкриття позиції"""
        results = {"tp": None, "sl": None}
        close_side = 2 if direction == "LONG" else 4
        
        try:
            logging.info(f"⏳ Waiting 3 seconds for position {symbol} to settle...")
            time.sleep(3)
            
            positions = self.get_open_positions()
            
            if not positions:
                return {"tp": {"success": False, "error": "No positions"}, "sl": {"success": False, "error": "No positions"}}
            
            target_position = None
            for pos in positions:
                pos_symbol = pos.get("symbol")
                pos_vol = abs(float(pos.get("holdVol", 0)))
                pos_type = pos.get("positionType")  # 1=long, 2=short
                
                expected_type = 1 if direction == "LONG" else 2
                
                if pos_symbol == symbol and pos_vol > 0 and pos_type == expected_type:
                    target_position = pos
                    break
            
            if not target_position:
                logging.error(f"❌ Position {symbol} not found")
                return {"tp": {"success": False, "error": "Not found"}, "sl": {"success": False, "error": "Not found"}}
            
            position_id = target_position.get("positionId")
            actual_volume = abs(float(target_position.get("holdVol", quantity)))
            
            logging.info(f"🎯 Setting TP/SL for ID={position_id}, Vol={actual_volume}")
            
            # Setting TP
            tp_result = self.place_plan_order(symbol, close_side, tp_price, actual_volume, position_id, "tp")
            results["tp"] = tp_result
            
            time.sleep(0.5)
            
            # Setting SL
            sl_result = self.place_plan_order(symbol, close_side, sl_price, actual_volume, position_id, "sl")
            results["sl"] = sl_result
                
        except Exception as e:
            logging.error(f"❌ SL/TP Exception: {e}", exc_info=True)
        
        return results

# ==========================================
# 🎯 STATE MACHINE
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
    position_side: int = 0
    sl_order_placed: bool = False
    tp_order_placed: bool = False
    last_check: float = 0.0
    target_sl: float = 0.0
    target_tp: float = 0.0

class PositionManager:
    def __init__(self):
        self.positions: Dict[str, ManagedPosition] = {}
        self.opening_timeout = 30
    
    def add_signal(self, symbol: str, direction: str, sl_price: float, tp_price: float):
        self.positions[symbol] = ManagedPosition(
            symbol=symbol,
            state=PositionState.OPENING,
            signal_direction=direction,
            signal_time=time.time(),
            target_sl=sl_price,
            target_tp=tp_price
        )
    
    def update_from_exchange(self, exchange_positions: List[Dict]):
        exchange_symbols = {}
        for pos in exchange_positions:
            symbol = pos.get("symbol")
            size = abs(float(pos.get("holdVol", 0)))
            if size > 0:
                exchange_symbols[symbol] = {
                    "size": size,
                    "entry_price": float(pos.get("openAvgPrice", 0)),
                    "side": pos.get("positionType")
                }
        
        for symbol, managed in list(self.positions.items()):
            if managed.state == PositionState.OPENING:
                if symbol in exchange_symbols:
                    ex_pos = exchange_symbols[symbol]
                    managed.state = PositionState.POSITION_DETECTED
                    managed.current_size = ex_pos["size"]
                    managed.entry_price = ex_pos["entry_price"]
                    managed.position_side = ex_pos["side"]
                    logging.info(f"✅ POSITION OPENED: {symbol}")
                elif time.time() - managed.signal_time > self.opening_timeout:
                    logging.warning(f"⏱️ TIMEOUT: {symbol}")
                    del self.positions[symbol]
            elif managed.state in [PositionState.POSITION_DETECTED, PositionState.SL_TP_SET]:
                if symbol in exchange_symbols:
                    ex_pos = exchange_symbols[symbol]
                    managed.current_size = ex_pos["size"]
                else:
                    logging.warning(f"🔔 POSITION CLOSED: {symbol}")
                    del self.positions[symbol]
    
    def can_accept_signal(self, symbol: str) -> bool:
        return symbol not in self.positions
    
    def mark_sl_tp_placed(self, symbol: str):
        if symbol in self.positions:
            self.positions[symbol].sl_order_placed = True
            self.positions[symbol].tp_order_placed = True
            self.positions[symbol].state = PositionState.SL_TP_SET

# ==========================================
# 💰 RISK MANAGEMENT
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
        
        # Placeholder calculation (will be recalculated on entry)
        if direction == "LONG":
            sl_price = price * (1 - sl_pct / 100)
            tp_price = price * (1 + tp_pct / 100)
        else:
            sl_price = price * (1 + sl_pct / 100)
            tp_price = price * (1 - tp_pct / 100)
            
        return {"qty": qty, "sl_price": sl_price, "tp_price": tp_price}
    except:
        return None

# ==========================================
# 🔄 MONITORING LOOP
# ==========================================
async def position_monitoring_loop(web_client: MexcWebClient, manager: PositionManager, context):
    logging.info("🔄 Monitoring started")
    check_interval = 10
    
    while True:
        try:
            if len(manager.positions) == 0:
                await asyncio.sleep(check_interval)
                continue
            
            exchange_positions = web_client.get_open_positions()
            manager.update_from_exchange(exchange_positions)
            
            for symbol, managed in list(manager.positions.items()):
                if managed.state == PositionState.POSITION_DETECTED and not managed.sl_order_placed:
                    logging.info(f"🎯 Calculating actual TP/SL for {symbol}")
                    
                    # ✅ FIX TP/SL CALCULATION
                    try:
                        entry = float(managed.entry_price)
                        sl_pct_val = float(os.getenv("STOP_LOSS_PERCENT", 0.5)) / 100
                        tp_pct_val = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5)) / 100
                        
                        def get_precision(price_float):
                            s = f"{price_float:.10f}".rstrip('0')
                            return len(s.split('.')[1]) if '.' in s else 4
                            
                        prec = get_precision(entry)
                        
                        if managed.signal_direction == "LONG":
                            new_tp = entry * (1 + tp_pct_val)
                            new_sl = entry * (1 - sl_pct_val)
                        else: # SHORT
                            new_tp = entry * (1 - tp_pct_val)
                            new_sl = entry * (1 + sl_pct_val)
                            
                        managed.target_tp = round(new_tp, prec)
                        managed.target_sl = round(new_sl, prec)
                        
                    except Exception as e:
                        logging.error(f"Calc error: {e}")

                    result = web_client.set_sl_tp_for_position(
                        symbol=symbol,
                        direction=managed.signal_direction,
                        quantity=int(managed.current_size),
                        entry_price=managed.entry_price,
                        sl_price=managed.target_sl,
                        tp_price=managed.target_tp
                    )
                    
                    manager.mark_sl_tp_placed(symbol)
                    
                    # Send Report
                    target_id = os.getenv("SIGNAL_CHANNEL_ID")
                    
                    tp_ok = result['tp'].get('success')
                    sl_ok = result['sl'].get('success')
                    
                    msg = (
                        f"✅ <b>POSITION CONFIRMED</b>\n\n"
                        f"<b>Symbol:</b> {symbol}\n"
                        f"<b>Side:</b> {managed.signal_direction}\n"
                        f"<b>Entry:</b> ${managed.entry_price}\n"
                        f"<b>Size:</b> {managed.current_size}\n\n"
                        f"🎯 <b>TP:</b> ${managed.target_tp}\n"
                        f"🛑 <b>SL:</b> ${managed.target_sl}\n\n"
                        f"TP Status: {'✅' if tp_ok else '❌'}\n"
                        f"SL Status: {'✅' if sl_ok else '❌'}"
                    )
                    
                    # Додаємо помилки якщо є, але безпечно
                    if not tp_ok:
                        err = html.escape(str(result['tp'].get('error') or result['tp'].get('msg') or 'Unknown'))
                        msg += f"\n⚠️ TP Err: {err}"
                    if not sl_ok:
                        err = html.escape(str(result['sl'].get('error') or result['sl'].get('msg') or 'Unknown'))
                        msg += f"\n⚠️ SL Err: {err}"

                    await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
            
            await asyncio.sleep(check_interval)
            
        except Exception as e:
            logging.error(f"❌ Monitoring error: {e}")
            await asyncio.sleep(30)

# ==========================================
# 🤖 TELEGRAM HANDLER
# ==========================================
position_manager = None
mexc_web = None

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_web, position_manager
    
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    if str(update.effective_chat.id).strip() != target_id: return

    msg_text = update.channel_post.text or update.channel_post.caption or ""
    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    if not json_match: return
        
    try:
        data = json.loads(json_match.group(1))
        symbol_raw = str(data.get('symbol', '')).upper().replace('_', '').replace('USDT', '')
        symbol_api = f"{symbol_raw}_USDT"
        
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        my_direction = "LONG" if signal_type == "LONG_FLUSH" else "SHORT" if signal_type == "SHORT_SQUEEZE" else None
        if not my_direction: return

        if not position_manager.can_accept_signal(symbol_api): return

        balance = mexc_web.get_balance()
        if balance < 5:
            await context.bot.send_message(chat_id=target_id, text=f"❌ Low Balance: {balance} USDT")
            return

        risk = calculate_risk_params(balance, price, my_direction)
        position_manager.add_signal(symbol_api, my_direction, risk['sl_price'], risk['tp_price'])
        
        logging.info(f"🚀 Opening {my_direction} {symbol_api}, Qty: {risk['qty']}")

        res = mexc_web.place_market_order(symbol_api, my_direction, risk['qty'], int(os.getenv("LEVERAGE", 20)))
        
        if res.get("success") or res.get("dry_run"):
            msg = f"✅ <b>ORDER SENT</b>\n{symbol_api} {my_direction}\nWaiting for confirmation..."
            await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
        else:
            if symbol_api in position_manager.positions:
                del position_manager.positions[symbol_api]
            
            # ✅ FIX: Escape HTML in error message to prevent Telegram crash
            raw_error = str(res.get('msg') or res.get('error') or 'Unknown')
            safe_error = html.escape(raw_error)
            
            await context.bot.send_message(
                chat_id=target_id,
                text=f"❌ <b>ORDER FAILED</b>\n<pre>{safe_error}</pre>",
                parse_mode="HTML"
            )

    except Exception as e:
        logging.error(f"❌ Handler error: {e}", exc_info=True)

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        await application.bot.send_message(chat_id=target_id, text="🚀 <b>MEXC Bot Reloaded</b>", parse_mode='HTML')

def main():
    global mexc_web, position_manager
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    web_token = os.getenv("MEXC_TOKEN", "").strip()
    
    if not telegram_token or not web_token: return

    mexc_web = MexcWebClient(web_token)
    position_manager = PositionManager()
    
    async def init_and_start_monitoring(app):
        await post_init(app)
        asyncio.create_task(position_monitoring_loop(mexc_web, position_manager, app))
    
    application = ApplicationBuilder().token(telegram_token).post_init(init_and_start_monitoring).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 Bot started!")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()