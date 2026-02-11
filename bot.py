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
# ⏰ TRADING HOURS CHECK
# ==========================================
def is_trading_hours():
    """
    Перевіряє чи зараз дозволений час для торгівлі
    
    Returns:
        tuple: (is_allowed: bool, reason: str)
    """
    enabled = os.getenv("TRADING_HOURS_ENABLED", "false").lower() == "true"
    
    # Якщо вимкнено - торгуємо 24/7
    if not enabled:
        return True, "24/7 mode"
    
    try:
        start_hour = int(os.getenv("TRADING_START_HOUR_UTC", 0))
        end_hour = int(os.getenv("TRADING_END_HOUR_UTC", 23))
        
        # Валідація годин
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            logging.error(f"❌ Невірні години: start={start_hour}, end={end_hour}")
            return True, "Invalid hours config, trading allowed"
        
        # Поточний час UTC
        now_utc = datetime.utcnow()
        current_hour = now_utc.hour
        
        # Обробка випадку коли вікно перетинає добу (наприклад 22:00 → 05:00)
        if start_hour <= end_hour:
            # Звичайний випадок: 05:00 → 14:00
            in_trading_hours = start_hour <= current_hour < end_hour
        else:
            # Вікно через північ: 22:00 → 05:00
            in_trading_hours = current_hour >= start_hour or current_hour < end_hour
        
        if in_trading_hours:
            return True, f"Trading hours {start_hour:02d}:00-{end_hour:02d}:00 UTC"
        else:
            return False, f"Outside trading hours (current: {current_hour:02d}:00 UTC, allowed: {start_hour:02d}:00-{end_hour:02d}:00 UTC)"
            
    except Exception as e:
        logging.error(f"❌ Помилка перевірки trading hours: {e}")
        return True, "Error checking hours, trading allowed"

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
            logging.error(f"Помилка розшифрування: {e}")
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
        self.tick_cache = {}  # Кеш для tick sizes
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
            payload = {"ts": ts, "platform_type": 3, "product_type": 0, "sdk_v": "0.0.17", "mtoken": ""}
            resp = self.session.post(url, json=payload, headers=self.base_headers, timeout=10)
            data = resp.json()
            decrypted = self.crypto.sigma_decrypt(data["data"])
            self.config_obj = decrypted[27] if len(decrypted) > 27 else decrypted[-1]
            logging.info("✅ Web Config завантажено")
        except Exception as e:
            logging.error(f"❌ Помилка Config: {e}")

    def _make_signed_request(self, url, body_dict, method="POST"):
        """Універсальний підписаний запит з динамічним hostname"""
        try:
            if not self.config_obj:
                self.refresh_config()
            
            # Визначаємо hostname з URL
            if "www.mexc.com" in url:
                hostname = "www.mexc.com"
            elif "contract.mexc.com" in url:
                hostname = "contract.mexc.com"
            else:
                hostname = "contract.mexc.com"  # fallback
            
            ts = str(int(time.time() * 1000))
            mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
            
            # Шифруємо з правильним hostname
            p0, k0 = self.crypto.encrypt_request({
                "hostname": hostname,
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
            
            # Зберігаємо алгоритм підпису ТОЧНО
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
            
            # Додаємо заголовки для www.mexc.com
            if hostname == "www.mexc.com":
                headers["Host"] = "www.mexc.com"
                headers["Origin"] = "https://www.mexc.com"
                headers["Referer"] = "https://www.mexc.com/"
            
            logging.info(f"🔗 Запит: {method} {url}")
            logging.info(f"🏠 Hostname для encryption: {hostname}")
            logging.info(f"🔑 Auth fields: p0={len(p0)} chars, k0={len(k0)} chars, chash={bool(self.config_obj['chash'])}")
            
            if method == "GET":
                resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, data=body_json, headers=headers, timeout=10)
            
            logging.info(f"📥 Відповідь статус: {resp.status_code}")
            
            if resp.status_code == 403:
                logging.error("❌ 403 Forbidden. WAF заблокував запит.")
                return {"success": False, "error": "403 Forbidden"}

            if not resp.text.strip():
                logging.error("❌ Порожня відповідь від сервера")
                return {"success": False, "error": "Empty response"}
            
            try:
                return resp.json()
            except json.JSONDecodeError as e:
                logging.error(f"❌ Помилка JSON decode: {e}")
                logging.error(f"Response text: {resp.text[:500]}")
                return {"success": False, "error": f"Invalid JSON"}
            
        except Exception as e:
            logging.error(f"❌ Помилка запиту: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def get_tick_size(self, symbol):
        """Отримує tick size для символу"""
        if symbol in self.tick_cache:
            return self.tick_cache[symbol]
        
        try:
            # Спроба отримати через contract info
            url = "https://contract.mexc.com/api/v1/contract/detail"
            params = {"symbol": symbol}
            resp = self.session.get(url, params=params, timeout=5)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("data"):
                    tick = float(data["data"].get("priceUnit", 0.01))
                    self.tick_cache[symbol] = tick
                    logging.info(f"📐 Tick size для {symbol}: {tick}")
                    return tick
        except Exception as e:
            logging.warning(f"Не вдалося отримати tick size для {symbol}: {e}")
        
        # Fallback на основі ціни
        logging.warning(f"Використовую fallback tick size для {symbol}")
        return 0.001  # Універсальний fallback

    def round_to_tick(self, price, tick, mode="nearest"):
        """
        Округлює ціну до tick size
        mode: 'up', 'down', 'nearest'
        """
        if tick <= 0:
            tick = 0.001
        
        if mode == "up":
            return round((price // tick + 1) * tick, 10)
        elif mode == "down":
            return round((price // tick) * tick, 10)
        else:  # nearest
            return round(round(price / tick) * tick, 10)

    def calculate_tp_sl(self, entry_price, direction, tp_percent, sl_percent, tick):
        """
        Розраховує TP/SL з правильним округленням та валідацією
        
        Returns: (tp_price, sl_price)
        """
        logging.info(f"📊 Розрахунок TP/SL:")
        logging.info(f"  Entry: {entry_price}, Direction: {direction}")
        logging.info(f"  TP%: {tp_percent*100}%, SL%: {sl_percent*100}%")
        logging.info(f"  Tick size: {tick}")
        
        # Розрахунок сирих значень
        if direction == "LONG":
            tp_raw = entry_price * (1 + tp_percent)
            sl_raw = entry_price * (1 - sl_percent)
            
            # Округлення для LONG: обидва DOWN
            tp_price = self.round_to_tick(tp_raw, tick, "down")
            sl_price = self.round_to_tick(sl_raw, tick, "down")
            
        else:  # SHORT
            tp_raw = entry_price * (1 - tp_percent)
            sl_raw = entry_price * (1 + sl_percent)
            
            # Округлення для SHORT: обидва UP
            tp_price = self.round_to_tick(tp_raw, tick, "up")
            sl_price = self.round_to_tick(sl_raw, tick, "up")
        
        logging.info(f"  TP raw: {tp_raw} -> rounded: {tp_price}")
        logging.info(f"  SL raw: {sl_raw} -> rounded: {sl_price}")
        
        # Валідація та корекція
        if direction == "LONG":
            # LONG: TP > entry, SL < entry
            if tp_price <= entry_price:
                tp_price = entry_price + tick
                logging.warning(f"⚠️ TP скориговано: {tp_price}")
            if sl_price >= entry_price:
                sl_price = entry_price - tick
                logging.warning(f"⚠️ SL скориговано: {sl_price}")
        else:  # SHORT
            # SHORT: TP < entry, SL > entry
            if tp_price >= entry_price:
                tp_price = entry_price - tick
                logging.warning(f"⚠️ TP скориговано: {tp_price}")
            if sl_price <= entry_price:
                sl_price = entry_price + tick
                logging.warning(f"⚠️ SL скориговано: {sl_price}")
        
        logging.info(f"✅ Фінальні значення: TP={tp_price}, SL={sl_price}")
        
        return tp_price, sl_price

    def open_position_with_sl_tp(self, symbol, direction, quantity, leverage, tp_price, sl_price):
        """
        Відкриває позицію з TP/SL в одному запиті через UI endpoint
        """
        side = 1 if direction == "LONG" else 3  # 1=Open Long, 3=Open Short
        
        if isinstance(quantity, float) and quantity.is_integer():
            quantity = int(quantity)
        
        # ТОЧНА структура з DevTools
        body_dict = {
            "symbol": symbol,
            "side": side,
            "openType": 1,
            "type": "5",  # STRING, market order
            "vol": quantity,
            "positionMode": 2,  # З DevTools
            "marketCeiling": False,
            "leverage": int(leverage),
            "takeProfitPrice": str(tp_price),  # STRING!
            "stopLossPrice": str(sl_price),    # STRING!
            "profitTrend": "1",  # STRING!
            "lossTrend": "1",    # STRING!
            "priceProtect": "0"  # STRING!
        }
        
        logging.info(f"📤 Відкриття позиції з TP/SL:")
        logging.info(f"  Symbol: {symbol}, Side: {side} ({direction})")
        logging.info(f"  Quantity: {quantity}, Leverage: {leverage}")
        logging.info(f"  TP: {tp_price} (string: '{body_dict['takeProfitPrice']}')")
        logging.info(f"  SL: {sl_price} (string: '{body_dict['stopLossPrice']}')")
        logging.info(f"  profitTrend: '{body_dict['profitTrend']}', lossTrend: '{body_dict['lossTrend']}'")
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            logging.info("🧪 DRY RUN MODE - не відправляю запит")
            return {"success": True, "dry_run": True}
        
        # ПРАВИЛЬНИЙ UI endpoint
        url = "https://www.mexc.com/api/platform/futures/api/v1/private/order/create"
        result = self._make_signed_request(url, body_dict)
        
        return result

    def get_balance(self):
        try:
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            result = self._make_signed_request(url, {}, method="GET")
            
            if not result.get("success"):
                return 0.0

            data = result.get("data", [])
            if isinstance(data, list):
                for item in data:
                    if item.get("currency") == "USDT":
                        bal = float(item.get("availableBalance", 0))
                        logging.info(f"💰 Баланс Futures: {bal} USDT")
                        return bal
            return 0.0
        except Exception as e:
            logging.error(f"❌ Помилка балансу: {e}")
            return 0.0

    def get_open_positions(self):
        """Отримує всі відкриті позиції з біржі"""
        try:
            url = "https://contract.mexc.com/api/v1/private/position/open_positions"
            result = self._make_signed_request(url, {}, method="GET")
            if not result.get("success"):
                return []
            return result.get("data", [])
        except Exception as e:
            logging.error(f"❌ Помилка позицій: {e}")
            return []

# ==========================================
# 🎯 STATE MACHINE
# ==========================================
class PositionState(Enum):
    NO_POSITION = "no_position"
    OPENING = "opening"
    POSITION_DETECTED = "position_detected"

@dataclass
class ManagedPosition:
    symbol: str
    state: PositionState
    signal_direction: str
    signal_time: float
    current_size: float = 0.0
    entry_price: float = 0.0
    position_side: int = 0
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
        logging.info(f"📡 Сигнал: {symbol} {direction}")
    
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
                    logging.info(f"✅ ПОЗИЦІЯ ВІДКРИТА: {symbol}")
                elif time.time() - managed.signal_time > self.opening_timeout:
                    logging.warning(f"⏱️ ТАЙМАУТ: {symbol}")
                    del self.positions[symbol]
            elif managed.state == PositionState.POSITION_DETECTED:
                if symbol in exchange_symbols:
                    ex_pos = exchange_symbols[symbol]
                    managed.current_size = ex_pos["size"]
                else:
                    logging.warning(f"🔔 ПОЗИЦІЯ ЗАКРИТА: {symbol}")
                    del self.positions[symbol]
    
    def can_accept_signal(self, symbol: str) -> bool:
        return symbol not in self.positions

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
        
        # Повертаємо лише кількість та відсотки
        # TP/SL будуть розраховані від реальної ціни входу
        return {
            "qty": qty, 
            "tp_percent": tp_pct / 100,  # 0.005 для 0.5%
            "sl_percent": sl_pct / 100
        }
    except:
        return None

# ==========================================
# 🔄 MONITORING LOOP
# ==========================================
async def position_monitoring_loop(web_client: MexcWebClient, manager: PositionManager, context):
    logging.info("🔄 Моніторинг запущено")
    check_interval = 10
    
    while True:
        try:
            if len(manager.positions) == 0:
                await asyncio.sleep(check_interval)
                continue
            
            exchange_positions = web_client.get_open_positions()
            manager.update_from_exchange(exchange_positions)
            
            # Повідомлення про підтверджені позиції
            for symbol, managed in list(manager.positions.items()):
                if managed.state == PositionState.POSITION_DETECTED and managed.entry_price > 0:
                    target_id = os.getenv("SIGNAL_CHANNEL_ID")
                    
                    msg = (
                        f"✅ <b>ПОЗИЦІЯ ПІДТВЕРДЖЕНА</b>\n\n"
                        f"<b>Символ:</b> {symbol}\n"
                        f"<b>Бік:</b> {managed.signal_direction}\n"
                        f"<b>Вхід:</b> ${managed.entry_price}\n"
                        f"<b>Розмір:</b> {managed.current_size}\n\n"
                        f"🎯 <b>TP:</b> ${managed.target_tp}\n"
                        f"🛑 <b>SL:</b> ${managed.target_sl}\n\n"
                        f"ℹ️ TP/SL встановлені при відкритті"
                    )
                    
                    await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
                    
                    # Видаляємо з менеджера після повідомлення
                    del manager.positions[symbol]
            
            await asyncio.sleep(check_interval)
            
        except Exception as e:
            logging.error(f"❌ Помилка моніторингу: {e}")
            await asyncio.sleep(30)

# ==========================================
# 🤖 TELEGRAM HANDLER
# ==========================================
position_manager = None
mexc_web = None
last_pause_notification = 0  # Timestamp останнього повідомлення про паузу

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
            await context.bot.send_message(chat_id=target_id, text=f"❌ Низький баланс: {balance} USDT")
            return

        # ⏰ ПЕРЕВІРКА РОБОЧИХ ГОДИН
        global last_pause_notification
        is_allowed, reason = is_trading_hours()
        
        if not is_allowed:
            logging.info(f"⏸️ Торгівля призупинена: {reason}")
            
            # Відправляємо повідомлення максимум раз на годину
            current_time = time.time()
            if current_time - last_pause_notification > 3600:  # 1 година
                last_pause_notification = current_time
                
                pause_msg = (
                    f"⏸️ <b>ТОРГІВЛЯ ПРИЗУПИНЕНА</b>\n\n"
                    f"📊 Сигнал: {symbol_api} {my_direction}\n"
                    f"⏰ {reason}\n\n"
                    f"ℹ️ Бот продовжить торгівлю в робочі години"
                )
                await context.bot.send_message(chat_id=target_id, text=pause_msg, parse_mode="HTML")
            
            return  # Виходимо без відкриття позиції

        risk = calculate_risk_params(balance, price, my_direction)
        
        # Отримуємо tick size
        tick = mexc_web.get_tick_size(symbol_api)
        
        # Розраховуємо TP/SL від поточної ціни (як approximation)
        tp_price, sl_price = mexc_web.calculate_tp_sl(
            entry_price=price,
            direction=my_direction,
            tp_percent=risk['tp_percent'],
            sl_percent=risk['sl_percent'],
            tick=tick
        )
        
        position_manager.add_signal(symbol_api, my_direction, sl_price, tp_price)
        
        logging.info(f"🚀 Відкриваю {my_direction} {symbol_api}, Кількість: {risk['qty']}")

        res = mexc_web.open_position_with_sl_tp(
            symbol=symbol_api,
            direction=my_direction,
            quantity=risk['qty'],
            leverage=int(os.getenv("LEVERAGE", 20)),
            tp_price=tp_price,
            sl_price=sl_price
        )
        
        if res.get("success") or res.get("dry_run"):
            msg = (
                f"✅ <b>ОРДЕР ВІДПРАВЛЕНО</b>\n\n"
                f"{symbol_api} {my_direction}\n"
                f"Розмір: {risk['qty']}\n"
                f"🎯 TP: ${tp_price}\n"
                f"🛑 SL: ${sl_price}\n\n"
                f"Очікування підтвердження..."
            )
            await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
        else:
            if symbol_api in position_manager.positions:
                del position_manager.positions[symbol_api]
            
            error_msg = res.get('msg') or res.get('error') or 'Невідома помилка'
            safe_error = str(error_msg).replace('<', '').replace('>', '')
            
            await context.bot.send_message(
                chat_id=target_id,
                text=f"❌ <b>ОРДЕР ПРОВАЛИВСЯ</b>\n{safe_error}",
                parse_mode="HTML"
            )

    except Exception as e:
        logging.error(f"❌ Помилка обробника: {e}", exc_info=True)

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        # Перевіряємо статус trading hours
        is_allowed, reason = is_trading_hours()
        hours_enabled = os.getenv("TRADING_HOURS_ENABLED", "false").lower() == "true"
        
        status_icon = "✅" if is_allowed else "⏸️"
        mode_text = f"<i>Режим: {'Обмежені години' if hours_enabled else '24/7'}</i>\n"
        hours_text = f"<i>{reason}</i>" if hours_enabled else ""
        
        startup_msg = (
            f"🚀 <b>MEXC Bot v2.0 Запущено</b>\n"
            f"{mode_text}"
            f"{hours_text}\n"
            f"{status_icon} <i>{'Торгівля активна' if is_allowed else 'Торгівля призупинена'}</i>\n\n"
            f"<i>TP/SL в одному запиті</i>"
        )
        
        await application.bot.send_message(chat_id=target_id, text=startup_msg, parse_mode='HTML')

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
    
    logging.info("🤖 Бот запущено!")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
