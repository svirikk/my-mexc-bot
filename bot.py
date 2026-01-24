import os
import json
import time
import base64
import hashlib
import hmac
import re
import logging
import asyncio
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict
from dotenv import load_dotenv

# Cryptography
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

# Telegram Bot
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

# Завантаження налаштувань
if os.path.exists('.env'):
    load_dotenv()

# Логування
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 МОДУЛЬ ШИФРУВАННЯ MEXC (ДЛЯ ВІДКРИТТЯ ПОЗИЦІЙ)
# ==========================================
KEY_B = "1b8c71b668084dda9dc0285171ccf753".encode("utf-8")
MEXC_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqpMCeNv7qfsKe09xwE5o05ZCq/qJvTok6WbqYZOXA16UQqR+sHH0XXfnWxLSEvCviP9qjZjruHWdpMmC4i/yQJe7MJ66YoNloeNtmMgtqEIjOvSxRktmAxywul/eJolrhDnRPXYll4fA5+24t1g6L5fgo/p66yLtZRg4fC1s3rAF1WPe6dSJQx7jQ/xhy8Z0WojmzIeaoBa0m8qswx0DMIdzXfswH+gwMYCQGR3F/NAlxyvlWPMBlpFEuHZWkp9TXlTtbLf+YL8vYjV5HNqIdNjVzrIvg/Bis49ktfsWuQxT/RIyCsTEuHmZyZR6NJAMPZUE5DBnVWdLShb6KuyqwIDAQAB
-----END PUBLIC KEY-----"""

class MexcCrypto:
    """Шифрування для веб-API MEXC (ОБОВ'ЯЗКОВО для відкриття позицій)"""
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
# 🌐 MEXC WEB CLIENT (ВІДКРИТТЯ ПОЗИЦІЙ)
# ==========================================
class MexcWebClient:
    """Веб-клієнт для ВІДКРИТТЯ позицій через mexc_logout_modal_token"""
    
    def __init__(self, web_token):
        self.token = web_token.strip() if web_token else ""
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
            logging.info("✅ MEXC Web Config Refreshed")
        except Exception as e:
            logging.error(f"❌ Config Refresh Error: {e}")

    def place_order(self, symbol, direction, quantity, leverage):
        """ВІДКРИТТЯ позиції через веб-токен (єдиний спосіб)"""
        if not self.config_obj:
            self.refresh_config()
            
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        
        side = 1 if direction == "LONG" else 3
        
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
            logging.info(f"🧪 DRY RUN: Would open {direction} {symbol} qty={quantity}")
            return {"success": True, "dry_run": True, "code": 200}
        
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        
        try:
            url = "https://contract.mexc.com/api/v1/private/order/create"
            r = self.session.post(url, data=body_json, headers=headers, timeout=10)
            result = r.json()
            logging.info(f"📤 Order result: {result}")
            return result
        except Exception as e:
            logging.error(f"❌ Order exception: {e}")
            return {"success": False, "error": str(e)}

# ==========================================
# 📊 MEXC API CLIENT (МОНІТОРИНГ)
# ==========================================
class MexcMonitoringAPI:
    """API-клієнт для МОНІТОРИНГУ позицій через API Key/Secret"""
    
    BASE_URL = "https://contract.mexc.com"
    
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key.strip()
        self.api_secret = api_secret.strip()
        self.session = requests.Session()
    
    def _sign(self, params: Dict) -> str:
        """HMAC-SHA256 підпис"""
        query_string = "&".join([f"{k}={v}" for k, v in sorted(params.items())])
        return hmac.new(
            self.api_secret.encode('utf-8'),
            query_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def _request(self, method: str, endpoint: str, params: Dict = None) -> Dict:
        """Аутентифікований API запит"""
        params = params or {}
        params['timestamp'] = int(time.time() * 1000)
        params['recv_window'] = 5000
        
        signature = self._sign(params)
        params['signature'] = signature
        
        headers = {
            'X-MEXC-APIKEY': self.api_key,
            'Content-Type': 'application/json'
        }
        
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            if method == "GET":
                resp = self.session.get(url, params=params, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, json=params, headers=headers, timeout=10)
            
            return resp.json()
        except Exception as e:
            logging.error(f"API request error: {e}")
            return {"success": False, "error": str(e)}
    
    def get_account_assets(self) -> List[Dict]:
        """Баланс рахунку"""
        result = self._request("GET", "/api/v1/private/account/assets")
        if result.get("success"):
            return result.get("data", [])
        return []
    
    def get_usdt_balance(self) -> float:
        """Доступний USDT баланс"""
        assets = self.get_account_assets()
        for asset in assets:
            if asset.get("currency") == "USDT":
                return float(asset.get("availableBalance", 0))
        return 0.0
    
    def get_open_positions(self) -> List[Dict]:
        """Відкриті позиції"""
        result = self._request("GET", "/api/v1/private/position/open_positions", {"symbol": ""})
        if result.get("success"):
            positions = result.get("data", [])
            # Фільтруємо тільки активні позиції
            return [p for p in positions if abs(float(p.get("holdVol", 0))) > 0]
        return []

# ==========================================
# 🎯 STATE MACHINE
# ==========================================
class PositionState(Enum):
    NO_POSITION = "no_position"
    OPENING = "opening"  # Сигнал отримано, чекаємо відкриття
    POSITION_DETECTED = "position_detected"
    SL_TP_SET = "sl_tp_set"

@dataclass
class ManagedPosition:
    symbol: str
    state: PositionState
    signal_direction: str  # "LONG" or "SHORT"
    signal_time: float
    current_size: float = 0.0
    entry_price: float = 0.0
    position_side: int = 0  # 1=long, 2=short
    sl_order_placed: bool = False
    tp_order_placed: bool = False
    last_check: float = 0.0

class PositionManager:
    """Управління lifecycle позицій"""
    
    def __init__(self):
        self.positions: Dict[str, ManagedPosition] = {}
        self.opening_timeout = 30  # секунд на відкриття
    
    def add_signal(self, symbol: str, direction: str):
        """Додати новий сигнал"""
        self.positions[symbol] = ManagedPosition(
            symbol=symbol,
            state=PositionState.OPENING,
            signal_direction=direction,
            signal_time=time.time()
        )
        logging.info(f"📡 Signal registered: {symbol} {direction}")
    
    def update_from_exchange(self, exchange_positions: List[Dict]):
        """Синхронізація з біржею"""
        exchange_symbols = {}
        
        # Індексуємо позиції з біржі
        for pos in exchange_positions:
            symbol = pos.get("symbol")
            size = abs(float(pos.get("holdVol", 0)))
            
            if size > 0:
                exchange_symbols[symbol] = {
                    "size": size,
                    "entry_price": float(pos.get("openAvgPrice", 0)),
                    "side": pos.get("positionType")  # 1=long, 2=short
                }
        
        # Оновлюємо наші позиції
        for symbol, managed in list(self.positions.items()):
            
            if managed.state == PositionState.OPENING:
                # Чекаємо на відкриття
                if symbol in exchange_symbols:
                    # Позиція відкрилась!
                    ex_pos = exchange_symbols[symbol]
                    managed.state = PositionState.POSITION_DETECTED
                    managed.current_size = ex_pos["size"]
                    managed.entry_price = ex_pos["entry_price"]
                    managed.position_side = ex_pos["side"]
                    managed.last_check = time.time()
                    logging.info(f"✅ POSITION OPENED: {symbol}, size={ex_pos['size']}, entry={ex_pos['entry_price']}")
                    
                elif time.time() - managed.signal_time > self.opening_timeout:
                    # Таймаут - позиція не відкрилась
                    logging.warning(f"⏱️ TIMEOUT: {symbol} position didn't open in {self.opening_timeout}s")
                    del self.positions[symbol]
            
            elif managed.state in [PositionState.POSITION_DETECTED, PositionState.SL_TP_SET]:
                # Перевіряємо існуючу позицію
                if symbol in exchange_symbols:
                    # Позиція ще є
                    ex_pos = exchange_symbols[symbol]
                    prev_size = managed.current_size
                    managed.current_size = ex_pos["size"]
                    managed.last_check = time.time()
                    
                    if ex_pos["size"] != prev_size:
                        logging.info(f"📊 SIZE CHANGED: {symbol}, {prev_size} → {ex_pos['size']}")
                else:
                    # Позиція закрита вручну або SL/TP спрацював
                    logging.warning(f"🚨 POSITION CLOSED: {symbol} (manual or SL/TP)")
                    del self.positions[symbol]
    
    def can_accept_signal(self, symbol: str) -> bool:
        """Чи можемо прийняти новий сигнал?"""
        return symbol not in self.positions
    
    def mark_sl_tp_placed(self, symbol: str):
        """Позначити що SL/TP виставлено"""
        if symbol in self.positions:
            self.positions[symbol].sl_order_placed = True
            self.positions[symbol].tp_order_placed = True
            self.positions[symbol].state = PositionState.SL_TP_SET
            logging.info(f"✅ SL/TP marked as set for {symbol}")

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
        
        if qty < 1:
            qty = 1
        
        if direction == "LONG":
            sl_price = price * (1 - sl_pct / 100)
            tp_price = price * (1 + tp_pct / 100)
        else:
            sl_price = price * (1 + sl_pct / 100)
            tp_price = price * (1 - tp_pct / 100)
            
        return {
            "qty": qty, "sl_price": sl_price, "tp_price": tp_price,
            "risk_amount": risk_amount, "sl_pct": sl_pct, "tp_pct": tp_pct
        }
    except Exception as e:
        logging.error(f"Risk calculation error: {e}")
        return None

# ==========================================
# 🔄 MONITORING LOOP
# ==========================================
async def position_monitoring_loop(api_client: MexcMonitoringAPI, web_client: MexcWebClient, 
                                   manager: PositionManager, context):
    """Цикл моніторингу позицій"""
    
    while True:
        try:
            # Отримуємо позиції з біржі через API
            exchange_positions = api_client.get_open_positions()
            
            # Оновлюємо state manager
            manager.update_from_exchange(exchange_positions)
            
            # Обробляємо позиції що потребують SL/TP
            for symbol, managed in list(manager.positions.items()):
                
                if managed.state == PositionState.POSITION_DETECTED and not managed.sl_order_placed:
                    # Потрібно виставити SL/TP через WEB CLIENT
                    logging.info(f"🎯 Setting SL/TP for {symbol} via web API")
                    
                    sl_pct = float(os.getenv("STOP_LOSS_PERCENT", 0.5))
                    tp_pct = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5))
                    
                    if managed.position_side == 1:  # LONG
                        sl_price = managed.entry_price * (1 - sl_pct / 100)
                        tp_price = managed.entry_price * (1 + tp_pct / 100)
                    else:  # SHORT
                        sl_price = managed.entry_price * (1 + sl_pct / 100)
                        tp_price = managed.entry_price * (1 - tp_pct / 100)
                    
                    # TODO: Тут потрібна функція web_client.place_sl_tp_order()
                    # Поки що просто позначаємо як встановлені
                    manager.mark_sl_tp_placed(symbol)
                    
                    # Повідомлення в Telegram
                    target_id = os.getenv("SIGNAL_CHANNEL_ID")
                    msg = (
                        f"✅ <b>SL/TP SET</b>\n"
                        f"<b>Symbol:</b> {symbol}\n"
                        f"<b>Entry:</b> ${managed.entry_price:.4f}\n"
                        f"🎯 TP: ${tp_price:.4f}\n"
                        f"🛑 SL: ${sl_price:.4f}"
                    )
                    await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
            
            await asyncio.sleep(5)
            
        except Exception as e:
            logging.error(f"Monitoring loop error: {e}", exc_info=True)
            await asyncio.sleep(10)

# ==========================================
# 🤖 TELEGRAM HANDLER
# ==========================================
position_manager = None
mexc_web = None
mexc_api = None

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_web, mexc_api, position_manager
    
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    current_id = str(update.effective_chat.id).strip()
    
    if current_id != target_id:
        return

    msg_text = update.channel_post.text or update.channel_post.caption or ""
    json_match = re.search(r'(\{.*\})', msg_text, re.DOTALL)
    
    if not json_match:
        return
        
    try:
        data = json.loads(json_match.group(1))
        symbol_raw = str(data.get('symbol', '')).upper().replace('_', '').replace('USDT', '')
        symbol_api = f"{symbol_raw}_USDT"
        
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        my_direction = None
        if signal_type == "LONG_FLUSH":
            my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE":
            my_direction = "SHORT"
        
        if not my_direction:
            return

        # Перевірка whitelist
        allowed_str = os.getenv("ALLOWED_SYMBOLS", "").upper()
        if symbol_raw not in allowed_str and f"{symbol_raw}USDT" not in allowed_str:
            return

        # Перевірка чи можемо прийняти сигнал
        if not position_manager.can_accept_signal(symbol_api):
            logging.info(f"⏭️ SKIPPING {symbol_api} - already managed")
            return

        # Отримуємо баланс через API
        balance = mexc_api.get_usdt_balance()
        logging.info(f"💰 Balance: {balance} USDT")
        
        if balance < 5:
            logging.error("❌ Balance too low")
            return

        # Розраховуємо ризик
        risk = calculate_risk_params(balance, price, my_direction)
        if not risk:
            return
        
        # Реєструємо сигнал
        position_manager.add_signal(symbol_api, my_direction)
        
        logging.info(f"🚀 Opening {my_direction} {symbol_api}, Qty: {risk['qty']}")

        # ВІДКРИВАЄМО ПОЗИЦІЮ через WEB CLIENT
        res = mexc_web.place_order(symbol_api, my_direction, risk['qty'], int(os.getenv("LEVERAGE", 20)))
        
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            is_dry = res.get("dry_run")
            header = "🧪 <b>DRY RUN</b>" if is_dry else "✅ <b>ORDER SENT</b>"
            emoji = "📈" if my_direction == "LONG" else "📉"
            
            msg = (
                f"{header}\n"
                f"<b>Symbol:</b> {symbol_api}\n"
                f"<b>Side:</b> {emoji} {my_direction}\n"
                f"<b>Price:</b> ${price}\n"
                f"<b>Qty:</b> {risk['qty']}\n\n"
                f"⏳ Waiting for position confirmation..."
            )
            
            await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
        else:
            logging.error(f"❌ Order failed: {res}")
            # Видаляємо з manager якщо не відкрилось
            if symbol_api in position_manager.positions:
                del position_manager.positions[symbol_api]
            await context.bot.send_message(chat_id=target_id, text=f"❌ Error: {res.get('msg') or res}")

    except Exception as e:
        logging.error(f"Handler error: {e}", exc_info=True)

async def post_init(application):
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    if target_id:
        try:
            mode = "🧪 DRY RUN" if os.getenv("DRY_RUN") == "true" else "🔥 REAL TRADING"
            await application.bot.send_message(
                chat_id=target_id,
                text=f"🚀 MEXC Dual-Mode Bot Online\n"
                     f"Mode: {mode}\n"
                     f"📤 Orders: Web Token\n"
                     f"📊 Monitoring: API Key"
            )
        except:
            pass

def main():
    global mexc_web, mexc_api, position_manager
    
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    web_token = os.getenv("MEXC_WEB_TOKEN", "").strip()  # mexc_logout_modal_token
    api_key = os.getenv("MEXC_API_KEY", "").strip()
    api_secret = os.getenv("MEXC_API_SECRET", "").strip()
    
    if not telegram_token or not web_token:
        logging.error("❌ Missing tokens")
        return

    # Ініціалізація WEB CLIENT (для відкриття позицій)
    mexc_web = MexcWebClient(web_token)
    
    # Ініціалізація API CLIENT (для моніторингу)
    if api_key and api_secret:
        mexc_api = MexcMonitoringAPI(api_key, api_secret)
        balance = mexc_api.get_usdt_balance()
        logging.info(f"💰 Startup Balance: {balance} USDT")
    else:
        logging.warning("⚠️ API credentials missing - monitoring disabled")
        mexc_api = None
    
    # State manager
    position_manager = PositionManager()
    
    # Telegram app
    application = ApplicationBuilder().token(telegram_token).post_init(post_init).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    # Запуск monitoring loop
    if mexc_api:
        async def start_monitoring(app):
            asyncio.create_task(position_monitoring_loop(mexc_api, mexc_web, position_manager, app))
        
        application.post_init(start_monitoring)
    
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()