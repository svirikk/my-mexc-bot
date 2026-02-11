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
        self.contract_size_cache = {}  # ✨ НОВИЙ КЕШ для contract sizes
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
            
            if resp.status_code == 200:
                return resp.json()
            else:
                logging.error(f"❌ HTTP {resp.status_code}: {resp.text[:200]}")
                return {"code": resp.status_code, "msg": resp.text[:200]}
                
        except Exception as e:
            logging.error(f"❌ Помилка запиту: {e}")
            return {"code": -1, "msg": str(e)}

    # ✨ НОВИЙ МЕТОД: Отримання інформації про контракт
    def get_contract_info(self, symbol: str) -> Dict:
        """
        Отримує інформацію про контракт з біржі.
        Повертає: {
            'contractSize': float,  # Скільки монет в 1 контракті (0.1 для HYPE)
            'minQty': float,        # Мінімальна кількість контрактів
            'tickSize': float       # Tick size для ціни
        }
        """
        try:
            url = "https://contract.mexc.com/api/v1/contract/detail"
            params = {"symbol": symbol}
            
            resp = self.session.get(url, params=params, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and data.get("data"):
                    contract_data = data["data"]
                    
                    # contractSize - скільки монет в одному контракті
                    contract_size = float(contract_data.get("contractSize", 1))
                    
                    # minVol - мінімальна кількість контрактів
                    min_qty = float(contract_data.get("minVol", 1))
                    
                    # priceUnit - tick size для ціни
                    tick_size = float(contract_data.get("priceUnit", 0.01))
                    
                    logging.info(
                        f"📊 {symbol}: contractSize={contract_size}, "
                        f"minQty={min_qty}, tickSize={tick_size}"
                    )
                    
                    return {
                        'contractSize': contract_size,
                        'minQty': min_qty,
                        'tickSize': tick_size
                    }
            
            logging.warning(f"⚠️ Не вдалося отримати інфо для {symbol}, використовую defaults")
            return {'contractSize': 1.0, 'minQty': 1.0, 'tickSize': 0.01}
            
        except Exception as e:
            logging.error(f"❌ Помилка get_contract_info для {symbol}: {e}")
            return {'contractSize': 1.0, 'minQty': 1.0, 'tickSize': 0.01}

    # ✨ ОНОВЛЕНИЙ МЕТОД: Завантаження contract sizes для всіх дозволених монет
    def load_contract_sizes(self, allowed_symbols: List[str]):
        """
        Завантажує contract sizes для всіх дозволених монет при старті бота.
        Кешує результати для швидкого доступу.
        """
        logging.info("📥 Завантажую інформацію про контракти...")
        
        for symbol in allowed_symbols:
            info = self.get_contract_info(symbol)
            self.contract_size_cache[symbol] = info
            
            # Також оновлюємо tick_cache
            self.tick_cache[symbol] = info['tickSize']
            
            # Невелика пауза між запитами
            time.sleep(0.2)
        
        logging.info(f"✅ Завантажено інфо для {len(self.contract_size_cache)} монет")

    def get_tick_size(self, symbol: str) -> float:
        """Повертає tick size для символу (з кешу або дефолтне значення)"""
        if symbol in self.tick_cache:
            return self.tick_cache[symbol]
        
        # Якщо немає в кеші, пробуємо отримати
        if symbol in self.contract_size_cache:
            return self.contract_size_cache[symbol]['tickSize']
        
        # Дефолтне значення
        return 0.01

    def round_to_tick(self, price: float, tick: float) -> float:
        """Округлює ціну до найближчого tick size"""
        if tick <= 0:
            return round(price, 2)
        return round(price / tick) * tick

    def calculate_tp_sl(self, entry_price: float, direction: str, tp_percent: float, sl_percent: float, tick: float):
        """Розраховує ціни TP та SL"""
        if direction == "LONG":
            tp_raw = entry_price * (1 + tp_percent / 100)
            sl_raw = entry_price * (1 - sl_percent / 100)
        else:  # SHORT
            tp_raw = entry_price * (1 - tp_percent / 100)
            sl_raw = entry_price * (1 + sl_percent / 100)
        
        tp = self.round_to_tick(tp_raw, tick)
        sl = self.round_to_tick(sl_raw, tick)
        
        return tp, sl

    def get_balance(self) -> float:
        """Отримує доступний баланс USDT"""
        url = "https://contract.mexc.com/api/v1/private/account/assets"
        body = {}
        
        result = self._make_signed_request(url, body)
        
        if result.get("success"):
            data = result.get("data", [])
            for asset in data:
                if asset.get("currency") == "USDT":
                    available = float(asset.get("availableBalance", 0))
                    logging.info(f"💰 Баланс: {available} USDT")
                    return available
        
        logging.warning("⚠️ Не вдалося отримати баланс")
        return 0.0

    def get_open_positions(self) -> List[Dict]:
        """Отримує список відкритих позицій"""
        url = "https://contract.mexc.com/api/v1/private/position/open_positions"
        body = {}
        
        result = self._make_signed_request(url, body)
        
        if result.get("success"):
            positions = result.get("data", [])
            logging.info(f"📊 Відкритих позицій: {len(positions)}")
            return positions
        
        return []

    def open_position_with_sl_tp(self, symbol: str, direction: str, quantity: float, leverage: int, tp_price: float, sl_price: float) -> Dict:
        """
        Відкриває позицію з автоматичним встановленням TP/SL в одному запиті.
        
        ✨ ОНОВЛЕНО: quantity тепер вже в контрактах (не потрібно додаткове перетворення)
        """
        dry_run = os.getenv("DRY_RUN", "false").lower() == "true"
        
        if dry_run:
            logging.info(f"🧪 DRY RUN: {direction} {symbol}, qty={quantity}, lev={leverage}, tp={tp_price}, sl={sl_price}")
            return {"dry_run": True, "msg": "DRY RUN mode"}

        try:
            # Отримуємо поточну ціну для розрахунку vol (approximate)
            url_price = "https://contract.mexc.com/api/v1/contract/ticker"
            resp = self.session.get(url_price, params={"symbol": symbol}, timeout=10)
            current_price = 1.0
            
            if resp.status_code == 200:
                ticker_data = resp.json()
                if ticker_data.get("success") and ticker_data.get("data"):
                    current_price = float(ticker_data["data"][0].get("lastPrice", 1))

            # vol = quantity * current_price (approximate)
            vol = int(quantity * current_price)
            
            url = "https://www.mexc.com/api/contract/private/order/submit"
            
            body = {
                "symbol": symbol,
                "price": 0,
                "vol": vol,
                "leverage": leverage,
                "side": 1 if direction == "LONG" else 2,  # 1=LONG(OPEN_LONG), 2=SHORT(OPEN_SHORT)
                "type": 5,  # Market order
                "openType": 2,  # Isolated margin
                "stopLossPrice": sl_price,
                "takeProfitPrice": tp_price,
                "positionMode": 1  # One-way mode
            }
            
            logging.info(f"📤 Відправляю ордер: {body}")
            
            result = self._make_signed_request(url, body)
            
            if result.get("code") == 0 or result.get("success"):
                logging.info(f"✅ Позицію відкрито: {symbol} {direction}")
                return {"success": True, "data": result.get("data")}
            else:
                error_msg = result.get("msg") or result.get("message") or "Unknown error"
                logging.error(f"❌ Помилка відкриття: {error_msg}")
                return {"success": False, "msg": error_msg}
                
        except Exception as e:
            logging.error(f"❌ Exception при відкритті позиції: {e}")
            return {"success": False, "error": str(e)}

# ==========================================
# 📊 POSITION MANAGER
# ==========================================
class PositionState(Enum):
    SIGNAL_RECEIVED = "signal_received"
    POSITION_DETECTED = "position_detected"
    POSITION_CLOSED = "position_closed"  # ✨ НОВИЙ СТАН

@dataclass
class ManagedPosition:
    symbol: str
    signal_direction: str  # "LONG" / "SHORT"
    target_sl: float
    target_tp: float
    state: PositionState
    entry_price: float = 0.0
    current_size: float = 0.0
    signal_time: float = 0.0
    
    # ✨ НОВІ ПОЛЯ для відстеження закритих позицій
    close_price: float = 0.0
    close_time: float = 0.0
    pnl_usdt: float = 0.0
    pnl_percent: float = 0.0

class PositionManager:
    def __init__(self):
        self.positions: Dict[str, ManagedPosition] = {}
        self.closed_positions: Dict[str, ManagedPosition] = {}  # ✨ НОВИЙ: історія закритих
        self.cooldown_seconds = 300
    
    def can_accept_signal(self, symbol: str) -> bool:
        """Перевіряє чи можна прийняти новий сигнал"""
        if symbol in self.positions:
            managed = self.positions[symbol]
            elapsed = time.time() - managed.signal_time
            
            if elapsed < self.cooldown_seconds:
                logging.info(f"⏳ Cooldown для {symbol}: {int(self.cooldown_seconds - elapsed)}s")
                return False
        
        return True
    
    def add_signal(self, symbol: str, direction: str, sl: float, tp: float):
        """Додає новий сигнал до менеджера"""
        self.positions[symbol] = ManagedPosition(
            symbol=symbol,
            signal_direction=direction,
            target_sl=sl,
            target_tp=tp,
            state=PositionState.SIGNAL_RECEIVED,
            signal_time=time.time()
        )
        logging.info(f"📝 Сигнал збережено: {symbol} {direction}")
    
    def update_from_exchange(self, exchange_positions: List[Dict]):
        """
        Оновлює стан позицій на основі даних з біржі.
        
        ✨ ОНОВЛЕНО: Тепер також відстежує закриті позиції
        """
        # Створюємо словник відкритих позицій на біржі
        open_symbols = {}
        for pos in exchange_positions:
            symbol = pos.get("symbol")
            if symbol:
                open_symbols[symbol] = pos
        
        # Перевіряємо наші відстежувані позиції
        for symbol, managed in list(self.positions.items()):
            
            if symbol in open_symbols:
                # Позиція ще відкрита на біржі
                exchange_pos = open_symbols[symbol]
                
                # Оновлюємо дані позиції
                if managed.state == PositionState.SIGNAL_RECEIVED:
                    managed.state = PositionState.POSITION_DETECTED
                    managed.entry_price = float(exchange_pos.get("openAvgPrice", 0))
                    managed.current_size = abs(float(exchange_pos.get("holdVol", 0)))
                    logging.info(f"✅ Позицію підтверджено: {symbol} @ ${managed.entry_price}")
                
                # Оновлюємо поточний розмір
                managed.current_size = abs(float(exchange_pos.get("holdVol", 0)))
                
            else:
                # Позиція закрита на біржі
                if managed.state == PositionState.POSITION_DETECTED:
                    # ✨ НОВА ЛОГІКА: Позиція була відкрита і тепер закрита
                    logging.info(f"🔔 Позиція закрита: {symbol}")
                    
                    # Переміщуємо в закриті позиції для повідомлення
                    managed.state = PositionState.POSITION_CLOSED
                    managed.close_time = time.time()
                    
                    # Зберігаємо для обробки в моніторингу
                    self.closed_positions[symbol] = managed

# ==========================================
# 💰 RISK CALCULATION
# ==========================================
def calculate_risk_params(balance: float, price: float, direction: str, contract_size: float = 1.0) -> dict:
    """
    Розраховує параметри ризику для позиції.
    
    ✨ ОНОВЛЕНО: Додано параметр contract_size для правильного розрахунку кількості контрактів
    
    Args:
        balance: Доступний баланс в USDT
        price: Поточна ціна монети
        direction: "LONG" або "SHORT"
        contract_size: Скільки монет в одному контракті (наприклад, 0.1 для HYPE)
    
    Returns:
        dict: {
            'qty': int,  # Кількість КОНТРАКТІВ для відкриття
            'tp_percent': float,
            'sl_percent': float
        }
    """
    try:
        risk_percent = float(os.getenv("RISK_PERCENT", 3))
        tp_percent = float(os.getenv("TP_PERCENT", 10))
        sl_percent = float(os.getenv("SL_PERCENT", 2))
        leverage = int(os.getenv("LEVERAGE", 20))
        
        # Сума під ризик
        risk_amount = balance * (risk_percent / 100)
        
        # Позиційний розмір з урахуванням кредитного плеча
        position_value = risk_amount * leverage
        
        # Кількість МОНЕТ які ми хочемо купити
        qty_coins = position_value / price
        
        # ✨ КЛЮЧОВА ЗМІНА: Конвертуємо монети в контракти
        # Якщо 1 контракт = 0.1 монети (contract_size = 0.1)
        # То для покупки 1 монети потрібно 1 / 0.1 = 10 контрактів
        qty_contracts = qty_coins / contract_size
        
        # Округлюємо до цілого числа контрактів
        qty_contracts = max(1, int(qty_contracts))
        
        logging.info(
            f"💰 Розрахунок: Balance={balance:.2f}, Risk={risk_percent}%, "
            f"Position=${position_value:.2f}, Price=${price:.4f}, "
            f"ContractSize={contract_size}, "
            f"Монет={qty_coins:.2f} → Контрактів={qty_contracts}"
        )
        
        return {
            'qty': qty_contracts,
            'tp_percent': tp_percent,
            'sl_percent': sl_percent
        }
    except:
        return {
            'qty': 1,
            'tp_percent': 10.0,
            'sl_percent': 2.0
        }

# ✨ НОВА ФУНКЦІЯ: Розрахунок PnL
def calculate_pnl(entry_price: float, close_price: float, size: float, direction: str) -> tuple:
    """
    Розраховує прибуток/збиток позиції.
    
    Args:
        entry_price: Ціна входу
        close_price: Ціна закриття (можна взяти поточну ціну як approximation)
        size: Розмір позиції в контрактах
        direction: "LONG" або "SHORT"
    
    Returns:
        tuple: (pnl_usdt: float, pnl_percent: float)
    """
    if entry_price <= 0 or close_price <= 0:
        return 0.0, 0.0
    
    if direction == "LONG":
        # Для LONG: прибуток якщо ціна виросла
        price_change_percent = ((close_price - entry_price) / entry_price) * 100
    else:
        # Для SHORT: прибуток якщо ціна впала
        price_change_percent = ((entry_price - close_price) / entry_price) * 100
    
    # PnL в USDT (approximate, без врахування комісій та точного розміру)
    # Точний розрахунок вимагає знання точного розміру в USDT
    position_value = size * entry_price
    pnl_usdt = position_value * (price_change_percent / 100)
    
    return pnl_usdt, price_change_percent

# ==========================================
# 🔄 MONITORING LOOP
# ==========================================
async def position_monitoring_loop(web_client: MexcWebClient, manager: PositionManager, context):
    logging.info("🔄 Моніторинг запущено")
    check_interval = 10
    
    while True:
        try:
            if len(manager.positions) == 0 and len(manager.closed_positions) == 0:
                await asyncio.sleep(check_interval)
                continue
            
            exchange_positions = web_client.get_open_positions()
            manager.update_from_exchange(exchange_positions)
            
            # Повідомлення про підтверджені позиції (як і раніше)
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
                    
                    # НЕ видаляємо з менеджера - продовжуємо відстежувати для повідомлення про закриття
                    # Просто змінюємо стан щоб не слати повторні повідомлення
                    managed.state = PositionState.POSITION_DETECTED
            
            # ✨ НОВА ЛОГІКА: Повідомлення про закриті позиції
            for symbol, managed in list(manager.closed_positions.items()):
                target_id = os.getenv("SIGNAL_CHANNEL_ID")
                
                # Отримуємо поточну ціну як approximation ціни закриття
                try:
                    url_price = "https://contract.mexc.com/api/v1/contract/ticker"
                    resp = web_client.session.get(url_price, params={"symbol": symbol}, timeout=10)
                    close_price = managed.entry_price  # Fallback
                    
                    if resp.status_code == 200:
                        ticker_data = resp.json()
                        if ticker_data.get("success") and ticker_data.get("data"):
                            close_price = float(ticker_data["data"][0].get("lastPrice", managed.entry_price))
                    
                    # Розраховуємо PnL
                    pnl_usdt, pnl_percent = calculate_pnl(
                        entry_price=managed.entry_price,
                        close_price=close_price,
                        size=managed.current_size,
                        direction=managed.signal_direction
                    )
                    
                    # Визначаємо результат (TP, SL, або Manual)
                    result_type = "ЗАКРИТО"
                    result_icon = "⚪"
                    
                    # Перевіряємо чи близько до TP або SL
                    if managed.signal_direction == "LONG":
                        if close_price >= managed.target_tp * 0.99:  # Близько до TP
                            result_type = "TAKE PROFIT"
                            result_icon = "✅"
                        elif close_price <= managed.target_sl * 1.01:  # Близько до SL
                            result_type = "STOP LOSS"
                            result_icon = "🛑"
                    else:  # SHORT
                        if close_price <= managed.target_tp * 1.01:
                            result_type = "TAKE PROFIT"
                            result_icon = "✅"
                        elif close_price >= managed.target_sl * 0.99:
                            result_type = "STOP LOSS"
                            result_icon = "🛑"
                    
                    # Формуємо повідомлення
                    pnl_sign = "+" if pnl_usdt >= 0 else ""
                    msg = (
                        f"{result_icon} <b>{result_type}</b>\n\n"
                        f"<b>Символ:</b> {symbol}\n"
                        f"<b>Бік:</b> {managed.signal_direction}\n"
                        f"<b>Вхід:</b> ${managed.entry_price:.4f}\n"
                        f"<b>Вихід:</b> ${close_price:.4f}\n"
                        f"<b>Розмір:</b> {managed.current_size}\n\n"
                        f"💰 <b>PnL:</b> {pnl_sign}{pnl_usdt:.2f} USDT ({pnl_sign}{pnl_percent:.2f}%)\n"
                    )
                    
                    await context.bot.send_message(chat_id=target_id, text=msg, parse_mode="HTML")
                    logging.info(f"📤 Відправлено повідомлення про закриття: {symbol}")
                    
                except Exception as e:
                    logging.error(f"❌ Помилка при обробці закритої позиції {symbol}: {e}")
                
                # Видаляємо з закритих після відправки повідомлення
                del manager.closed_positions[symbol]
                
                # Також видаляємо з активних позицій
                if symbol in manager.positions:
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

        # ✨ ОНОВЛЕНО: Отримуємо інформацію про контракт з кешу
        contract_info = mexc_web.contract_size_cache.get(symbol_api)
        
        if not contract_info:
            # Якщо чомусь немає в кеші, отримуємо зараз
            contract_info = mexc_web.get_contract_info(symbol_api)
            mexc_web.contract_size_cache[symbol_api] = contract_info
        
        contract_size = contract_info['contractSize']
        tick = contract_info['tickSize']
        
        logging.info(f"📊 {symbol_api}: ContractSize={contract_size}, TickSize={tick}")

        # ✨ ОНОВЛЕНО: Передаємо contract_size в розрахунок ризику
        risk = calculate_risk_params(balance, price, my_direction, contract_size)
        
        # Розраховуємо TP/SL від поточної ціни (як approximation)
        tp_price, sl_price = mexc_web.calculate_tp_sl(
            entry_price=price,
            direction=my_direction,
            tp_percent=risk['tp_percent'],
            sl_percent=risk['sl_percent'],
            tick=tick
        )
        
        position_manager.add_signal(symbol_api, my_direction, sl_price, tp_price)
        
        logging.info(f"🚀 Відкриваю {my_direction} {symbol_api}, Контрактів: {risk['qty']}")

        res = mexc_web.open_position_with_sl_tp(
            symbol=symbol_api,
            direction=my_direction,
            quantity=risk['qty'],  # Вже в контрактах!
            leverage=int(os.getenv("LEVERAGE", 20)),
            tp_price=tp_price,
            sl_price=sl_price
        )
        
        if res.get("success") or res.get("dry_run"):
            msg = (
                f"✅ <b>ОРДЕР ВІДПРАВЛЕНО</b>\n\n"
                f"{symbol_api} {my_direction}\n"
                f"Контрактів: {risk['qty']}\n"
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
            f"🚀 <b>MEXC Bot v2.1 Запущено</b>\n"
            f"{mode_text}"
            f"{hours_text}\n"
            f"{status_icon} <i>{'Торгівля активна' if is_allowed else 'Торгівля призупинена'}</i>\n\n"
            f"<i>✨ ContractSize підтримка\n"
            f"✨ Повідомлення про закриття</i>"
        )
        
        await application.bot.send_message(chat_id=target_id, text=startup_msg, parse_mode='HTML')

def main():
    global mexc_web, position_manager
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    web_token = os.getenv("MEXC_TOKEN", "").strip()
    
    if not telegram_token or not web_token: return

    mexc_web = MexcWebClient(web_token)
    position_manager = PositionManager()
    
    # ✨ НОВИЙ КОД: Завантажуємо інформацію про контракти для дозволених монет
    allowed_symbols_str = os.getenv("ALLOWED_SYMBOLS", "BTC_USDT,ETH_USDT")
    allowed_symbols = [s.strip() for s in allowed_symbols_str.split(",")]
    
    logging.info(f"📋 Дозволені монети: {allowed_symbols}")
    mexc_web.load_contract_sizes(allowed_symbols)
    
    async def init_and_start_monitoring(app):
        await post_init(app)
        asyncio.create_task(position_monitoring_loop(mexc_web, position_manager, app))
    
    application = ApplicationBuilder().token(telegram_token).post_init(init_and_start_monitoring).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 Бот запущено!")
    application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    main()
