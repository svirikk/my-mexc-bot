import os
import json
import time
import base64
import hashlib
import re
import logging
from datetime import datetime
from dotenv import load_dotenv

# Cryptography
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
import requests

# Telegram Bot
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

# ==========================================
# 📋 CONFIGURATION
# ==========================================
if os.path.exists('.env'):
    load_dotenv()

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ==========================================
# 🔐 MEXC CRYPTO MODULE
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
# 💰 RISK MANAGEMENT
# ==========================================
class RiskManager:
    @staticmethod
    def calculate_position_size(balance, entry_price, direction, risk_percent=2.5, sl_percent=0.5, leverage=20):
        """
        Розраховує розмір позиції на основі риск-менеджменту
        """
        try:
            risk_usd = balance * (risk_percent / 100)
            
            # Розрахунок Stop Loss ціни
            if direction == "LONG":
                sl_price = entry_price * (1 - sl_percent / 100)
            else:
                sl_price = entry_price * (1 + sl_percent / 100)
            
            # Відстань до SL
            sl_distance = abs(entry_price - sl_price)
            
            # Розмір позиції в USDT
            position_size_usd = (risk_usd / sl_distance) * entry_price
            
            # Кількість контрактів
            quantity = int(position_size_usd / entry_price)
            
            # Take Profit (за замовчуванням 0.5%)
            tp_percent = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5))
            if direction == "LONG":
                tp_price = entry_price * (1 + tp_percent / 100)
            else:
                tp_price = entry_price * (1 - tp_percent / 100)
            
            # Перевірка мінімуму
            if quantity < 1:
                quantity = 1
            
            required_margin = (quantity * entry_price) / leverage
            
            return {
                "quantity": quantity,
                "position_size_usd": position_size_usd,
                "required_margin": required_margin,
                "stop_loss": round(sl_price, 4),
                "take_profit": round(tp_price, 4),
                "risk_amount": risk_usd,
                "sl_percent": sl_percent,
                "tp_percent": tp_percent
            }
            
        except Exception as e:
            logging.error(f"❌ Risk calculation error: {e}")
            return None

# ==========================================
# 🌐 MEXC CLIENT
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
            logging.info("✅ MEXC Config loaded")
        except Exception as e:
            logging.error(f"❌ Config error: {e}")

    def _make_signed_request(self, url, method="GET", params=None, data=None):
        """
        Універсальний метод для підписаних запитів
        """
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
                "product_type": 0,
                "request_id": "",
                "sys": "Linux",
                "sys_ver": "",
                "member_id": ""
            })
            
            body_dict = {
                "p0": p0,
                "k0": k0,
                "chash": self.config_obj["chash"],
                "mtoken": self.crypto.mtoken,
                "ts": ts,
                "mhash": mhash
            }
            
            if data:
                body_dict.update(data)
            
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {
                **self.base_headers,
                "x-mxc-nonce": ts,
                "x-mxc-sign": x_mxc_sign
            }
            
            if method == "GET":
                resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, data=body_json, headers=headers, timeout=10)
            
            return resp.json()
            
        except Exception as e:
            logging.error(f"❌ API request error: {e}")
            return None

    def get_wallet_balance(self):
        """Отримання балансу"""
        try:
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            data = self._make_signed_request(url, method="GET")
            
            if not data or not data.get("success"):
                logging.warning(f"⚠️ Balance API: {data}")
                return 0.0
            
            balance_data = data.get("data", {})
            available = 0.0
            
            if isinstance(balance_data, dict):
                available = float(
                    balance_data.get("availableBalance") or 
                    balance_data.get("availableBal") or 
                    balance_data.get("available") or 
                    balance_data.get("equity") or 
                    0
                )
            elif isinstance(balance_data, list) and len(balance_data) > 0:
                for item in balance_data:
                    if item.get("currency") == "USDT":
                        available = float(item.get("availableBalance", 0))
                        break
            
            logging.info(f"💰 Balance: {available} USDT")
            return available
            
        except Exception as e:
            logging.error(f"❌ Balance error: {e}", exc_info=True)
            return 0.0

    def get_open_positions(self):
        """Отримання відкритих позицій"""
        try:
            url = "https://contract.mexc.com/api/v1/private/position/open_positions"
            data = self._make_signed_request(url, method="GET")
            
            if not data or not data.get("success"):
                return []
            
            positions = data.get("data", [])
            logging.info(f"📊 Open positions: {len(positions)}")
            
            return positions
            
        except Exception as e:
            logging.error(f"❌ Get positions error: {e}")
            return []

    def place_order(self, symbol, direction, quantity, leverage, stop_loss=None, take_profit=None):
        """Відкриття ордеру з TP/SL"""
        if not self.config_obj: 
            self.refresh_config()
            
        ts = str(int(time.time() * 1000))
        mhash = hashlib.md5(self.crypto.mtoken.encode()).hexdigest()
        
        p0, k0 = self.crypto.encrypt_request({
            "hostname": "www.mexc.com", 
            "mhash": mhash, 
            "mtoken": self.crypto.mtoken, 
            "platform_type": 3,
            "product_type": 0,
            "request_id": "",
            "sys": "Linux",
            "sys_ver": "",
            "member_id": ""
        })
        
        body_dict = {
            "symbol": symbol,
            "side": 1 if direction == "LONG" else 2,
            "openType": 2,  # Cross margin
            "type": "5",    # Market order
            "vol": str(quantity),
            "leverage": int(leverage),
            "marketCeiling": False,
            "priceProtect": "0",
            "p0": p0, 
            "k0": k0, 
            "chash": self.config_obj["chash"],
            "mtoken": self.crypto.mtoken, 
            "ts": ts, 
            "mhash": mhash
        }
        
        # Додаємо TP/SL якщо є
        if stop_loss:
            body_dict["stopLossPrice"] = str(stop_loss)
        if take_profit:
            body_dict["takeProfitPrice"] = str(take_profit)
        
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
        x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            logging.info(f"[DRY RUN] Order: {body_dict}")
            return {"success": True, "dry_run": True, "code": 200}
        
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        
        try:
            logging.info(f"📤 Opening: {direction} {symbol}, Qty: {quantity}, Leverage: {leverage}x")
            
            r = self.session.post(
                "https://www.mexc.com/api/platform/futures/api/v1/private/order/create", 
                data=body_json, 
                headers=headers, 
                timeout=10
            )
            
            result = r.json()
            logging.info(f"📥 Response: {result}")
            
            return result
        except Exception as e:
            logging.error(f"❌ Order error: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

# ==========================================
# 📊 POSITION TRACKER
# ==========================================
class PositionTracker:
    def __init__(self):
        self.open_positions = {}  # symbol -> position data
        self.closed_positions = []
        
    def add_position(self, symbol, direction, entry_price, quantity, leverage, stop_loss, take_profit, risk_amount):
        """Додає позицію до трекінгу"""
        self.open_positions[symbol] = {
            "symbol": symbol,
            "direction": direction,
            "entry_price": entry_price,
            "quantity": quantity,
            "leverage": leverage,
            "stop_loss": stop_loss,
            "take_profit": take_profit,
            "risk_amount": risk_amount,
            "opened_at": datetime.now(),
            "timestamp": int(time.time() * 1000)
        }
        logging.info(f"✅ Added to tracking: {symbol} {direction}")
    
    def remove_position(self, symbol):
        """Видаляє позицію з трекінгу"""
        if symbol in self.open_positions:
            pos = self.open_positions.pop(symbol)
            logging.info(f"🔔 Removed from tracking: {symbol}")
            return pos
        return None
    
    def has_position(self, symbol):
        """Перевіряє наявність позиції"""
        return symbol in self.open_positions
    
    def get_position(self, symbol):
        """Отримує дані позиції"""
        return self.open_positions.get(symbol)
    
    def add_closed_position(self, position_data, exit_price, pnl, pnl_percent):
        """Додає закриту позицію до історії"""
        duration = datetime.now() - position_data["opened_at"]
        
        self.closed_positions.append({
            **position_data,
            "exit_price": exit_price,
            "pnl": pnl,
            "pnl_percent": pnl_percent,
            "duration": str(duration).split('.')[0],
            "closed_at": datetime.now()
        })
    
    def get_statistics(self):
        """Отримує статистику"""
        total_trades = len(self.closed_positions)
        win_trades = sum(1 for p in self.closed_positions if p["pnl"] >= 0)
        total_pnl = sum(p["pnl"] for p in self.closed_positions)
        
        return {
            "total_trades": total_trades,
            "win_trades": win_trades,
            "lose_trades": total_trades - win_trades,
            "total_pnl": total_pnl,
            "open_positions": len(self.open_positions)
        }

# ==========================================
# 🤖 BOT LOGIC
# ==========================================
mexc_client = None
position_tracker = PositionTracker()
position_check_interval = 30

async def check_positions_loop(context: ContextTypes.DEFAULT_TYPE):
    """Фоновий моніторинг позицій"""
    global mexc_client, position_tracker
    
    if not mexc_client:
        return
    
    try:
        # Отримуємо відкриті позиції з біржі
        exchange_positions = mexc_client.get_open_positions()
        exchange_symbols = {pos.get("symbol") for pos in exchange_positions if pos.get("symbol")}
        
        # Перевіряємо які позиції закрилися
        for symbol in list(position_tracker.open_positions.keys()):
            if symbol not in exchange_symbols:
                # Позиція закрита
                tracked_pos = position_tracker.remove_position(symbol)
                
                if tracked_pos:
                    # Розраховуємо P&L (приблизно, без точної ціни виходу)
                    entry_price = tracked_pos["entry_price"]
                    direction = tracked_pos["direction"]
                    
                    # Берем останню ціну як exit (можна покращити через trade history)
                    exit_price = entry_price  # Спрощення
                    
                    if direction == "LONG":
                        pnl = (exit_price - entry_price) * tracked_pos["quantity"]
                        pnl_percent = ((exit_price - entry_price) / entry_price) * 100
                    else:
                        pnl = (entry_price - exit_price) * tracked_pos["quantity"]
                        pnl_percent = ((entry_price - exit_price) / entry_price) * 100
                    
                    position_tracker.add_closed_position(tracked_pos, exit_price, pnl, pnl_percent)
                    
                    # Відправляємо сповіщення
                    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
                    if target_id:
                        emoji = "🟢" if pnl >= 0 else "🔴"
                        result = "PROFIT" if pnl >= 0 else "LOSS"
                        
                        message = f"""{emoji} <b>POSITION CLOSED - {result}</b>

<b>Symbol:</b> {symbol}
<b>Direction:</b> {direction}
<b>Entry:</b> ${entry_price}
<b>Exit:</b> ${exit_price}
<b>Result:</b> {'+' if pnl >= 0 else ''}{pnl_percent:.2f}% ({'+' if pnl >= 0 else ''}${pnl:.2f})

<b>Duration:</b> {str(datetime.now() - tracked_pos['opened_at']).split('.')[0]}

✅ Bot ready for new signals on {symbol}"""
                        
                        await context.bot.send_message(
                            chat_id=target_id,
                            text=message,
                            parse_mode='HTML'
                        )
    
    except Exception as e:
        logging.error(f"❌ Position check error: {e}", exc_info=True)

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обробка сигналів з каналу"""
    global mexc_client, position_tracker
    
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
        symbol_raw = str(data.get('symbol', '')).upper()
        
        # Конвертація формату
        if 'USDT' in symbol_raw and '_' not in symbol_raw:
            symbol = symbol_raw.replace('USDT', '_USDT')
        else:
            symbol = symbol_raw
        
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        logging.info(f"🔎 Signal: {symbol} ({symbol_raw}) | Type: {signal_type} | Price: {price}")
        
        # Визначення напрямку
        my_direction = None
        if signal_type == "LONG_FLUSH": 
            my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE": 
            my_direction = "SHORT"
        
        if not my_direction: 
            logging.info(f"⏭ Unknown signal type: {signal_type}")
            return

        # Перевірка фільтрів
        allowed = [s.strip().upper() for s in os.getenv("ALLOWED_SYMBOLS", "").split(",")]
        if symbol not in allowed and symbol_raw not in allowed:
            logging.warning(f"🚫 {symbol} not in ALLOWED_SYMBOLS")
            return
            
        if position_tracker.has_position(symbol):
            logging.warning(f"⏳ Position already active: {symbol}")
            return

        # Отримання балансу
        balance = mexc_client.get_wallet_balance()
        logging.info(f"💰 Balance: {balance} USDT")
        
        if balance < 5:
            logging.error(f"❌ Balance too low: {balance} USDT")
            return

        # Розрахунок позиції через Risk Manager
        leverage = int(os.getenv("LEVERAGE", 20))
        risk_percent = float(os.getenv("RISK_PERCENTAGE", 2.5))
        sl_percent = float(os.getenv("STOP_LOSS_PERCENT", 0.5))
        
        risk_params = RiskManager.calculate_position_size(
            balance=balance,
            entry_price=price,
            direction=my_direction,
            risk_percent=risk_percent,
            sl_percent=sl_percent,
            leverage=leverage
        )
        
        if not risk_params:
            logging.error("❌ Risk calculation failed")
            return
        
        qty = risk_params["quantity"]
        stop_loss = risk_params["stop_loss"]
        take_profit = risk_params["take_profit"]
        risk_amount = risk_params["risk_amount"]
        
        logging.info(f"🚀 Order: {my_direction} {symbol}, Qty: {qty}, Risk: ${risk_amount:.2f}")
        logging.info(f"   TP: ${take_profit} (+{risk_params['tp_percent']}%), SL: ${stop_loss} (-{risk_params['sl_percent']}%)")

        # Відкриття ордеру
        res = mexc_client.place_order(
            symbol=symbol,
            direction=my_direction,
            quantity=qty,
            leverage=leverage,
            stop_loss=stop_loss,
            take_profit=take_profit
        )
        
        # Обробка результату
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            # Додаємо до трекера
            position_tracker.add_position(
                symbol=symbol,
                direction=my_direction,
                entry_price=price,
                quantity=qty,
                leverage=leverage,
                stop_loss=stop_loss,
                take_profit=take_profit,
                risk_amount=risk_amount
            )
            
            mode_text = "🧪 TEST MODE" if res.get("dry_run") else "✅ POSITION OPENED"
            
            # Форматування повідомлення
            tp_percent = risk_params['tp_percent']
            sl_percent = risk_params['sl_percent']
            balance_percent = (risk_amount / balance * 100)
            
            clean_symbol = symbol.replace('_USDT', '').replace('USDT', '')
            dir_emoji = "📈" if my_direction == "LONG" else "📉"
            
            message = f"""{mode_text}

<b>Symbol:</b> {symbol}
<b>Direction:</b> {dir_emoji} {my_direction}
<b>Entry Price:</b> ${price}
<b>Quantity:</b> {qty:,} {clean_symbol}
<b>Leverage:</b> {leverage}x

🎯 <b>Take Profit:</b> ${take_profit} (+{tp_percent:.2f}%)
🛑 <b>Stop Loss:</b> ${stop_loss} (-{sl_percent:.2f}%)
💰 <b>Risk:</b> ${risk_amount:.2f} ({balance_percent:.2f}% of balance)

Signal from: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"""
            
            await context.bot.send_message(
                chat_id=target_id,
                text=message,
                parse_mode='HTML'
            )
            
            logging.info(f"✅ Order executed: {res}")
        else:
            logging.error(f"❌ Order failed: {res}")
            await context.bot.send_message(
                chat_id=target_id,
                text=f"❌ Failed to open {symbol}:\n{res.get('msg') or res.get('error') or res}"
            )

    except Exception as e:
        logging.error(f"❌ Critical error: {e}", exc_info=True)

async def post_init(application):
    """Ініціалізація після запуску"""
    global position_check_interval
    
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    
    # Запуск моніторингу позицій
    job_queue = application.job_queue
    job_queue.run_repeating(
        check_positions_loop, 
        interval=position_check_interval, 
        first=10
    )
    logging.info(f"⏰ Position monitoring: every {position_check_interval}s")
    
    if target_id:
        try:
            stats = position_tracker.get_statistics()
            dry_run_mode = os.getenv('DRY_RUN', 'false').lower() == 'true'
            mode_text = 'DRY RUN' if dry_run_mode else 'LIVE TRADING'
            
            message = f"""🚀 <b>MEXC Copy Bot Started</b>

✅ Mode: {mode_text}
📊 Leverage: {os.getenv('LEVERAGE', 20)}x
💰 Risk: {os.getenv('RISK_PERCENTAGE', 2.5)}%
🛑 Stop Loss: {os.getenv('STOP_LOSS_PERCENT', 0.5)}%
🎯 Take Profit: {os.getenv('TAKE_PROFIT_PERCENT', 0.5)}%
⏰ Position Check: {position_check_interval}s

📈 <b>Statistics:</b>
Open Positions: {stats['open_positions']}
Total Trades: {stats['total_trades']}
Win Rate: {(stats['win_trades']/stats['total_trades']*100) if stats['total_trades'] > 0 else 0:.1f}%
Total P&L: ${stats['total_pnl']:.2f}
"""
            
            await application.bot.send_message(
                chat_id=target_id,
                text=message,
                parse_mode='HTML'
            )
        except Exception as e:
            logging.error(f"Post-init error: {e}")

def main():
    global mexc_client, position_check_interval
    
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    mexc_token = os.getenv("MEXC_TOKEN", "").strip()
    position_check_interval = int(os.getenv("POSITION_CHECK_INTERVAL", 30))
    
    if not token: 
        logging.error("❌ TELEGRAM_BOT_TOKEN not set!")
        return
    
    if not mexc_token:
        logging.error("❌ MEXC_TOKEN not set!")
        return

    mexc_client = MexcWebClient(mexc_token)
    
    # Startup checks
    balance = mexc_client.get_wallet_balance