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
        """
        Отримання балансу Futures
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
            
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {
                **self.base_headers,
                "x-mxc-nonce": ts,
                "x-mxc-sign": x_mxc_sign
            }
            
            url = "https://contract.mexc.com/api/v1/private/account/assets"
            resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            data = resp.json()
            
            logging.info(f"📊 Balance API Response: {data}")
            
            if not data.get("success") and data.get("code") != 200:
                logging.warning(f"⚠️ API Response: {data}")
                return 0.0
            
            balance_data = data.get("data", {})
            available = 0.0
            
            if isinstance(balance_data, dict):
                available = float(
                    balance_data.get("availableBalance") or 
                    balance_data.get("availableBal") or 
                    balance_data.get("available") or 
                    balance_data.get("equity") or 
                    balance_data.get("totalBalance") or
                    0
                )
            elif isinstance(balance_data, list) and len(balance_data) > 0:
                for item in balance_data:
                    if item.get("currency") == "USDT" or item.get("asset") == "USDT":
                        available = float(item.get("availableBalance", 0))
                        break
            
            logging.info(f"✅ MEXC Futures Balance: {available} USDT")
            return available
            
        except Exception as e:
            logging.error(f"❌ Balance Error: {e}", exc_info=True)
            return 0.0

    def get_open_positions(self):
        """
        Отримання відкритих позицій
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
            
            body_json = json.dumps(body_dict, separators=(",", ":"))
            inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
            x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
            
            headers = {
                **self.base_headers,
                "x-mxc-nonce": ts,
                "x-mxc-sign": x_mxc_sign
            }
            
            url = "https://contract.mexc.com/api/v1/private/position/open_positions"
            resp = self.session.get(url, params=body_dict, headers=headers, timeout=10)
            data = resp.json()
            
            if not data.get("success"):
                logging.warning(f"⚠️ Positions API: {data}")
                return []
            
            positions = data.get("data", [])
            logging.info(f"📊 Open Positions: {len(positions)} active")
            
            return positions
            
        except Exception as e:
            logging.error(f"❌ Get Positions Error: {e}", exc_info=True)
            return []

    def place_order(self, symbol, direction, quantity, leverage):
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
            "openType": 2,
            "type": "5",
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
        
        body_json = json.dumps(body_dict, separators=(",", ":"))
        inner = hashlib.md5((self.token + ts).encode()).hexdigest()[7:]
        x_mxc_sign = hashlib.md5((ts + body_json + inner).encode()).hexdigest()
        
        if os.getenv("DRY_RUN", "false").lower() == "true":
            logging.info(f"[DRY RUN] Would place order: {body_dict}")
            return {"success": True, "dry_run": True, "code": 200}
        
        headers = {**self.base_headers, "x-mxc-nonce": ts, "x-mxc-sign": x_mxc_sign}
        
        try:
            logging.info(f"📤 Placing REAL order: {direction} {symbol}, Qty: {quantity}, Leverage: {leverage}x")
            
            r = self.session.post(
                "https://www.mexc.com/api/platform/futures/api/v1/private/order/create", 
                data=body_json, 
                headers=headers, 
                timeout=10
            )
            
            result = r.json()
            logging.info(f"📥 MEXC Order Response: {result}")
            
            return result
        except Exception as e:
            logging.error(f"❌ Order Exception: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

# ==========================================
# 📊 POSITION TRACKER
# ==========================================
class PositionTracker:
    def __init__(self):
        self.open_positions = {}
        self.closed_positions = []
        
    def add_position(self, symbol, direction, entry_price, quantity, leverage, stop_loss, take_profit, risk_amount):
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
        if symbol in self.open_positions:
            pos = self.open_positions.pop(symbol)
            logging.info(f"🔔 Removed from tracking: {symbol}")
            return pos
        return None
    
    def has_position(self, symbol):
        return symbol in self.open_positions
    
    def get_position(self, symbol):
        return self.open_positions.get(symbol)
    
    def add_closed_position(self, position_data, exit_price, pnl, pnl_percent):
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
# 💰 RISK MANAGEMENT
# ==========================================
def calculate_position_size(balance, entry_price, direction):
    """
    Розраховує розмір позиції
    """
    try:
        risk_percent = float(os.getenv("RISK_PERCENTAGE", 2.5))
        sl_percent = float(os.getenv("STOP_LOSS_PERCENT", 0.5))
        tp_percent = float(os.getenv("TAKE_PROFIT_PERCENT", 0.5))
        leverage = int(os.getenv("LEVERAGE", 20))
        
        risk_usd = balance * (risk_percent / 100)
        
        # Stop Loss
        if direction == "LONG":
            sl_price = entry_price * (1 - sl_percent / 100)
            tp_price = entry_price * (1 + tp_percent / 100)
        else:
            sl_price = entry_price * (1 + sl_percent / 100)
            tp_price = entry_price * (1 - tp_percent / 100)
        
        sl_distance = abs(entry_price - sl_price)
        position_size_usd = (risk_usd / sl_distance) * entry_price
        quantity = int(position_size_usd / entry_price)
        
        if quantity < 1:
            quantity = 1
        
        return {
            "quantity": quantity,
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
# 🤖 ЛОГІКА БОТА
# ==========================================
mexc_client = None
position_tracker = PositionTracker()
position_check_interval = 30

async def check_positions_loop(context: ContextTypes.DEFAULT_TYPE):
    """
    Фоновий моніторинг позицій
    """
    global mexc_client, position_tracker
    
    if not mexc_client:
        return
    
    try:
        open_positions = mexc_client.get_open_positions()
        open_symbols = set()
        
        for pos in open_positions:
            symbol = pos.get("symbol", "")
            if symbol:
                open_symbols.add(symbol)
        
        closed_symbols = []
        for symbol in list(position_tracker.open_positions.keys()):
            if symbol not in open_symbols:
                closed_symbols.append(symbol)
                tracked_pos = position_tracker.remove_position(symbol)
                
                if tracked_pos:
                    # Приблизний P&L
                    entry_price = tracked_pos["entry_price"]
                    direction = tracked_pos["direction"]
                    exit_price = entry_price
                    
                    if direction == "LONG":
                        pnl = (exit_price - entry_price) * tracked_pos["quantity"]
                        pnl_percent = ((exit_price - entry_price) / entry_price) * 100
                    else:
                        pnl = (entry_price - exit_price) * tracked_pos["quantity"]
                        pnl_percent = ((entry_price - exit_price) / entry_price) * 100
                    
                    position_tracker.add_closed_position(tracked_pos, exit_price, pnl, pnl_percent)
                    
                    # Сповіщення
                    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
                    if target_id:
                        emoji = "🟢" if pnl >= 0 else "🔴"
                        result = "PROFIT" if pnl >= 0 else "LOSS"
                        duration_str = str(datetime.now() - tracked_pos['opened_at']).split('.')[0]
                        
                        message = (
                            f"{emoji} <b>POSITION CLOSED - {result}</b>\n\n"
                            f"<b>Symbol:</b> {symbol}\n"
                            f"<b>Direction:</b> {direction}\n"
                            f"<b>Entry:</b> ${entry_price}\n"
                            f"<b>Exit:</b> ${exit_price}\n"
                            f"<b>Result:</b> {'+' if pnl >= 0 else ''}{pnl_percent:.2f}% "
                            f"({'+' if pnl >= 0 else ''}${pnl:.2f})\n\n"
                            f"<b>Duration:</b> {duration_str}\n\n"
                            f"✅ Bot ready for new signals on {symbol}"
                        )
                        
                        await context.bot.send_message(
                            chat_id=target_id,
                            text=message,
                            parse_mode='HTML'
                        )
    
    except Exception as e:
        logging.error(f"❌ Position check error: {e}", exc_info=True)

async def handle_channel_post(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global mexc_client, position_tracker
    
    target_id = str(os.getenv("SIGNAL_CHANNEL_ID", "")).strip()
    current_id = str(update.effective_chat.id).strip()
    
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
        symbol_raw = str(data.get('symbol', '')).upper()
        
        if 'USDT' in symbol_raw and '_' not in symbol_raw:
            symbol = symbol_raw.replace('USDT', '_USDT')
        else:
            symbol = symbol_raw
        
        signal_type = str(data.get('signalType', '')).upper()
        price = float(data['stats']['lastPrice'])
        
        logging.info(f"🔎 Processing Signal: {symbol} (raw: {symbol_raw}) | Type: {signal_type} | Price: {price}")
        
        my_direction = None
        if signal_type == "LONG_FLUSH": 
            my_direction = "LONG"
        elif signal_type == "SHORT_SQUEEZE": 
            my_direction = "SHORT"
        
        if not my_direction: 
            logging.info(f"⏭ Skipped: Unknown Signal Type {signal_type}")
            return

        allowed = [s.strip().upper() for s in os.getenv("ALLOWED_SYMBOLS", "").split(",")]
        
        if symbol not in allowed and symbol_raw not in allowed:
            logging.warning(f"🚫 Skipped: {symbol} is not in ALLOWED_SYMBOLS")
            return
            
        if position_tracker.has_position(symbol):
            logging.warning(f"⏳ Skipped: Position already active for {symbol}")
            return

        balance = mexc_client.get_wallet_balance()
        logging.info(f"💰 Current Balance: {balance} USDT")
        
        if balance < 5:
            logging.error(f"❌ Balance too low: {balance} USDT (minimum 5 USDT required)")
            return

        # Розрахунок позиції
        risk_params = calculate_position_size(balance, price, my_direction)
        
        if not risk_params:
            logging.error("❌ Risk calculation failed")
            return
        
        qty = risk_params["quantity"]
        stop_loss = risk_params["stop_loss"]
        take_profit = risk_params["take_profit"]
        risk_amount = risk_params["risk_amount"]
        
        logging.info(f"🚀 Placing Order: {my_direction} {symbol}, Qty: {qty}, Risk: ${risk_amount:.2f}")

        res = mexc_client.place_order(symbol, my_direction, qty, int(os.getenv("LEVERAGE", 20)))
        
        if res.get("success") or res.get("code") == 200 or res.get("dry_run"):
            position_tracker.add_position(
                symbol=symbol,
                direction=my_direction,
                entry_price=price,
                quantity=qty,
                leverage=int(os.getenv("LEVERAGE", 20)),
                stop_loss=stop_loss,
                take_profit=take_profit,
                risk_amount=risk_amount
            )
            
            mode_text = "🧪 TEST MODE" if res.get("dry_run") else "✅ POSITION OPENED"
            clean_symbol = symbol.replace('_USDT', '').replace('USDT', '')
            dir_emoji = "📈" if my_direction == "LONG" else "📉"
            balance_percent = (risk_amount / balance * 100)
            
            message = (
                f"{mode_text}\n\n"
                f"<b>Symbol:</b> {symbol}\n"
                f"<b>Direction:</b> {dir_emoji} {my_direction}\n"
                f"<b>Entry Price:</b> ${price}\n"
                f"<b>Quantity:</b> {qty:,} {clean_symbol}\n"
                f"<b>Leverage:</b> {int(os.getenv('LEVERAGE', 20))}x\n\n"
                f"🎯 <b>Take Profit:</b> ${take_profit} (+{risk_params['tp_percent']:.2f}%)\n"
                f"🛑 <b>Stop Loss:</b> ${stop_loss} (-{risk_params['sl_percent']:.2f}%)\n"
                f"💰 <b>Risk:</b> ${risk_amount:.2f} ({balance_percent:.2f}% of balance)\n\n"
                f"Signal from: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
            
            await context.bot.send_message(
                chat_id=target_id, 
                text=message,
                parse_mode='HTML'
            )
            logging.info(f"✅ Order executed successfully: {res}")
        else:
            logging.error(f"❌ ORDER FAILED. Exchange response: {res}")
            await context.bot.send_message(
                chat_id=target_id, 
                text=f"❌ Помилка відкриття угоди {symbol}:\n{res.get('msg') or res.get('error') or res}"
            )

    except Exception as e:
        logging.error(f"❌ CRITICAL ERROR in handler: {e}", exc_info=True)

async def post_init(application):
    global position_check_interval
    
    target_id = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
    
    job_queue = application.job_queue
    job_queue.run_repeating(
        check_positions_loop, 
        interval=position_check_interval, 
        first=10
    )
    logging.info(f"⏰ Position monitoring started (check every {position_check_interval}s)")
    
    if target_id:
        try:
            stats = position_tracker.get_statistics()
            dry_run = "DRY RUN" if os.getenv('DRY_RUN', 'false').lower() == 'true' else "LIVE TRADING"
            
            message = (
                f"🚀 <b>MEXC Copy Bot Started</b>\n\n"
                f"✅ Mode: {dry_run}\n"
                f"📊 Leverage: {os.getenv('LEVERAGE', 20)}x\n"
                f"💰 Risk: {os.getenv('RISK_PERCENTAGE', 2.5)}%\n"
                f"🛑 Stop Loss: {os.getenv('STOP_LOSS_PERCENT', 0.5)}%\n"
                f"🎯 Take Profit: {os.getenv('TAKE_PROFIT_PERCENT', 0.5)}%\n"
                f"⏰ Position Check: {position_check_interval}s\n\n"
                f"📈 <b>Statistics:</b>\n"
                f"Open Positions: {stats['open_positions']}\n"
                f"Total Trades: {stats['total_trades']}\n"
                f"Win Rate: {(stats['win_trades']/stats['total_trades']*100) if stats['total_trades'] > 0 else 0:.1f}%\n"
                f"Total P&L: ${stats['total_pnl']:.2f}"
            )
            
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
    
    balance = mexc_client.get_wallet_balance()
    logging.info(f"🎯 Startup Balance Check: {balance} USDT")
    
    open_positions = mexc_client.get_open_positions()
    for pos in open_positions:
        symbol = pos.get("symbol", "")
        if symbol:
            position_tracker.open_positions[symbol] = {
                "symbol": symbol,
                "direction": "LONG" if pos.get("positionType") == 1 else "SHORT",
                "entry_price": float(pos.get("openAvgPrice", 0)),
                "quantity": float(pos.get("holdVol", 0)),
                "leverage": float(pos.get("leverage", 20)),
                "stop_loss": 0,
                "take_profit": 0,
                "risk_amount": 0,
                "opened_at": datetime.now(),
                "timestamp": int(time.time() * 1000)
            }
            logging.info(f"📌 Found existing position: {symbol}")
    
    application = ApplicationBuilder().token(token).post_init(post_init).build()
    application.add_handler(MessageHandler(filters.ChatType.CHANNEL, handle_channel_post))
    
    logging.info("🤖 Bot started successfully!")
    application.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()