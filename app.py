import streamlit as st
import requests
import urllib3
import ssl
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import bcrypt

# --- 1. SSL PATCH (MUST BE FIRST) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

old_merge_environment_settings = requests.Session.merge_environment_settings

def merge_environment_settings(self, url, proxies, stream, verify, cert):
    return old_merge_environment_settings(self, url, proxies, stream, False, cert)

requests.Session.merge_environment_settings = merge_environment_settings

# --- 2. IMPORT YFINANCE ---
import yfinance as yf

# --- DATABASE SETUP ---
Base = declarative_base()
engine = create_engine('sqlite:///stock_bot.db', connect_args={'check_same_thread': False})
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'
    username = Column(String, primary_key=True)
    password_hash = Column(String)

class TradeHistory(Base):
    __tablename__ = 'trades'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user = Column(String)
    symbol = Column(String)
    action = Column(String)
    price = Column(Float)
    strategy = Column(String) # Track which strategy was used
    timestamp = Column(DateTime, default=datetime.utcnow)

class Config(Base):
    __tablename__ = 'config'
    user = Column(String, primary_key=True)
    stocks = Column(String, default="RELIANCE.NS, TCS.NS, INFY.NS, HDFCBANK.NS") 
    webhook_url = Column(String, default="")
    short_window = Column(Integer, default=20)
    long_window = Column(Integer, default=50)
    rsi_period = Column(Integer, default=14) # New Config
    rsi_overbought = Column(Integer, default=70) # New Config
    rsi_oversold = Column(Integer, default=30) # New Config

Base.metadata.create_all(engine)

# --- INDICATOR FUNCTIONS ---
def calculate_rsi(data, window=14):
    delta = data['Close'].diff()
    gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
    loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()
    rs = gain / loss
    return 100 - (100 / (1 + rs))

def calculate_macd(data, slow=26, fast=12, signal=9):
    exp1 = data['Close'].ewm(span=fast, adjust=False).mean()
    exp2 = data['Close'].ewm(span=slow, adjust=False).mean()
    macd = exp1 - exp2
    signal_line = macd.ewm(span=signal, adjust=False).mean()
    return macd, signal_line

# --- AUTH & NOTIFICATION ---
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_user(username, password):
    if session.query(User).filter_by(username=username).first():
        return False
    user = User(username=username, password_hash=hash_password(password))
    session.add(user)
    session.commit()
    return True

def verify_login(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        return True
    return False

def send_notification(msg, webhook_url):
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={'text': msg}, verify=False)
    except Exception as e:
        print(f"Notification failed: {e}")

# --- APP UI ---
st.set_page_config(page_title="Pro Stock Trader v2", layout="wide")

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = None

if not st.session_state['logged_in']:
    st.title("🔐 Stock Dashboard Login")
    tab1, tab2 = st.tabs(["Login", "Register"])
    with tab1:
        l_user = st.text_input("Username", key="l_user")
        l_pass = st.text_input("Password", type="password", key="l_pass")
        if st.button("Login"):
            if verify_login(l_user, l_pass):
                st.session_state['logged_in'] = True
                st.session_state['username'] = l_user
                st.rerun()
            else:
                st.error("Invalid Login")
    with tab2:
        r_user = st.text_input("New Username", key="r_user")
        r_pass = st.text_input("New Password", type="password", key="r_pass")
        if st.button("Register"):
            if create_user(r_user, r_pass):
                st.success("User created! Please login.")
            else:
                st.error("User exists.")

else:
    current_user = st.session_state['username']
    
    # Load Config
    user_config = session.query(Config).filter_by(user=current_user).first()
    if not user_config:
        user_config = Config(user=current_user)
        session.add(user_config)
        session.commit()

    st.sidebar.title(f"User: {current_user}")
    page = st.sidebar.radio("Navigate", ["Dashboard", "Settings", "History"])
    
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.rerun()

    # --- SETTINGS PAGE ---
    if page == "Settings":
        st.header("⚙️ Strategy Configuration")
        with st.form("config_form"):
            st.subheader("General")
            new_stocks = st.text_area("Watchlist (comma separated)", value=user_config.stocks)
            c_webhook = st.text_input("Webhook URL", value=user_config.webhook_url)
            
            st.subheader("SMA Strategy Params")
            c1, c2 = st.columns(2)
            c_short = c1.number_input("SMA Short Window", value=user_config.short_window)
            c_long = c2.number_input("SMA Long Window", value=user_config.long_window)
            
            st.subheader("RSI Strategy Params")
            c3, c4, c5 = st.columns(3)
            c_rsi_p = c3.number_input("RSI Period", value=user_config.rsi_period)
            c_rsi_low = c4.number_input("RSI Oversold (Buy)", value=user_config.rsi_oversold)
            c_rsi_high = c5.number_input("RSI Overbought (Sell)", value=user_config.rsi_overbought)

            if st.form_submit_button("Save All Settings"):
                user_config.stocks = new_stocks
                user_config.webhook_url = c_webhook
                user_config.short_window = c_short
                user_config.long_window = c_long
                user_config.rsi_period = c_rsi_p
                user_config.rsi_oversold = c_rsi_low
                user_config.rsi_overbought = c_rsi_high
                session.commit()
                st.success("Settings Updated!")

    # --- DASHBOARD PAGE ---
    elif page == "Dashboard":
        st.header("📈 Advanced Technical Analysis")
        
        # Controls
        col_ctl1, col_ctl2, col_ctl3 = st.columns([2, 2, 2])
        stock_list = [s.strip() for s in user_config.stocks.split(',')]
        selected_stock = col_ctl1.selectbox("1. Select Stock", stock_list)
        period = col_ctl2.select_slider("2. Data Period", options=['3mo', '6mo', '1y', '2y', '5y'], value='1y')
        strategy_mode = col_ctl3.selectbox("3. Select Strategy", ["SMA Crossover", "RSI Reversal", "MACD Trend"])

        if selected_stock:
            try:
                df = yf.download(selected_stock, period=period, progress=False)
            except:
                df = None

            if df is not None and not df.empty:
                # --- CALCULATE ALL INDICATORS ---
                # SMA
                df['SMA_Short'] = df['Close'].rolling(window=user_config.short_window).mean()
                df['SMA_Long'] = df['Close'].rolling(window=user_config.long_window).mean()
                # RSI
                df['RSI'] = calculate_rsi(df, window=user_config.rsi_period)
                # MACD
                df['MACD'], df['Signal_Line'] = calculate_macd(df)

                # --- STRATEGY LOGIC ---
                df['Signal'] = 0.0
                
                if strategy_mode == "SMA Crossover":
                    df['Signal'] = (df['SMA_Short'] > df['SMA_Long']).astype(float)
                    chart_title = f"SMA Strategy ({user_config.short_window}/{user_config.long_window})"
                
                elif strategy_mode == "RSI Reversal":
                    # Buy when RSI < Oversold, Sell when RSI > Overbought
                    # This is a bit complex to vectorise, so we use a simple rule:
                    # 1 = Bullish zone (RSI < 70), 0 = Bearish zone (RSI > 70) 
                    # But for triggers:
                    df['Signal'] = np.where(df['RSI'] < user_config.rsi_oversold, 1.0, 0.0)
                    df['Signal'] = np.where(df['RSI'] > user_config.rsi_overbought, -1.0, df['Signal'])
                    chart_title = f"RSI Strategy ({user_config.rsi_period})"

                elif strategy_mode == "MACD Trend":
                    df['Signal'] = (df['MACD'] > df['Signal_Line']).astype(float)
                    chart_title = "MACD Momentum Strategy"

                # Calculate Buy/Sell positions (changes in signal)
                # Note: RSI logic above returns 1, 0, or -1 directly.
                if strategy_mode == "RSI Reversal":
                     df['Position'] = df['Signal'] # Use raw signal for RSI
                else:
                     df['Position'] = df['Signal'].diff()

                # --- DISPLAY ---
                last_price = float(df['Close'].iloc[-1])
                last_pos = df['Position'].iloc[-1]

                # Metric Cards
                m1, m2, m3 = st.columns(3)
                m1.metric("Current Price", f"₹{last_price:,.2f}")
                m2.metric("Active Strategy", strategy_mode)
                
                # Signal Notification
                if last_pos == 1:
                    m3.metric("Signal", "BUY 🟢")
                    st.success(f"🚀 BUY SIGNAL ({strategy_mode})")
                    if st.button("Execute BUY Order"):
                        trade = TradeHistory(user=current_user, symbol=selected_stock, action="BUY", price=last_price, strategy=strategy_mode)
                        session.add(trade)
                        session.commit()
                        send_notification(f"BUY {selected_stock} @ {last_price} via {strategy_mode}", user_config.webhook_url)
                        st.balloons()
                elif last_pos == -1:
                    m3.metric("Signal", "SELL 🔴")
                    st.error(f"🔻 SELL SIGNAL ({strategy_mode})")
                    if st.button("Execute SELL Order"):
                        trade = TradeHistory(user=current_user, symbol=selected_stock, action="SELL", price=last_price, strategy=strategy_mode)
                        session.add(trade)
                        session.commit()
                        send_notification(f"SELL {selected_stock} @ {last_price} via {strategy_mode}", user_config.webhook_url)
                        st.balloons()
                else:
                    m3.metric("Signal", "WAIT ⚪")

                # --- ADVANCED PLOTTING ---
                # Create Subplots: Row 1 for Price, Row 2 for Indicator
                fig = make_subplots(rows=2, cols=1, shared_xaxes=True, 
                                    vertical_spacing=0.05, row_heights=[0.7, 0.3])

                # Main Price Chart (Row 1)
                fig.add_trace(go.Scatter(x=df.index, y=df['Close'], name='Price', line=dict(color='black')), row=1, col=1)
                
                # Buy/Sell Markers on Price
                buys = df[df['Position'] == 1]
                sells = df[df['Position'] == -1]
                fig.add_trace(go.Scatter(x=buys.index, y=buys['Close'], mode='markers', marker=dict(color='green', symbol='triangle-up', size=12), name='Buy'), row=1, col=1)
                fig.add_trace(go.Scatter(x=sells.index, y=sells['Close'], mode='markers', marker=dict(color='red', symbol='triangle-down', size=12), name='Sell'), row=1, col=1)

                # Indicator Charts (Row 2) depending on selection
                if strategy_mode == "SMA Crossover":
                    # For SMA, we actually plot MAs on Row 1, not Row 2
                    fig.add_trace(go.Scatter(x=df.index, y=df['SMA_Short'], name='Short MA', line=dict(color='blue')), row=1, col=1)
                    fig.add_trace(go.Scatter(x=df.index, y=df['SMA_Long'], name='Long MA', line=dict(color='orange')), row=1, col=1)
                    # Hide Row 2 or plot volume? Let's just plot Volume
                    fig.add_trace(go.Bar(x=df.index, y=df['Volume'], name='Volume', marker_color='lightgray'), row=2, col=1)

                elif strategy_mode == "RSI Reversal":
                    fig.add_trace(go.Scatter(x=df.index, y=df['RSI'], name='RSI', line=dict(color='purple')), row=2, col=1)
                    # Add RSI lines (30/70)
                    fig.add_hline(y=70, line_dash="dot", row=2, col=1, line_color="red")
                    fig.add_hline(y=30, line_dash="dot", row=2, col=1, line_color="green")

                elif strategy_mode == "MACD Trend":
                    fig.add_trace(go.Scatter(x=df.index, y=df['MACD'], name='MACD', line=dict(color='blue')), row=2, col=1)
                    fig.add_trace(go.Scatter(x=df.index, y=df['Signal_Line'], name='Signal', line=dict(color='orange')), row=2, col=1)
                    # Histogram
                    colors = ['green' if v >= 0 else 'red' for v in (df['MACD'] - df['Signal_Line'])]
                    fig.add_trace(go.Bar(x=df.index, y=df['MACD']-df['Signal_Line'], name='Hist', marker_color=colors), row=2, col=1)

                fig.update_layout(title=chart_title, height=700)
                st.plotly_chart(fig, use_container_width=True)

            else:
                st.warning("Data not available.")

    # --- HISTORY PAGE ---
    elif page == "History":
        st.header("📜 Trade Log")
        trades = session.query(TradeHistory).filter_by(user=current_user).order_by(TradeHistory.timestamp.desc()).all()
        if trades:
            # Added 'Strategy' column to history
            data = [{"Date": t.timestamp, "Stock": t.symbol, "Action": t.action, 
                     "Price": f"₹{t.price:,.2f}", "Strategy": t.strategy} for t in trades]
            st.table(data)
        else:
            st.info("No trades executed yet.")