import streamlit as st
import requests
import urllib3
import ssl
import pandas as pd
import plotly.graph_objects as go
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import bcrypt

# --- 1. APPLY SSL PATCH FIRST (Before importing yfinance) ---
# Disable "Insecure Request" warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Force Python's socket to ignore SSL
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Monkey-patch requests to always disable SSL verification
old_merge_environment_settings = requests.Session.merge_environment_settings

def merge_environment_settings(self, url, proxies, stream, verify, cert):
    # FORCE verify = False
    return old_merge_environment_settings(self, url, proxies, stream, False, cert)

requests.Session.merge_environment_settings = merge_environment_settings

# --- 2. NOW IMPORT YFINANCE ---
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
    action = Column(String) # BUY or SELL
    price = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Config(Base):
    __tablename__ = 'config'
    user = Column(String, primary_key=True)
    stocks = Column(String, default="RELIANCE.NS, TCS.NS, INFY.NS") 
    webhook_url = Column(String, default="")
    short_window = Column(Integer, default=20)
    long_window = Column(Integer, default=50)

Base.metadata.create_all(engine)

# --- HELPER FUNCTIONS ---
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
        requests.post(webhook_url, json={'text': msg}, verify=False) # Ensure verify=False here too
    except Exception as e:
        print(f"Notification failed: {e}")

# --- APP UI ---
st.set_page_config(page_title="Pro Stock Trader", layout="wide")

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
                st.error("Invalid Username or Password")

    with tab2:
        r_user = st.text_input("New Username", key="r_user")
        r_pass = st.text_input("New Password", type="password", key="r_pass")
        if st.button("Register"):
            if create_user(r_user, r_pass):
                st.success("User created! Please login.")
            else:
                st.error("User already exists.")

else:
    current_user = st.session_state['username']
    
    # Load/Create Config
    user_config = session.query(Config).filter_by(user=current_user).first()
    if not user_config:
        user_config = Config(user=current_user)
        session.add(user_config)
        session.commit()

    st.sidebar.title(f"Welcome, {current_user}")
    page = st.sidebar.radio("Navigate", ["Dashboard", "Configuration", "Trade History"])
    
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.rerun()

    if page == "Configuration":
        st.header("⚙️ Bot Settings")
        with st.form("config_form"):
            st.subheader("1. Watchlist")
            new_stocks = st.text_area("Stocks (comma separated)", value=user_config.stocks)
            st.subheader("2. Strategy")
            c_short = st.number_input("Short Window", value=user_config.short_window)
            c_long = st.number_input("Long Window", value=user_config.long_window)
            st.subheader("3. Alerts")
            c_webhook = st.text_input("Webhook URL", value=user_config.webhook_url)
            
            if st.form_submit_button("Save"):
                user_config.stocks = new_stocks
                user_config.short_window = c_short
                user_config.long_window = c_long
                user_config.webhook_url = c_webhook
                session.commit()
                st.success("Saved!")

    elif page == "Dashboard":
        st.header("📈 Market Analysis")
        stock_list = [s.strip() for s in user_config.stocks.split(',')]
        selected_stock = st.selectbox("Select Stock", stock_list)
        period = st.select_slider("Period", options=['3mo', '6mo', '1y', '2y', '5y'], value='1y')

        if selected_stock:
            # --- FIX: Safe Download ---
            try:
                # 'progress=False' stops the terminal progress bar which sometimes clutters logs
                df = yf.download(selected_stock, period=period, progress=False)
            except Exception as e:
                st.error(f"Download failed: {e}")
                df = None

            # --- FIX: Check if DataFrame is valid ---
            if df is not None and not df.empty:
                # Data Processing
                df['SMA_Short'] = df['Close'].rolling(window=user_config.short_window).mean()
                df['SMA_Long'] = df['Close'].rolling(window=user_config.long_window).mean()
                
                df['Signal'] = 0.0
                df['Signal'] = (df['SMA_Short'] > df['SMA_Long']).astype(float)
                df['Position'] = df['Signal'].diff()

                last_price = float(df['Close'].iloc[-1])
                last_signal = df['Position'].iloc[-1]
                
                # Metrics
                c1, c2 = st.columns(2)
                c1.metric("Price", f"₹{last_price:,.2f}")
                
                status = "BULLISH" if df['SMA_Short'].iloc[-1] > df['SMA_Long'].iloc[-1] else "BEARISH"
                c2.metric("Trend", status)
                
                # Action Buttons
                if last_signal == 1:
                    st.success("BUY SIGNAL")
                    if st.button("Execute BUY"):
                        trade = TradeHistory(user=current_user, symbol=selected_stock, action="BUY", price=last_price)
                        session.add(trade)
                        session.commit()
                        send_notification(f"BUY {selected_stock} @ {last_price}", user_config.webhook_url)
                        st.success("Bought!")
                elif last_signal == -1:
                    st.error("SELL SIGNAL")
                    if st.button("Execute SELL"):
                        trade = TradeHistory(user=current_user, symbol=selected_stock, action="SELL", price=last_price)
                        session.add(trade)
                        session.commit()
                        send_notification(f"SELL {selected_stock} @ {last_price}", user_config.webhook_url)
                        st.success("Sold!")

                # Chart
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=df.index, y=df['Close'], name='Price', line=dict(color='gray')))
                fig.add_trace(go.Scatter(x=df.index, y=df['SMA_Short'], name='Short MA', line=dict(color='blue')))
                fig.add_trace(go.Scatter(x=df.index, y=df['SMA_Long'], name='Long MA', line=dict(color='orange')))
                
                buys = df[df['Position'] == 1]
                sells = df[df['Position'] == -1]
                
                fig.add_trace(go.Scatter(x=buys.index, y=buys['Close'], mode='markers', marker=dict(color='green', symbol='triangle-up', size=10), name='Buy'))
                fig.add_trace(go.Scatter(x=sells.index, y=sells['Close'], mode='markers', marker=dict(color='red', symbol='triangle-down', size=10), name='Sell'))
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning(f"Could not retrieve data for {selected_stock}. Check if the ticker is correct.")

    elif page == "Trade History":
        st.header("📜 History")
        trades = session.query(TradeHistory).filter_by(user=current_user).order_by(TradeHistory.timestamp.desc()).all()
        if trades:
            data = [{"Date": t.timestamp, "Stock": t.symbol, "Action": t.action, "Price": f"₹{t.price:,.2f}"} for t in trades]
            st.table(data)
        else:
            st.info("No trades yet.")