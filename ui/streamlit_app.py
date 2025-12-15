# streamlit_app.py
import streamlit as st
import pandas as pd
import pydeck as pdk
from pymongo import MongoClient
import os, requests, random, time
from datetime import datetime

st.set_page_config(layout="wide", page_title="AI-Driven Cyber Deception Dashboard")

# ---------- Helpers ----------
def geoip_lookup_fallback(ip):
    # lightweight fallback geo lookup (ipapi.co) with try/except
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        j = resp.json()
        if j.get("latitude") and j.get("longitude"):
            return float(j["latitude"]), float(j["longitude"])
        if j.get("lat") and j.get("lon"):
            return float(j["lat"]), float(j["lon"])
    except Exception:
        pass
    return random.uniform(-30, 60), random.uniform(-130, 150)

def ensure_geo(df):
    if df is None or df.empty:
        return pd.DataFrame(columns=["session_id","src_ip","start","reward","applied_action","lat","lon"])
    df = df.copy()
    if "lat" in df.columns and "lon" in df.columns:
        return df
    lats, lons = [], []
    for ip in df["src_ip"].fillna("0.0.0.0"):
        try:
            lat, lon = geoip_lookup_fallback(ip)
        except Exception:
            lat, lon = random.uniform(-30,60), random.uniform(-130,150)
        lats.append(lat); lons.append(lon)
    df["lat"] = lats; df["lon"] = lons
    return df

# ------------ Data loaders ------------
@st.cache_data(ttl=10)
def load_from_csv(path="notebooks/features_agg.csv"):
    if not os.path.exists(path):
        return pd.DataFrame()
    df = pd.read_csv(path)
    return df

@st.cache_data(ttl=5)
def load_from_mongo(uri="mongodb://localhost:27017"):
    client = MongoClient(uri)
    db = client.get_database("honeypot")
    cur = db.sessions_agg.find({}, {"_id":0, "session_id":1, "src_ip":1, "start":1, "reward":1, "applied_action":1, "ts":1}).sort("ts", -1)
    df = pd.DataFrame(list(cur))
    return df

# ------------ Demo injector ------------
def inject_demo_from_csv(mongo_uri="mongodb://localhost:27017", csv_path="notebooks/features_agg.csv", delay=0.05, count=100):
    client = MongoClient(mongo_uri)
    agg = client["honeypot"]["sessions_agg"]
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        sample = df.sample(min(len(df), count))
        for _, r in sample.iterrows():
            doc = {
                "session_id": r.get("session_id") or str(time.time()),
                "src_ip": r.get("src_ip") or f"10.0.0.{random.randint(2,254)}",
                "start": str(r.get("start") or datetime.utcnow().isoformat()),
                "reward": float(r.get("reward") or 0.0),
                "applied_action": r.get("applied_action") or "default",
                "ts": time.time()
            }
            agg.insert_one(doc)
            time.sleep(delay)
    else:
        for i in range(count):
            doc = {
                "session_id": f"demo-{int(time.time())}-{i}",
                "src_ip": f"{random.randint(1,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "start": datetime.utcnow().isoformat(),
                "reward": round(random.random(), 4),
                "applied_action": random.choice(["banner:generic","banner:hard","fakefs","default"]),
                "ts": time.time()
            }
            agg.insert_one(doc)
            time.sleep(delay)

# ---------------- UI pages ----------------
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Overview", "Attack Map", "Session Replay", "Demo Controls"])

# Global config
DATA_SOURCE = st.sidebar.selectbox("Data source", ["MongoDB (live)", "CSV (static)"])
MONGO_URI = st.sidebar.text_input("Mongo URI", value=os.getenv("MONGO_URI","mongodb://localhost:27017"))
CSV_PATH = st.sidebar.text_input("CSV path", value="notebooks/features_agg.csv")
REFRESH = st.sidebar.button("Refresh data")

# -------- Overview page --------
if page == "Overview":
    st.title("Overview — AI-Driven Cyber Deception")
    # load df
    if DATA_SOURCE == "CSV (static)":
        df = load_from_csv(CSV_PATH)
    else:
        df = load_from_mongo(MONGO_URI)
    if df is None or df.empty:
        st.warning("No data found. Use Demo Controls to inject demo sessions, or switch data source.")
    else:
        total = len(df)
        avg_reward = float(df["reward"].mean()) if "reward" in df.columns and len(df)>0 else 0.0
        col1, col2 = st.columns(2)
        col1.metric("Total Sessions", total)
        col2.metric("Avg Reward", f"{avg_reward:.3f}")
        st.subheader("Top actions")
        if "applied_action" in df.columns:
            st.table(df["applied_action"].value_counts().rename_axis("action").reset_index(name="count").head(10))
        st.subheader("Recent sessions sample")
        show = df.head(200) if isinstance(df, pd.DataFrame) else pd.DataFrame()
        st.dataframe(show)

# -------- Attack Map page --------
elif page == "Attack Map":
    st.title("Attack Map — Live Attacker Locations")
    if DATA_SOURCE == "CSV (static)":
        df = load_from_csv(CSV_PATH)
    else:
        df = load_from_mongo(MONGO_URI)
    if df is None or df.empty:
        st.warning("No data found. Use Demo Controls to inject sessions.")
        st.stop()
    # normalize columns and ensure geo
    for c in ["session_id","src_ip","start","reward","applied_action"]:
        if c not in df.columns:
            df[c] = None
    df = ensure_geo(df)
    df["reward"] = pd.to_numeric(df["reward"].fillna(0.0))
    df["size"] = (df["reward"] * 50) + 5
    mid = {"lat": df["lat"].mean() if not df["lat"].isna().all() else 20,
           "lon": df["lon"].mean() if not df["lon"].isna().all() else 0}
    layer = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position='[lon, lat]',
        get_fill_color="[255*(1-reward), 60, 255*reward, 160]",
        get_radius="size",
        pickable=True,
    )
    view_state = pdk.ViewState(latitude=mid["lat"], longitude=mid["lon"], zoom=1.5, pitch=0)
    r = pdk.Deck(layers=[layer], initial_view_state=view_state,
                 tooltip={"text":"Session: {session_id}\nIP: {src_ip}\nAction: {applied_action}\nReward: {reward}"})
    st.pydeck_chart(r)
    st.subheader("Recent attacker sessions")
    st.dataframe(df[["session_id","src_ip","start","applied_action","reward"]].sort_values("start",ascending=False).head(200))

# -------- Session Replay page (simple) --------
elif page == "Session Replay":
    st.title("Session Replay (simple)")
    # fetch sessions (from agg or csv)
    if DATA_SOURCE == "CSV (static)":
        df = load_from_csv(CSV_PATH)
    else:
        df = load_from_mongo(MONGO_URI)
    if df is None or df.empty:
        st.warning("No data for replay. Inject demo data first.")
        st.stop()
    sid = st.selectbox("Choose session", df["session_id"].head(200).tolist())
    st.write("Selected:", sid)
    # try to fetch raw events from Mongo sessions collection if available
    try:
        client = MongoClient(MONGO_URI)
        raw = client["honeypot"]["sessions"]
        events = list(raw.find({"session": {"$regex": sid[:8]}}).limit(500))
    except Exception:
        events = []
    if not events:
        st.info("No raw events found; showing aggregated info")
        agg_row = df[df["session_id"]==sid].to_dict(orient="records")[0]
        st.json(agg_row)
    else:
        st.subheader("Events (chronological)")
        # show timestamp + event + command
        table = []
        for e in events:
            t = e.get("timestamp") or e.get("_ts_parsed") or ""
            table.append({"ts": str(t), "event": e.get("eventid") or e.get("event"), "input": e.get("input") or e.get("command") or e.get("message")})
        st.table(pd.DataFrame(table))

# -------- Demo Controls --------
elif page == "Demo Controls":
    st.title("Demo Controls")
    st.write("Use this to inject sample sessions into Mongo for live demo")
    col1, col2 = st.columns(2)
    with col1:
        count = st.number_input("Count", min_value=1, max_value=1000, value=200)
        delay = st.number_input("Delay (s)", min_value=0.0, max_value=2.0, value=0.02, step=0.01)
    with col2:
        run = st.button("Inject demo sessions")
    if run:
        with st.spinner("Injecting..."):
            inject_demo_from_csv(MONGO_URI, CSV_PATH, delay=delay, count=count)
        st.success("Done injecting demo sessions")

