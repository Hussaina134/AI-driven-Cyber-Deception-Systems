# ui/attack_map.py
import streamlit as st
import pandas as pd
import pydeck as pdk
from pymongo import MongoClient
import os
import requests
import random
from datetime import datetime

st.set_page_config(layout="wide", page_title="Attack Map")

st.title("Attack Map — Live Attacker Locations")

# Sidebar
DATA_SOURCE = st.sidebar.selectbox("Data source", ["MongoDB (live)", "CSV (static)"])
MONGO_URI = st.sidebar.text_input("Mongo URI", value=os.getenv("MONGO_URI", "mongodb://localhost:27017"))
CSV_PATH = st.sidebar.text_input("CSV path", value="notebooks/features_agg.csv")
REFRESH = st.sidebar.button("Refresh now")

# Geo helpers (try local geoip2, else fallback to ipapi, else random)
GEO_DB_PATHS = [
    "./GeoLite2-City.mmdb",
    "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
]

def geoip_lookup(ip):
    try:
        import geoip2.database
        for p in GEO_DB_PATHS:
            if os.path.exists(p):
                reader = geoip2.database.Reader(p)
                rec = reader.city(ip)
                lat = rec.location.latitude
                lon = rec.location.longitude
                reader.close()
                if lat and lon:
                    return lat, lon
    except Exception:
        pass
    # fallback: use ipapi.co (rate-limited)
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        j = resp.json()
        if j.get("latitude") and j.get("longitude"):
            return float(j["latitude"]), float(j["longitude"])
        if j.get("lat") and j.get("lon"):
            return float(j["lat"]), float(j["lon"])
    except Exception:
        pass
    # final fallback: random near equator (visible)
    return (random.uniform(-30, 60), random.uniform(-130, 150))

@st.cache_data(ttl=30)
def load_from_csv(path):
    df = pd.read_csv(path)
    # expected columns: session_id, src_ip, start, reward, applied_action
    return df

@st.cache_data(ttl=10)
def load_from_mongo(uri):
    client = MongoClient(uri)
    db = client["honeypot"]
    cur = db.sessions_agg.find({}, {"_id":0, "session_id":1, "src_ip":1, "start":1, "reward":1, "applied_action":1}).sort("ts", -1)
    df = pd.DataFrame(list(cur))
    return df

def ensure_geo(df):
    if df is None or df.empty:
        return pd.DataFrame(columns=["session_id","src_ip","start","reward","applied_action","lat","lon"])
    df = df.copy()
    if "lat" in df.columns and "lon" in df.columns:
        return df
    lats, lons = [], []
    for ip in df["src_ip"].fillna("0.0.0.0"):
        try:
            lat, lon = geoip_lookup(ip)
        except Exception:
            lat, lon = (random.uniform(-30, 60), random.uniform(-130, 150))
        lats.append(lat); lons.append(lon)
    df["lat"] = lats; df["lon"] = lons
    return df

# Load data
if DATA_SOURCE == "CSV (static)":
    df = load_from_csv(CSV_PATH)
else:
    df = load_from_mongo(MONGO_URI)

if df is None or df.empty:
    st.warning("No data found. Make sure the source contains aggregated session docs.")
    st.stop()

# normalize columns
for c in ["session_id","src_ip","start","reward","applied_action"]:
    if c not in df.columns:
        df[c] = None

df = ensure_geo(df)

# Map layer (radius by reward)
df["reward"] = pd.to_numeric(df["reward"].fillna(0.0))
df["size"] = (df["reward"] * 50) + 5

mid = {"lat": df["lat"].mean() if not df["lat"].isna().all() else 20,
       "lon": df["lon"].mean() if not df["lon"].isna().all() else 0}

layer = pdk.Layer(
    "ScatterplotLayer",
    data=df,
    get_position='[lon, lat]',
    get_fill_color="[255*(1-reward), 50, 255*reward, 160]",
    get_radius="size",
    pickable=True,
)

view_state = pdk.ViewState(latitude=mid["lat"], longitude=mid["lon"], zoom=1.5, pitch=0)

r = pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip={"text":"Session: {session_id}\nIP: {src_ip}\nAction: {applied_action}\nReward: {reward}"})
st.pydeck_chart(r)

# Table and detail area
st.subheader("Recent attacker sessions")
st.dataframe(df[["session_id","src_ip","start","applied_action","reward"]].sort_values("start",ascending=False).head(200))

st.markdown("**Usage:** Start with CSV for a snapshot; then switch to MongoDB and run the demo injection script to see live updates.")
