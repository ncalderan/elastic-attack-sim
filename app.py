# app.py
import os
from pathlib import Path
import streamlit as st
from dotenv import load_dotenv, set_key
from elasticsearch import Elasticsearch
from packs import PACKS
from script_runner import run_generator

APP_TITLE = "Elastic Attack Simulation"
ENV_PATH = Path(".env")
EXAMPLE_ENV = Path(".env.example")

def ensure_env_file():
    if not ENV_PATH.exists() and EXAMPLE_ENV.exists():
        ENV_PATH.write_text(EXAMPLE_ENV.read_text())

def load_env():
    ensure_env_file()
    load_dotenv(dotenv_path=ENV_PATH)

def save_cred_to_env(key: str, value: str):
    set_key(str(ENV_PATH), key, value)

def test_elastic_connection(cloud_id: str, api_key: str) -> tuple[bool, str]:
    try:
        client = Elasticsearch(cloud_id=cloud_id, api_key=api_key, request_timeout=15)
        info = client.info()
        version = info.get("version", {}).get("number", "?")
        cluster = info.get("cluster_name", "elastic-cloud")
        return True, f"Connected to {cluster} (v{version})"
    except Exception as e:
        return False, f"Connection failed: {e}"

def main():
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")
    st.title("🛡️ Elastic Attack Simulation")

    load_env()

    # initialize session state from env ONCE
    if "cloud_id" not in st.session_state:
        st.session_state.cloud_id = os.getenv("ELASTIC_CLOUD_ID", "")
    if "api_key" not in st.session_state:
        st.session_state.api_key = os.getenv("ELASTIC_API_KEY", "")

    with st.sidebar:
        st.header("Elastic Credentials")

        cloud_id = st.text_input(
            "Elastic Cloud ID",
            value=st.session_state.cloud_id,
            key="cloud_id_input",
            type="password",
            help="From Elastic Cloud console → Copy Cloud ID",
        )
        api_key = st.text_input(
            "API Key",
            value=st.session_state.api_key,
            key="api_key_input",
            type="password",
            help="Management → Security → API keys",
        )

        colA, colB = st.columns(2)
        with colA:
            if st.button("Save", use_container_width=True):
                if cloud_id and api_key:
                    # persist to .env
                    save_cred_to_env("ELASTIC_CLOUD_ID", cloud_id)
                    save_cred_to_env("ELASTIC_API_KEY", api_key)
                    # keep process + session in sync immediately
                    os.environ["ELASTIC_CLOUD_ID"] = cloud_id
                    os.environ["ELASTIC_API_KEY"] = api_key
                    st.session_state.cloud_id = cloud_id
                    st.session_state.api_key = api_key
                    st.success("Saved to .env")
                    st.rerun()  # refresh widgets to use updated state
                else:
                    st.warning("Both Cloud ID and API Key are required.")

        with colB:
            if st.button("Test Connection", use_container_width=True):
                ok, msg = test_elastic_connection(cloud_id, api_key)
                (st.success if ok else st.error)(msg)

        st.divider()
        st.caption("Defaults")
        ns = st.text_input("Namespace", value=os.getenv("DEFAULT_NAMESPACE", "simulation"))
        count = st.number_input("Event Count", value=int(os.getenv("DEFAULT_COUNT", "1000")), step=100)
        rate = st.number_input("Rate (events/sec, 0=unlimited)", value=int(os.getenv("DEFAULT_RATE", "200")), step=50)
        batch = st.number_input("Batch Size", value=int(os.getenv("DEFAULT_BATCH_SIZE", "500")), step=50)
        seed = st.number_input("Seed", value=int(os.getenv("DEFAULT_SEED", "42")), step=1)

    st.subheader("Use-Case Packs")
    st.write("Pick a use-case. Only the first one is active today; the others are placeholders.")

    cols = st.columns(4)
    actions = {}
    for i, pack in enumerate(PACKS):
        with cols[i % 4]:
            st.markdown(f"### {pack.title}")
            st.caption(pack.description)
            if pack.active:
                actions[pack.key] = st.button(f"Run: {pack.title}", key=f"run_{pack.key}")
            else:
                st.button("Coming soon", key=f"disabled_{pack.key}", disabled=True)

    # Handle clicks (only one active)
    chosen = next((k for k, v in actions.items() if v), None)
    if chosen:
        pack = next(p for p in PACKS if p.key == chosen)

        # pull directly from session (already fresh from Save)
        cloud_id_val = st.session_state.get("cloud_id") or cloud_id
        api_key_val = st.session_state.get("api_key") or api_key
        if not cloud_id_val or not api_key_val:
            st.error("Missing credentials. Save your Elastic Cloud ID and API key in the sidebar first.")
            st.stop()

        # ensure generator subprocess inherits correct env
        os.environ["ELASTIC_CLOUD_ID"] = cloud_id_val
        os.environ["ELASTIC_API_KEY"] = api_key_val

        # Fill generator args from sidebar defaults
        args = dict(pack.generator_args)
        args["namespace"] = ns
        args["count"] = count
        args["rate"] = rate
        args["batch_size"] = batch
        args["seed"] = seed

        st.info(f"Starting generator for **{pack.title}** → namespace: `{ns}`")
        log_box = st.empty()
        log_lines = []

        # Run generator and stream logs
        for line in run_generator(pack.generator_script, args):
            log_lines.append(line)
            if len(log_lines) > 400:
                log_lines = log_lines[-400:]
            log_box.code("\n".join(log_lines), language="bash")

        st.success("Generator finished. Next steps below 👇")

        with st.expander("Validation (Discover)"):
            for q in pack.discover_queries:
                st.code(q, language="text")

        with st.expander("Expected Alerts"):
            st.write("Enable these prebuilt rules (non-ML) if not already enabled:")
            for r in pack.expected_alerts:
                st.write(f"- {r}")

        st.toast("Done! Open Security → Alerts and Discover to review results.", icon="✅")

if __name__ == "__main__":
    main()
