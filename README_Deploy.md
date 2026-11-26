# 🚀 Deploy GeoSentinel SOC Threat Intelligence Dashboard

You can host the **GeoSentinel** web console live for **free** on cloud platforms to showcase in your portfolio:

## Option A: Streamlit Community Cloud (Recommended)
1. Push this repository to your GitHub account (`https://github.com/NoyonSoftworks/geosentinel`).
2. Navigate to [Streamlit Community Cloud](https://share.streamlit.io/).
3. Sign in with GitHub → Click **New app**.
4. Select your repository: `NoyonSoftworks/geosentinel` (or current name).
5. Set Main file path to: `app.py`.
6. Click **Deploy!**
7. You will receive a live public portfolio URL (e.g. `https://geosentinel-threat-recon.streamlit.app`).

## Option B: Hugging Face Spaces (Free Docker/Streamlit)
1. Create a new Space at [Hugging Face Spaces](https://huggingface.co/spaces).
2. Choose **Streamlit** SDK.
3. Link your GitHub repository or push directly to the HF Space git remote.
4. Your application will build and deploy with a free public URL.

---

## Local Development & Testing

```bash
# Clone the repository
git clone https://github.com/NoyonSoftworks/bd-address-enricher.git
cd bd-address-enricher

# Install dependencies
pip install -r requirements.txt

# Run the full automated test suite (22 tests)
pytest

# Launch the Streamlit dashboard
streamlit run app.py
```
