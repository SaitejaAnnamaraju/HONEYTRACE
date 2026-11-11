"""
HONEYTRACE - Enterprise SOC Design System & UI Theme Engine
Provides a world-class SaaS cybersecurity command center theme,
custom CSS styling, component cards, severity badges, and Plotly styling.
"""

from datetime import datetime
import streamlit as st
import plotly.graph_objects as go


def get_soc_css() -> str:
    """Returns the comprehensive enterprise SOC CSS stylesheet."""
    return """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --bg-midnight: #080D19;
        --bg-sidebar: #0B1220;
        --bg-card: #111B2D;
        --bg-card-hover: #152238;
        --bg-card-elevated: #16243C;
        --border-subtle: rgba(255, 255, 255, 0.08);
        --border-accent: rgba(0, 212, 255, 0.3);
        --accent-cyan: #00D4FF;
        --accent-violet: #8B5CF6;
        --accent-blue: #38BDF8;
        --status-critical: #EF4444;
        --status-high: #F97316;
        --status-medium: #F59E0B;
        --status-low: #38BDF8;
        --status-info: #10B981;
        --text-primary: #F8FAFC;
        --text-secondary: #94A3B8;
        --text-muted: #64748B;
        --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        --font-mono: 'JetBrains Mono', 'Fira Code', Consolas, monospace;
    }

    /* Global App Canvas */
    .stApp {
        background-color: var(--bg-midnight) !important;
        color: var(--text-primary) !important;
        font-family: var(--font-sans) !important;
        background-image: 
            radial-gradient(circle at 15% 15%, rgba(0, 212, 255, 0.03) 0%, transparent 40%),
            radial-gradient(circle at 85% 85%, rgba(139, 92, 246, 0.03) 0%, transparent 40%) !important;
        background-attachment: fixed !important;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: var(--bg-sidebar) !important;
        border-right: 1px solid var(--border-subtle) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4) !important;
    }
    section[data-testid="stSidebar"] > div {
        padding-top: 1.5rem !important;
    }

    /* Typography Overrides */
    h1, h2, h3, h4, h5, h6 {
        font-family: var(--font-sans) !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        color: var(--text-primary) !important;
    }
    p, span, label {
        font-family: var(--font-sans) !important;
        color: var(--text-secondary);
    }
    code, pre {
        font-family: var(--font-mono) !important;
    }

    /* Enterprise SOC Top Header */
    .soc-header {
        background: linear-gradient(135deg, rgba(17, 27, 45, 0.8) 0%, rgba(11, 18, 32, 0.9) 100%);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--border-subtle);
        border-radius: 12px;
        padding: 16px 24px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
    }
    .soc-brand-wrap {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .soc-brand-title {
        font-size: 1.65rem;
        font-weight: 800;
        letter-spacing: 0.05em;
        background: linear-gradient(90deg, #00D4FF 0%, #8B5CF6 60%, #FFFFFF 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        line-height: 1.2;
    }
    .soc-brand-sub {
        font-size: 0.8rem;
        font-weight: 500;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-top: 2px;
    }
    .soc-status-group {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .soc-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        background: rgba(17, 27, 45, 0.9);
        border: 1px solid var(--border-subtle);
        color: var(--text-secondary);
    }
    .soc-pill-live {
        border-color: rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.08);
        color: #34D399;
    }
    .soc-pill-cyan {
        border-color: rgba(0, 212, 255, 0.3);
        background: rgba(0, 212, 255, 0.08);
        color: var(--accent-cyan);
    }

    /* Radar Pulse Animation */
    .radar-pulse {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10B981;
        position: relative;
        display: inline-block;
    }
    .radar-pulse::after {
        content: '';
        width: 100%;
        height: 100%;
        position: absolute;
        top: 0;
        left: 0;
        border-radius: 50%;
        background: #10B981;
        animation: pulse-ring 2s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
    }
    @keyframes pulse-ring {
        0% { transform: scale(1); opacity: 0.8; }
        100% { transform: scale(3.5); opacity: 0; }
    }

    /* Enterprise KPI Card Grid */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }
    .kpi-card {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        border-color: rgba(0, 212, 255, 0.3);
        box-shadow: 0 8px 24px rgba(0, 212, 255, 0.08);
    }
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent 0%, var(--accent-cyan) 50%, transparent 100%);
        opacity: 0.6;
    }
    .kpi-card-critical::before {
        background: linear-gradient(90deg, transparent 0%, var(--status-critical) 50%, transparent 100%);
    }
    .kpi-card-amber::before {
        background: linear-gradient(90deg, transparent 0%, var(--status-high) 50%, transparent 100%);
    }
    .kpi-card-violet::before {
        background: linear-gradient(90deg, transparent 0%, var(--accent-violet) 50%, transparent 100%);
    }
    .kpi-top-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
    }
    .kpi-title {
        font-size: 0.76rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--text-muted);
    }
    .kpi-icon-box {
        width: 34px;
        height: 34px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1rem;
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid var(--border-subtle);
    }
    .kpi-value {
        font-size: 1.95rem;
        font-weight: 800;
        color: var(--text-primary);
        font-variant-numeric: tabular-nums;
        letter-spacing: -0.02em;
        line-height: 1.1;
    }
    .kpi-footer {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-top: 10px;
        font-size: 0.75rem;
        font-weight: 500;
    }
    .kpi-trend-pill {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
    }
    .kpi-trend-cyan {
        background: rgba(0, 212, 255, 0.12);
        color: var(--accent-cyan);
    }
    .kpi-trend-critical {
        background: rgba(239, 68, 68, 0.12);
        color: var(--status-critical);
    }
    .kpi-trend-emerald {
        background: rgba(16, 185, 129, 0.12);
        color: var(--status-info);
    }
    .kpi-desc {
        color: var(--text-muted);
        font-size: 0.73rem;
    }

    /* Severity Badges */
    .sev-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        font-family: var(--font-mono);
    }
    .sev-critical {
        background: rgba(239, 68, 68, 0.14);
        border: 1px solid rgba(239, 68, 68, 0.35);
        color: #F87171;
    }
    .sev-high {
        background: rgba(249, 115, 22, 0.14);
        border: 1px solid rgba(249, 115, 22, 0.35);
        color: #FB923C;
    }
    .sev-medium {
        background: rgba(245, 158, 11, 0.14);
        border: 1px solid rgba(245, 158, 11, 0.35);
        color: #FBBF24;
    }
    .sev-low {
        background: rgba(56, 189, 248, 0.14);
        border: 1px solid rgba(56, 189, 248, 0.35);
        color: #38BDF8;
    }
    .sev-info {
        background: rgba(16, 185, 129, 0.14);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34D399;
    }

    /* Section Header Eyebrows */
    .soc-section-eyebrow {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        color: var(--accent-cyan);
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
    }
    .soc-section-title {
        font-size: 1.3rem;
        font-weight: 700;
        color: var(--text-primary);
        letter-spacing: -0.01em;
        margin-bottom: 6px;
    }
    .soc-section-caption {
        font-size: 0.85rem;
        color: var(--text-muted);
        margin-bottom: 18px;
    }

    /* Content Cards */
    .ht-panel {
        background: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
    }

    /* Streamlit UI Widget Enhancements */
    div[data-baseweb="select"] > div {
        background-color: #0F172A !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 6px !important;
        color: var(--text-primary) !important;
    }
    div[data-baseweb="select"]:hover > div {
        border-color: var(--accent-cyan) !important;
    }
    div[data-baseweb="input"] > div {
        background-color: #0F172A !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 6px !important;
        color: var(--text-primary) !important;
    }
    div[data-baseweb="input"]:focus-within > div {
        border-color: var(--accent-cyan) !important;
        box-shadow: 0 0 0 1px var(--accent-cyan) !important;
    }

    /* Button Enhancements */
    .stButton>button {
        background: linear-gradient(180deg, #16243C 0%, #0F1A2E 100%) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        letter-spacing: 0.02em !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3) !important;
    }
    .stButton>button:hover {
        background: linear-gradient(180deg, #1E3252 0%, #16243C 100%) !important;
        border-color: var(--accent-cyan) !important;
        color: var(--accent-cyan) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(0, 212, 255, 0.15) !important;
    }
    .stButton>button[kind="primary"] {
        background: linear-gradient(135deg, #0284C7 0%, #0369A1 100%) !important;
        border-color: var(--accent-cyan) !important;
        color: #FFFFFF !important;
        box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35) !important;
    }
    .stButton>button[kind="primary"]:hover {
        background: linear-gradient(135deg, #0EA5E9 0%, #0284C7 100%) !important;
        box-shadow: 0 6px 20px rgba(14, 165, 233, 0.5) !important;
        color: #FFFFFF !important;
    }

    /* Dataframe Table Modernization */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border-subtle) !important;
        border-radius: 8px !important;
        overflow: hidden !important;
        background-color: var(--bg-card) !important;
    }

    /* Expanders */
    div[data-testid="stExpander"] {
        background: var(--bg-card) !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 8px !important;
        margin-bottom: 12px !important;
    }
    div[data-testid="stExpander"]:hover {
        border-color: rgba(255, 255, 255, 0.15) !important;
    }

    /* Code Blocks */
    pre, div[data-testid="stCodeBlock"] {
        background-color: #070B14 !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 6px !important;
    }

    /* Custom Radio Navigation */
    div[data-testid="stRadio"] > div {
        gap: 6px !important;
    }
    div[data-testid="stRadio"] label {
        background: rgba(255, 255, 255, 0.02) !important;
        border: 1px solid transparent !important;
        border-radius: 6px !important;
        padding: 8px 12px !important;
        margin: 2px 0 !important;
        transition: all 0.15s ease !important;
        cursor: pointer !important;
    }
    div[data-testid="stRadio"] label:hover {
        background: rgba(0, 212, 255, 0.05) !important;
        border-color: rgba(0, 212, 255, 0.2) !important;
    }
    div[data-testid="stRadio"] label[data-checked="true"] {
        background: rgba(0, 212, 255, 0.1) !important;
        border-color: var(--accent-cyan) !important;
    }

    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-midnight);
    }
    ::-webkit-scrollbar-thumb {
        background: #1E293B;
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #334155;
    }
    </style>
    """


def apply_custom_css():
    """Injects the master SOC CSS stylesheet into the active Streamlit app."""
    st.markdown(get_soc_css(), unsafe_allow_html=True)


def render_top_header(db=None):
    """Renders the enterprise SOC command header bar."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    active_incidents = 0
    if db:
        try:
            kpis = db.get_kpis()
            active_incidents = kpis.get("open_incidents", 0)
        except Exception:
            pass

    header_html = f"""
    <div class="soc-header">
        <div class="soc-brand-wrap">
            <div style="font-size: 2rem; line-height: 1; filter: drop-shadow(0 0 10px rgba(0,212,255,0.4));">🛡️</div>
            <div>
                <h1 class="soc-brand-title">HONEYTRACE</h1>
                <div class="soc-brand-sub">// ENTERPRISE ACTIVE DECEPTION &amp; THREAT INTELLIGENCE COMMAND CENTER</div>
            </div>
        </div>
        <div class="soc-status-group">
            <div class="soc-pill soc-pill-live">
                <span class="radar-pulse"></span>
                <span>DECEPTION MESH ACTIVE</span>
            </div>
            <div class="soc-pill soc-pill-cyan">
                <span>🌐 HTTP :8080</span>
                <span style="opacity:0.4;">|</span>
                <span>🔒 SSH :2222</span>
            </div>
            <div class="soc-pill">
                <span>⏱️ {now_str}</span>
            </div>
            <div class="soc-pill" style="border-color: rgba(239, 68, 68, 0.4); color: #F87171;">
                <span>🚨 {active_incidents} ACTIVE INCIDENTS</span>
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_section_header(eyebrow: str, title: str, caption: str = ""):
    """Renders standardized cybersecurity section headers with eyebrow tags."""
    st.markdown(f"""
    <div style="margin-bottom: 16px;">
        <div class="soc-section-eyebrow">
            <span style="display:inline-block; width:6px; height:6px; background:#00D4FF; border-radius:50%;"></span>
            {eyebrow}
        </div>
        <div class="soc-section-title">{title}</div>
        {f'<div class="soc-section-caption">{caption}</div>' if caption else ''}
    </div>
    """, unsafe_allow_html=True)


def render_kpi_card(
    title: str,
    value: str,
    icon: str = "📊",
    trend_text: str = "",
    trend_type: str = "cyan",
    description: str = "",
    card_type: str = "default"
) -> str:
    """Generates pure HTML for an enterprise KPI card."""
    type_class = f"kpi-card-{card_type}" if card_type != "default" else ""
    trend_class = f"kpi-trend-{trend_type}"
    
    trend_html = ""
    if trend_text:
        trend_html = f'<span class="kpi-trend-pill {trend_class}">{trend_text}</span>'
        
    desc_html = f'<span class="kpi-desc">{description}</span>' if description else ""

    return f"""
    <div class="kpi-card {type_class}">
        <div class="kpi-top-row">
            <span class="kpi-title">{title}</span>
            <div class="kpi-icon-box">{icon}</div>
        </div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-footer">
            {trend_html}
            {desc_html}
        </div>
    </div>
    """


def render_severity_badge(severity: str) -> str:
    """Returns styled HTML severity badge."""
    sev = (severity or "INFO").upper()
    css_class = f"sev-{sev.lower()}"
    dot_color = {
        "CRITICAL": "#EF4444",
        "HIGH": "#F97316",
        "MEDIUM": "#F59E0B",
        "LOW": "#38BDF8",
        "INFO": "#10B981"
    }.get(sev, "#94A3B8")
    
    return f"""<span class="sev-badge {css_class}"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:{dot_color};"></span>{sev}</span>"""


def apply_plotly_theme(fig: go.Figure) -> go.Figure:
    """Standardizes any Plotly figure with the dark midnight enterprise theme."""
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(17, 27, 45, 0.45)",
        font=dict(
            family="Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            color="#94A3B8",
            size=11
        ),
        margin=dict(l=15, r=15, t=35, b=15),
        xaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(color="#64748B", size=10),
            title_font=dict(color="#94A3B8", size=11)
        ),
        yaxis=dict(
            gridcolor="rgba(255, 255, 255, 0.05)",
            zerolinecolor="rgba(255, 255, 255, 0.08)",
            tickfont=dict(color="#64748B", size=10),
            title_font=dict(color="#94A3B8", size=11)
        ),
        legend=dict(
            font=dict(color="#94A3B8", size=11),
            bgcolor="rgba(11, 18, 32, 0.7)",
            bordercolor="rgba(255, 255, 255, 0.08)",
            borderwidth=1
        )
    )
    return fig

