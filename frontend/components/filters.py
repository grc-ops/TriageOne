"""TriageOne v2.1 — Filter Components for Streamlit."""
import streamlit as st
from typing import Any


# IOC Type Icons and Labels
IOC_TYPES = {
    "ip": ("🌐", "IP Address"),
    "domain": ("🔗", "Domain"),
    "url": ("🔍", "URL"),
    "md5": ("#️⃣", "MD5 Hash"),
    "sha1": ("#️⃣", "SHA1 Hash"),
    "sha256": ("#️⃣", "SHA256 Hash"),
    "filename": ("📄", "Filename"),
    "unknown": ("❓", "Unknown"),
}

# Color scheme
COLOR_CLEAN = "#059669"
COLOR_SUSPICIOUS = "#dc2626"
COLOR_UNKNOWN = "#d97706"


def render_type_filters() -> dict[str, bool]:
    """Render IOC type filter buttons.

    Returns:
        Dictionary of type -> active status
    """
    st.markdown("### 🔍 Filter by IOC Type")

    col1, col2, col3 = st.columns(3)

    filters = {}

    with col1:
        filters["ip"] = st.checkbox(
            "🌐 IP Address",
            value=True,
            key="filter_ip",
            help="IPv4 addresses",
        )

    with col2:
        filters["domain"] = st.checkbox(
            "🔗 Domain",
            value=True,
            key="filter_domain",
            help="Domain names",
        )

    with col3:
        filters["url"] = st.checkbox(
            "🔍 URL",
            value=True,
            key="filter_url",
            help="Complete URLs with http/https",
        )

    col1, col2, col3 = st.columns(3)

    with col1:
        filters["md5"] = st.checkbox(
            "#️⃣ MD5 Hash",
            value=True,
            key="filter_md5",
            help="32-character hex strings",
        )

    with col2:
        filters["sha1"] = st.checkbox(
            "#️⃣ SHA1 Hash",
            value=True,
            key="filter_sha1",
            help="40-character hex strings",
        )

    with col3:
        filters["sha256"] = st.checkbox(
            "#️⃣ SHA256 Hash",
            value=True,
            key="filter_sha256",
            help="64-character hex strings",
        )

    col1, col2 = st.columns(2)

    with col1:
        filters["filename"] = st.checkbox(
            "📄 Filename",
            value=True,
            key="filter_filename",
            help="Executable or file names",
        )

    with col2:
        filters["unknown"] = st.checkbox(
            "❓ Unknown",
            value=True,
            key="filter_unknown",
            help="Unclassified types",
        )

    return filters


def render_verdict_toggle() -> bool:
    """Render malicious-only toggle.

    Returns:
        True if malicious-only filtering is enabled
    """
    st.markdown("---")
    st.markdown("### 🚨 Severity Filter")

    malicious_only = st.checkbox(
        "Show Malicious & Suspicious Only",
        value=False,
        key="malicious_toggle",
        help="Display only flagged or blocked IOCs",
    )

    return malicious_only


def render_statistics_panel(stats: dict[str, Any]) -> None:
    """Render statistics panel.

    Args:
        stats: Dictionary with statistics
    """
    st.markdown("---")
    st.markdown("### 📊 Statistics")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="🔴 Malicious",
            value=stats.get("malicious_count", 0),
            delta=None,
            label_visibility="visible",
        )

    with col2:
        st.metric(
            label="⚠️ Suspicious",
            value=stats.get("suspicious_count", 0),
            delta=None,
            label_visibility="visible",
        )

    with col3:
        st.metric(
            label="🟢 Clean",
            value=stats.get("clean_count", 0),
            delta=None,
            label_visibility="visible",
        )

    with col4:
        st.metric(
            label="🟠 Unknown",
            value=stats.get("unknown_count", 0),
            delta=None,
            label_visibility="visible",
        )

    # Breakdown by type
    if stats.get("by_type"):
        st.markdown("**By Type:**")
        type_cols = st.columns(len(stats["by_type"]))
        for idx, (ioc_type, count) in enumerate(sorted(stats["by_type"].items())):
            icon, label = IOC_TYPES.get(ioc_type, ("?", ioc_type.upper()))
            with type_cols[idx]:
                st.caption(f"{icon} {label}: **{count}**")


def render_filter_summary(active_filters: dict[str, Any]) -> None:
    """Render applied filters summary.

    Args:
        active_filters: Dictionary of active filters
    """
    st.markdown("---")
    st.markdown("### ✅ Applied Filters")

    types_active = [k for k, v in active_filters.get("types", {}).items() if v]
    malicious_only = active_filters.get("malicious_only", False)

    if not types_active and not malicious_only:
        st.info("No filters applied - showing all IOCs")
        return

    filter_text = "Active filters: "
    if types_active:
        filter_text += f"Types: {', '.join([t.upper() for t in types_active])} | "

    if malicious_only:
        filter_text += "Malicious/Suspicious only | "

    st.success(filter_text.rstrip(" | "))


def render_ioc_card(
    ioc: dict[str, Any],
    classification: str = "unknown",
) -> None:
    """Render a single IOC card.

    Args:
        ioc: IOC data
        classification: Classification status (clean/suspicious/unknown)
    """
    # Determine color based on classification
    if classification == "clean":
        bg_color = "rgba(5, 150, 105, 0.1)"
        border_color = "rgba(5, 150, 105, 0.3)"
        indicator_color = COLOR_CLEAN
    elif classification == "suspicious":
        bg_color = "rgba(220, 38, 38, 0.1)"
        border_color = "rgba(220, 38, 38, 0.3)"
        indicator_color = COLOR_SUSPICIOUS
    else:
        bg_color = "rgba(217, 119, 6, 0.1)"
        border_color = "rgba(217, 119, 6, 0.3)"
        indicator_color = COLOR_UNKNOWN

    col_left, col_right = st.columns([4, 1])

    with col_left:
        ioc_value = ioc.get("ioc_value", "unknown")
        ioc_type = ioc.get("ioc_type", "unknown").upper()
        verdict = ioc.get("verdict", "unknown").capitalize()
        risk_score = ioc.get("risk_score", 0)

        st.markdown(
            f"""
            <div style="background:{bg_color};border:1px solid {border_color};
            border-radius:10px;padding:12px;margin:8px 0;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>
                        <span style="font-size:11px;background:{indicator_color};color:#fff;
                        padding:2px 8px;border-radius:4px;margin-right:8px;">{ioc_type}</span>
                        <span style="font-size:11px;color:rgba(255,255,255,0.6);">
                        Risk: {risk_score}/100 | {verdict}</span>
                    </div>
                    <span style="font-size:10px;color:rgba(255,255,255,0.4);">
                    {ioc.get("providers_responded", 0)}/{ioc.get("providers_queried", 0)} providers</span>
                </div>
                <div style="margin-top:8px;font-family:monospace;font-size:12px;
                word-break:break-all;color:rgba(255,255,255,0.8);">
                {ioc_value}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_right:
        col_buttons = st.columns(1)
        with col_buttons:
            if st.button("✓ Clean", key=f"clean_{ioc_value}", use_container_width=True):
                st.session_state[f"classification_{ioc_value}"] = "clean"
                st.rerun()

            if st.button("✗ Sus", key=f"sus_{ioc_value}", use_container_width=True):
                st.session_state[f"classification_{ioc_value}"] = "suspicious"
                st.rerun()


def render_filter_controls() -> dict[str, Any]:
    """Render complete filter control panel.

    Returns:
        Dictionary with active filter settings
    """
    st.sidebar.markdown("## 🔧 Filters")

    # Type filters
    type_filters = render_type_filters()

    # Verdict toggle
    malicious_only = render_verdict_toggle()

    # Statistics (placeholder - would be populated with actual data)
    st.markdown("---")

    return {
        "types": type_filters,
        "malicious_only": malicious_only,
    }


def apply_filters(
    iocs: list[dict[str, Any]],
    filters: dict[str, Any],
) -> list[dict[str, Any]]:
    """Apply filters to IOC list.

    Args:
        iocs: List of IOC data
        filters: Filter criteria

    Returns:
        Filtered IOC list
    """
    filtered = iocs

    # Filter by type
    active_types = [k for k, v in filters.get("types", {}).items() if v]
    if active_types:
        filtered = [
            ioc for ioc in filtered
            if ioc.get("ioc_type", "").lower() in active_types
        ]

    # Filter by malicious only
    if filters.get("malicious_only", False):
        filtered = [
            ioc for ioc in filtered
            if ioc.get("verdict", "").lower() in ["malicious", "suspicious"]
        ]

    return filtered
