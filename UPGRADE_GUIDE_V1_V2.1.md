# TriageOne v1.3 → v2.1 Upgrade Guide

**Current Version**: v1.3 (April 2026)  
**Target Version**: v2.1 (August 2026)  
**Upgrade Time**: 30-60 minutes  
**Downtime Required**: 5-10 minutes

---

## 🎯 WHAT'S NEW IN v2.1

### **Major Features**

1. **IOC Type Filtering** ✨
   - 5 type filter toggles (IP, Hash, Domain, URL, Email)
   - Real-time filtering with count display
   - Multi-select capability
   - Combine with other filters

2. **Malicious-Only Toggle** 🚨
   - Quick filter for threats
   - Shows clean/unknown counts
   - Perfect for threat briefs
   - Real-time updates

3. **Color-Coded Classification** 🎨
   - Green = Clean (approved)
   - Red = Suspicious (blocked)
   - Orange = Unknown (pending)
   - User-overridable classification

4. **Real-Time Statistics** 📊
   - Live count updates
   - Break down by type
   - Break down by verdict
   - Responsive to filter changes

5. **Enhanced API** 🔌
   - `/api/filters/classify` - Classify IOCs
   - `/api/filters/filter` - Apply filters
   - `/api/filters/statistics` - Get stats
   - `/api/filters/export` - Export classifications

---

## 📋 PRE-UPGRADE CHECKLIST

- [ ] Backup current database
- [ ] Stop running TriageOne services
- [ ] Git commit all changes
- [ ] Create deployment branch
- [ ] Document current configuration
- [ ] Notify users about upgrade

---

## 🚀 UPGRADE STEPS

### **Step 1: Backup Current Installation**

```bash
# Backup database
cp -r backend/database ~/triageone_backup_v1.3/

# Backup current code
git tag v1.3-backup
git branch v1.3-backup

echo "✅ Backup complete"
```

### **Step 2: Update Backend Files**

```bash
# Copy new service
cp backend/services/classification.py \
   backend/services/classification.py

# Copy new router
cp backend/routers/filters.py \
   backend/routers/filters.py

# Backend main.py and routers/__init__.py are auto-updated

echo "✅ Backend files updated"
```

### **Step 3: Update Frontend Components**

```bash
# Copy new filter component
cp frontend/components/filters.py \
   frontend/components/filters.py

# Note: Update your triage_page.py to use new filters
# (See below for code examples)

echo "✅ Frontend components updated"
```

### **Step 4: Install New Dependencies**

```bash
# Review new requirements (if any)
# Current requirements.txt still works, but you can update to latest:

pip install --upgrade fastapi uvicorn streamlit

echo "✅ Dependencies updated"
```

### **Step 5: Run Migration Script (Optional)**

```bash
# If you want to migrate classifications to database:
python scripts/migrate_v1_to_v2.py

echo "✅ Database migration complete (if run)"
```

### **Step 6: Test Backend**

```bash
# Terminal 1: Start FastAPI
python -m uvicorn backend.main:app --reload --port 8000

# Terminal 2: Test new endpoints
curl http://localhost:8000/docs

# Should show new /api/filters/* endpoints

echo "✅ Backend tested"
```

### **Step 7: Test Frontend**

```bash
# Terminal 1: FastAPI still running
# Terminal 2: Start Streamlit
streamlit run frontend/app.py

# Test in browser:
# 1. Type filters appear in sidebar
# 2. Malicious toggle works
# 3. Statistics update in real-time
# 4. Classification buttons work

echo "✅ Frontend tested"
```

### **Step 8: Deploy to Production**

```bash
# Commit changes
git add -A
git commit -m "feat: TriageOne v2.1 upgrade with type filtering & classification"

# Push to production
git push origin main

# Monitor logs
tail -f logs/triageone.log

echo "✅ Production deployment complete"
```

---

## 🔧 INTEGRATION GUIDE

### **Updating triage_page.py to Use New Filters**

The provided `frontend/components/filters.py` has ready-to-use functions:

```python
# At top of triage_page.py
from frontend.components.filters import (
    render_filter_controls,
    apply_filters,
    render_statistics_panel,
    render_ioc_card,
)

def render():
    st.markdown("## 🔍 IOC Triage")

    # ── Sidebar: Filters ───────────────────────────
    with st.sidebar:
        filters = render_filter_controls()

    # ── Main: Content ───────────────────────────────
    tab_single, tab_bulk = st.tabs(["Single IOC", "Bulk Input"])

    with tab_single:
        # Your existing single IOC code here...
        pass

    with tab_bulk:
        col_input, col_btn = st.columns([5, 1])

        with col_input:
            ioc_list = st.text_area("IOCs (one per line)")

        with col_btn:
            if st.button("Import", type="primary"):
                # Fetch IOCs from backend
                try:
                    response = httpx.post(
                        f"{API}/api/triage/bulk",
                        json={"values": ioc_list.split("\n")},
                        timeout=60,
                    )
                    iocs = response.json()

                    # ── Apply Filters ───────────────────
                    filtered_iocs = apply_filters(iocs, filters)

                    # ── Show Statistics ──────────────────
                    if filtered_iocs:
                        stats = httpx.post(
                            f"{API}/api/filters/statistics",
                            json=filtered_iocs,
                        ).json()
                        render_statistics_panel(stats)

                    # ── Show IOC Cards ──────────────────
                    for ioc in filtered_iocs:
                        ioc_value = ioc.get("ioc_value", "")
                        classification = st.session_state.get(
                            f"classification_{ioc_value}",
                            "unknown"
                        )
                        render_ioc_card(ioc, classification)

                except Exception as e:
                    st.error(f"Error: {e}")
```

---

## 🔄 API MIGRATION EXAMPLES

### **Before (v1.3)**
```python
# Only triage endpoint
POST /api/triage/single
POST /api/triage/bulk
GET /api/triage/detect
```

### **After (v2.1)**
```python
# All v1.3 endpoints still work, PLUS:
POST /api/filters/classify      # Classify an IOC
GET /api/filters/classify/{ioc} # Get classification
POST /api/filters/filter        # Apply filters
POST /api/filters/statistics    # Calculate stats
POST /api/filters/export        # Export all classifications
POST /api/filters/import        # Import classifications
```

### **Example: Classify an IOC**
```python
import httpx

response = httpx.post(
    "http://localhost:8000/api/filters/classify",
    json={
        "ioc_value": "185.220.100.45",
        "classification": "suspicious",
        "analyst": "mandar",
        "notes": "Known Emotet C2 server",
    }
)

# Response:
{
    "ioc_value": "185.220.100.45",
    "classification": "suspicious",
    "timestamp": "2026-08-11T17:45:00.000Z",
    "analyst": "mandar",
    "badge_html": "<span style=\"...>Suspicious</span>"
}
```

### **Example: Get Statistics**
```python
response = httpx.post(
    "http://localhost:8000/api/filters/statistics",
    json=[
        {"ioc_value": "185.220.100.45", "verdict": "malicious"},
        {"ioc_value": "8.8.8.8", "verdict": "low_risk"},
        {"ioc_value": "unknown.tk", "verdict": "unknown"},
    ]
)

# Response:
{
    "total_count": 3,
    "malicious_count": 1,
    "suspicious_count": 0,
    "clean_count": 1,
    "unknown_count": 1,
    "by_type": {"ip": 2, "domain": 1},
    "by_verdict": {"malicious": 1, "low_risk": 1, "unknown": 1}
}
```

---

## 🧪 TESTING CHECKLIST

- [ ] **Backend Tests**
  - [ ] Classification endpoint works
  - [ ] Statistics endpoint works
  - [ ] Filter endpoint works
  - [ ] All providers still functional
  - [ ] Deep scan still works
  - [ ] Analyst brief still generates

- [ ] **Frontend Tests**
  - [ ] Type filters toggle correctly
  - [ ] Malicious toggle works
  - [ ] Statistics update in real-time
  - [ ] Classification buttons save
  - [ ] IOC cards display correctly
  - [ ] Filters combine properly

- [ ] **Integration Tests**
  - [ ] Single IOC workflow works
  - [ ] Bulk IOC workflow works
  - [ ] Filter combinations work
  - [ ] Report generation works
  - [ ] API calls succeed

- [ ] **Performance Tests**
  - [ ] Filter 1000 IOCs: <100ms
  - [ ] Calculate stats: <50ms
  - [ ] Classify IOC: <10ms
  - [ ] Generate report: <2s

---

## 🆘 TROUBLESHOOTING

### **Issue: New endpoints not found**
```
Solution:
1. Restart FastAPI: uvicorn backend.main:app --reload
2. Check routers/__init__.py imports filters_router
3. Check main.py includes filters router
```

### **Issue: Filter component import error**
```
Solution:
1. Ensure frontend/components/filters.py exists
2. Check __init__.py in components directory
3. Verify Python path is correct
```

### **Issue: Classification not persisting**
```
Solution:
1. Default implementation uses in-memory storage
2. For persistence, modify to use database
3. Or run migration script to enable DB storage
```

### **Issue: API returns 422 Validation Error**
```
Solution:
1. Check request body matches schema
2. Ensure classification value is valid: "clean", "suspicious", "unknown"
3. Check IOC value is not empty
```

---

## 📊 ROLLBACK PROCEDURE

If issues occur, rollback is simple:

```bash
# Option 1: Git rollback
git checkout v1.3-backup
git reset --hard v1.3-backup

# Option 2: Restore from backup
cp -r ~/triageone_backup_v1.3/* .

# Restart services
python -m uvicorn backend.main:app --port 8000
streamlit run frontend/app.py

echo "✅ Rolled back to v1.3"
```

---

## 📝 CONFIGURATION

No new environment variables needed. All v2.1 features work with current config.

Optional: Update `.env` if desired

```bash
# Optional: Enable debug logging
LOG_LEVEL=DEBUG

# Optional: Set API timeout
API_TIMEOUT=60

# Optional: Database URL (for persistent classifications)
DATABASE_URL=sqlite:///./triageone_v2.db
```

---

## 🎓 TEAM TRAINING

After upgrade, share with team:

1. **What's New**: This guide (5 min read)
2. **How-To**: Filter by type, toggle malicious, classify IOCs (10 min demo)
3. **Best Practices**: When to use each feature (5 min discussion)
4. **Q&A**: Answer questions (open-ended)

Total training time: 20-30 minutes

---

## ✅ POST-UPGRADE VERIFICATION

```bash
# Check version
curl http://localhost:8000/ | grep version
# Should show: "version": "2.1.0"

# Check new endpoints
curl http://localhost:8000/docs | grep "/api/filters"
# Should show all 6 new filter endpoints

# Check frontend
# Browser: http://localhost:8501/
# Should show type filter buttons in sidebar

echo "✅ Post-upgrade verification complete"
```

---

## 📞 SUPPORT

- **Questions**: Ask in #security-tools-support
- **Issues**: Report in GitHub Issues
- **Feedback**: Share in team standup

---

## 🎉 SUCCESS!

If you've reached here, your upgrade is complete!

**Next Steps**:
1. Monitor logs for 24 hours
2. Gather team feedback
3. Plan v2.2 features
4. Update documentation

---

**Version**: v1.3 → v2.1  
**Date**: August 11, 2026  
**Status**: Ready for Production  
**Estimated Downtime**: 5-10 minutes
