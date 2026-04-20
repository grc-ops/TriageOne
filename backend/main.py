"""TriageOne — FastAPI application entry point."""
from __future__ import annotations
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.routers import dashboard_router, triage_router

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s")

app = FastAPI(title="TriageOne", description="Unified IOC triage & cyber-risk monitoring API", version="1.3.0",
              docs_url="/docs", redoc_url="/redoc")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(triage_router)
app.include_router(dashboard_router)


@app.get("/")
async def root():
    return {"app": "TriageOne", "version": "1.3.0", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "ok"}
