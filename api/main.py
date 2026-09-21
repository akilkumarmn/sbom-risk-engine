"""SBOM Risk Engine REST API.

    uvicorn api.main:app --port 8080         # Swagger UI at http://localhost:8080/docs

POST /score  multipart: sbom (CycloneDX JSON), scan (Trivy JSON / Nessus / CSV),
             optional asset_context (JSON); query: fuzzy, live
GET  /model  the model card (site/model_meta.json)
GET  /health
Scoring reuses engine/ (same code as the backtest) and the exported per-CVE
model output, so API and dashboard rank identically.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile

from engine.service import Intel, score_documents

SITE_DIR = Path(os.environ.get("SRE_SITE_DIR", Path(__file__).resolve().parent.parent / "site"))
app = FastAPI(title="SBOM Context Risk Engine", version="2.0",
              description="Ranks SBOM-correlated vulnerabilities by CVSS-only, the Cap-1 formula, and Formula + ML.")
INTEL = Intel(SITE_DIR)


@app.get("/health")
def health():
    return {"status": "ok", "model_trained_at": INTEL.meta["trained_at"], "data_source": INTEL.meta["data_source"]}


@app.get("/model")
def model():
    return INTEL.meta


@app.post("/score")
async def score(sbom: UploadFile = File(..., description="CycloneDX JSON SBOM"),
                scan: UploadFile = File(..., description="Trivy JSON, Nessus .nessus/.xml, or CSV"),
                asset_context: UploadFile | None = File(None, description="optional asset-context.json"),
                fuzzy: bool = Query(False, description="fuzzy component-name matching"),
                live: bool = Query(False, description="fetch live EPSS/KEV (else bundled snapshot)")):
    try:
        return score_documents(
            INTEL, (await sbom.read()).decode("utf-8-sig"), scan.filename or "scan.json",
            (await scan.read()).decode("utf-8-sig"),
            (await asset_context.read()).decode("utf-8-sig") if asset_context else None,
            fuzzy=fuzzy, live=live)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
