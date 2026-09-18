"""FastAPI service for packet metadata stored in Supabase."""

import logging
import os
from collections import Counter
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from supabase import create_client
from supabase.lib.client_options import ClientOptions

logger = logging.getLogger(__name__)
PAGE_SIZE = 1000


class SourceIPCount(BaseModel):
    source_ip: str
    count: int = Field(ge=0)


class TrafficStats(BaseModel):
    total_packets: int = Field(ge=0)
    top_source_ips: list[SourceIPCount]
    total_payload_bytes: int = Field(ge=0)


class HealthStatus(BaseModel):
    status: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not url or not key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set.")
    client = create_client(url, key)
    app.state.supabase = client
    try:
        yield
    finally:
        await run_in_threadpool(client.postgrest.aclose)
        app.state.supabase = None


app = FastAPI(title="Network Packet Sniffer", version="1.0.0", lifespan=lifespan)


@app.get("/health", response_model=HealthStatus)
def health():
    """Process liveness check; does not query the database."""
    return HealthStatus(status="ok")


@app.get("/api/stats", response_model=TrafficStats)
def stats(request: Request):
    """Aggregate visible traffic rows, paging past Supabase's row limit.

    Reads are not a transactional snapshot when traffic changes during paging.
    """
    client = request.app.state.supabase
    total_packets = 0
    total_payload_bytes = 0
    sources = Counter()
    offset = 0
    target_count = None
    try:
        while target_count is None or offset < target_count:
            query = client.table("network_traffic").select(
                "source_ip,payload_size", count="exact" if target_count is None else None
            )
            response = (
                query.order("source_ip").order("payload_size")
                .range(offset, offset + PAGE_SIZE - 1).execute()
            )
            if target_count is None:
                if response.count is None:
                    raise ValueError("Database did not return a row count")
                target_count = response.count
            rows = response.data
            if not rows:
                if offset < target_count:
                    raise ValueError("Traffic changed during pagination")
                break
            rows = rows[:target_count - offset]
            for row in rows:
                payload_size = row.get("payload_size")
                if payload_size is not None:
                    if isinstance(payload_size, bool) or not isinstance(payload_size, int) or payload_size < 0:
                        raise ValueError("Invalid payload size in database")
                    total_payload_bytes += payload_size
                if row.get("source_ip"):
                    sources[row["source_ip"]] += 1
                total_packets += 1
            offset += len(rows)
    except Exception:
        # Avoid exposing upstream error messages, credentials, or packet data.
        logger.warning("Network traffic stats query failed")
        raise HTTPException(status_code=503, detail="Traffic statistics are temporarily unavailable") from None

    top_sources = sorted(sources.items(), key=lambda item: (-item[1], item[0]))[:5]
    return TrafficStats(
        total_packets=total_packets,
        top_source_ips=[SourceIPCount(source_ip=ip, count=count) for ip, count in top_sources],
        total_payload_bytes=total_payload_bytes,
    )
