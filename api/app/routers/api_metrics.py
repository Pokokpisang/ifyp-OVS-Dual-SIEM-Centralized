from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .. import models, db
from typing import List
from datetime import datetime, timedelta

router = APIRouter(prefix="/api")

@router.post("/metrics")
def ingest_metric(metric: models.MetricCreate, db: Session = Depends(db.get_db)):
    db_metric = models.Metric(
        timestamp=metric.timestamp,
        host=metric.host,
        cpu_percent=str(metric.cpu_percent),
        ram_percent=str(metric.ram_percent),
        net_in_bytes=str(metric.net_in_bytes),
        net_out_bytes=str(metric.net_out_bytes)
    )
    db.add(db_metric)
    db.commit()
    
    # --- Simple Alert Rule: High CPU ---
    # Check last 3 samples (including this one)
    if metric.cpu_percent > 85:
        # Fetch last 2 from DB
        recent = db.query(models.Metric).filter(
            models.Metric.host == metric.host
        ).order_by(desc(models.Metric.timestamp)).limit(2).all()
        
        consecutive_high = 1
        for m in recent:
            if float(m.cpu_percent) > 85:
                consecutive_high += 1
        
        if consecutive_high >= 3:
             # Check if we already alerted recently to avoid spam (dedupe 1 min)
             recent_alert = db.query(models.Alert).filter(
                 models.Alert.host == metric.host,
                 models.Alert.source == "CPU_HIGH",
                 models.Alert.timestamp > datetime.utcnow() - timedelta(minutes=1)
             ).first()
             
             if not recent_alert:
                 alert = models.Alert(
                     timestamp=datetime.utcnow(),
                     host=metric.host,
                     severity="HIGH",
                     title="High CPU Load",
                     description=f"CPU usage > 85% for 3 samples (Current: {metric.cpu_percent}%)",
                     source="CPU_HIGH"
                 )
                 db.add(alert)
                 db.commit()

    return {"status": "ok"}

@router.get("/metrics/summary")
def get_metrics_summary(host: str = Query(None), db: Session = Depends(db.get_db)):
    # Get latest metric
    query = db.query(models.Metric)
    if host:
        query = query.filter(models.Metric.host == host)
    latest = query.order_by(desc(models.Metric.timestamp)).first()
    
    if not latest:
        return {}
        
    # Calculate Net Rate (Current - Previous)
    # Find previous metric
    prev = db.query(models.Metric).filter(
        models.Metric.host == latest.host,
        models.Metric.timestamp < latest.timestamp
    ).order_by(desc(models.Metric.timestamp)).first()
    
    net_in_rate = 0.0
    net_out_rate = 0.0
    
    if prev:
        time_diff = (latest.timestamp - prev.timestamp).total_seconds()
        if time_diff > 0:
            net_in_rate = (float(latest.net_in_bytes) - float(prev.net_in_bytes)) / time_diff
            net_out_rate = (float(latest.net_out_bytes) - float(prev.net_out_bytes)) / time_diff
            
    return {
        "cpu_percent": float(latest.cpu_percent),
        "ram_percent": float(latest.ram_percent),
        "net_in_rate": max(0, net_in_rate), # Avoid negative if restart
        "net_out_rate": max(0, net_out_rate)
    }

@router.get("/metrics/timeseries")
def get_metrics_timeseries(host: str = Query(None), minutes: int = 10, db: Session = Depends(db.get_db)):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    query = db.query(models.Metric).filter(models.Metric.timestamp > since)
    if host:
        query = query.filter(models.Metric.host == host)
    
    data = query.order_by(models.Metric.timestamp.asc()).all()
    
    result = {
        "labels": [],
        "cpu": [],
        "ram": [],
        "net_in": [],
        "net_out": []
    }
    
    last_in = 0.0
    last_out = 0.0
    last_ts = None

    for m in data:
        result["labels"].append(m.timestamp.isoformat())
        result["cpu"].append(float(m.cpu_percent))
        result["ram"].append(float(m.ram_percent))
        
        # Rate calculation for charts
        current_in = float(m.net_in_bytes)
        current_out = float(m.net_out_bytes)
        rate_in = 0.0
        rate_out = 0.0
        
        if last_ts:
            td = (m.timestamp - last_ts).total_seconds()
            if td > 0:
                 rate_in = (current_in - last_in) / td
                 rate_out = (current_out - last_out) / td
        
        result["net_in"].append(max(0, rate_in))
        result["net_out"].append(max(0, rate_out))
        
        last_in = current_in
        last_out = current_out
        last_ts = m.timestamp
        
    return result

@router.get("/alerts/recent")
def get_recent_alerts(limit: int = 20, host: str = Query(None), db: Session = Depends(db.get_db)):
    query = db.query(models.Alert)
    if host:
        query = query.filter(models.Alert.host == host)
    return query.order_by(desc(models.Alert.timestamp)).limit(limit).all()
