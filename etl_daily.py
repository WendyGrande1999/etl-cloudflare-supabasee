#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ETL diario (sin parámetros) para Cloudflare Radar -> Supabase/PostgreSQL.

Incluye los siguientes pipelines ya probados por el usuario (codes 2..5,7,8), unificados:
  2) radar_http_ip_version (timeseries/summary/top) [rangos internos 30d/90d/7d]
  3) attacks_l3_summary_protocol + attacks_l3_summary_ip_version
  4) netflows_top_locations
  5) http_summary_browsers
  7) attacks_l3_top_origin_locations
  8) http_version_timeseries (HTTP/1.x vs HTTP/2 vs HTTP/3)
  9) iqi_latency_summary (p25/p50/p75)

Ejecuta TODO de forma diaria (últimas 24h) sin CLI. Programable en Windows Task Scheduler.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

import pandas as pd
import psycopg2
import psycopg2.extras as pg_extras
import requests

# ====================================================================
# Credenciales (provistas por el usuario; se mantienen tal cual)
# ====================================================================

# Cloudflare Radar API (Bearer token)
CLOUDFLARE_API_TOKEN = "DEIFSS5ceKnaTP4Kix318h5vD2Mu_x-Oi-F_JnrN"
API_BASE_V4 = "https://api.cloudflare.com/client/v4"
API_BASE_RADAR = f"{API_BASE_V4}/radar"

# Supabase (PostgreSQL) vía Pooler IPv4
SUPABASE_PASSWORD = "#JjZC7jNYD6iwdX"
SUPABASE_POOL_USER = "postgres.hhranylvbuuptmwnrtoz"
SUPABASE_POOL_HOST = "aws-1-us-east-1.pooler.supabase.com"
SUPABASE_POOL_PORT = 5432

PG_CONN_URL = (
    f"postgresql://{SUPABASE_POOL_USER}:"
    + quote_plus(SUPABASE_PASSWORD)
    + f"@{SUPABASE_POOL_HOST}:{SUPABASE_POOL_PORT}/postgres?sslmode=require"
)

# ====================================================================
# Helpers comunes
# ====================================================================

def _now_utc():
    return datetime.now(timezone.utc)

def _to_dt_utc(x):
    try:
        return pd.to_datetime(x, utc=True)
    except Exception:
        return None

def _isnum(s):
    try:
        float(s)
        return True
    except Exception:
        return False

def _coerce_float(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None

def _pg_conn():
    return psycopg2.connect(PG_CONN_URL)

# ====================================================================
# 2) CODE 2: radar_http_ip_version (sin cambios de lógica)
# ====================================================================

TABLE_IPV = "public.radar_http_ip_version"

def _pg_connect_c2():
    return _pg_conn()

def _bulk_insert_ipv(df: pd.DataFrame, conflict_constraint: str | None):
    if df.empty:
        print("⚠️ DataFrame vacío, nada que insertar.")
        return
    cols = list(df.columns)
    placeholders = "(" + ",".join(["%s"] * len(cols)) + ")"
    tuples = [tuple(x) for x in df.to_numpy()]
    conn = None
    try:
        conn = _pg_connect_c2()
        cur = conn.cursor()
        values_sql = ",".join(cur.mogrify(placeholders, row).decode("utf-8") for row in tuples)
        base_sql = f"INSERT INTO {TABLE_IPV} ({','.join(cols)}) VALUES {values_sql}"
        if conflict_constraint:
            sql = base_sql + f" ON CONFLICT ON CONSTRAINT {conflict_constraint} DO NOTHING;"
        else:
            sql = base_sql + ";"
        cur.execute(sql)
        conn.commit()
        print(f"✅ Insertadas {cur.rowcount} filas en {TABLE_IPV}.")
    except psycopg2.Error as e:
        print(f"❌ PostgreSQL: {e}")
    except Exception as e:
        print(f"❌ Error general al insertar: {e}")
    finally:
        try:
            if conn: conn.close()
        except:
            pass

def _req(endpoint: str, params: dict) -> dict | list | None:
    url = f"{API_BASE_RADAR}{endpoint}"
    headers = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}", "Accept": "application/json"}
    print(f"-> GET {url} params={params}")
    try:
        r = requests.get(url, headers=headers, params=params, timeout=60)
        if not r.ok:
            print(f"❌ HTTP {r.status_code}: {r.text[:400]}")
            r.raise_for_status()
        j = r.json()
        return j.get("result", j)
    except Exception as e:
        print(f"❌ Error fetch {endpoint}: {e}")
        return None

def _normalize_version_key(k: str) -> str:
    k = (k or "").lower().strip()
    if k in ("ipv6", "v6", "ip_v6"): return "ipv6"
    if k in ("ipv4", "v4", "ip_v4"): return "ipv4"
    return k

def _parse_agg_interval(agg: str | None) -> timedelta:
    if not agg: return timedelta(0)
    a = str(agg).upper()
    if a in ("ONE_DAY", "1D"): return timedelta(days=1)
    if a in ("ONE_HOUR", "1H"): return timedelta(hours=1)
    if a in ("FIFTEEN_MINUTES", "15M", "QUARTER_HOUR"): return timedelta(minutes=15)
    if a in ("THIRTY_MINUTES", "30M"): return timedelta(minutes=30)
    if a in ("FIVE_MINUTES", "5M"): return timedelta(minutes=5)
    return timedelta(0)

def _safe_ts(x) -> pd.Timestamp | None:
    try:
        t = pd.to_datetime(x, utc=True, errors="coerce")
        return None if pd.isna(t) else t
    except:
        return None

def _ensure_defaults(row: dict, grain: str, agg_interval_td: timedelta, top_scope_default: str | None = None):
    if grain == "timeseries":
        ts = row.get("metric_ts")
        if ts and not row.get("date_start"): row["date_start"] = ts
        if ts and not row.get("date_end"):   row["date_end"]   = ts + (agg_interval_td or timedelta(0))
        if row.get("rank") is None: row["rank"] = 0
        if not row.get("top_scope"): row["top_scope"] = "timeseries"
    elif grain == "summary":
        if not row.get("metric_ts"):
            row["metric_ts"] = row.get("date_end") or row.get("date_start")
        if row.get("rank") is None: row["rank"] = 0
        if not row.get("top_scope"): row["top_scope"] = "summary"
    elif grain == "top":
        if not row.get("metric_ts"):
            row["metric_ts"] = row.get("date_end") or row.get("date_start")
        if not row.get("top_scope"):
            row["top_scope"] = top_scope_default or "top"

    for k in ("location_type", "location_id", "ip_version", "source_endpoint"):
        if not row.get(k): row[k] = "n/a"

    try:
        row["share"] = float(row.get("share", 0.0))
    except:
        row["share"] = 0.0

    if row.get("agg_interval") is None:
        row["agg_interval"] = row.get("agg_interval_text") or ""

    if not row.get("ingestion_ts"):
        row["ingestion_ts"] = _now_utc()

    row.pop("agg_interval_text", None)
    return row

def ingest_timeseries_ipv(location: str, date_range: str | None, start: str | None, end: str | None, agg_interval: str | None):
    endpoint = "/http/timeseries_groups/ip_version"
    params = {}
    if date_range: params["dateRange"] = date_range
    if start and end:
        params["dateStart"] = start
        params["dateEnd"] = end
    if agg_interval: params["aggInterval"] = agg_interval
    if location: params["location"] = location

    result = _req(endpoint, params)
    if result is None:
        print("⏭️ Sin datos.")
        return

    series_obj = None
    if isinstance(result, dict):
        s = result.get("series")
        if isinstance(s, list) and s:
            series_obj = s[0]
        elif isinstance(s, dict):
            series_obj = s
        else:
            series_obj = result.get("serie_0") or result
    elif isinstance(result, list) and result:
        series_obj = result[0]

    if not isinstance(series_obj, dict):
        print("⚠️ timeseries: formato de series no reconocido.")
        return

    meta = result.get("meta", {}) if isinstance(result, dict) else {}
    agg_text = meta.get("aggInterval") or agg_interval or ""
    agg_td = _parse_agg_interval(agg_text)

    timestamps = series_obj.get("timestamps") or series_obj.get("timeStamps") or []
    if not timestamps:
        print("⚠️ timeseries: sin timestamps.")
        return

    version_keys = [k for k in series_obj.keys() if _normalize_version_key(k) in ("ipv4", "ipv6")]
    now_utc = _now_utc()
    location_id = (location.upper() if location else "WORLD")
    l_type = "global" if location_id == "WORLD" else "country"

    rows = []
    for i, ts in enumerate(timestamps):
        ts_dt = _safe_ts(ts)
        if not ts_dt:
            continue
        for vk in version_keys:
            ver = _normalize_version_key(vk)
            arr = series_obj.get(vk, [])
            val = 0.0
            if isinstance(arr, list) and i < len(arr) and arr[i] is not None:
                try: val = float(arr[i])
                except: val = 0.0
            row = {
                "grain": "timeseries",
                "location_type": l_type,
                "location_id": location_id,
                "ip_version": ver,
                "share": val,
                "metric_ts": ts_dt,
                "date_start": None,
                "date_end": None,
                "agg_interval": None,
                "rank": None,
                "top_scope": None,
                "source_endpoint": "http.timeseries_groups.ip_version",
                "ingestion_ts": now_utc,
                "agg_interval_text": str(agg_text)
            }
            rows.append(_ensure_defaults(row, "timeseries", agg_td))

    df = pd.DataFrame(rows)
    if "agg_interval_text" in df.columns:
        df.drop(columns=["agg_interval_text"], inplace=True)
    _bulk_insert_ipv(df, "uq_ipv_ts")

def ingest_summary_ipv(location: str, date_range: str | None, start: str | None, end: str | None):
    endpoint = "/http/summary/ip_version"
    params = {}
    if date_range: params["dateRange"] = date_range
    if start and end:
        params["dateStart"] = start
        params["dateEnd"] = end
    if location: params["location"] = location

    result = _req(endpoint, params)
    if result is None:
        print("⏭️ Sin datos.")
        return

    meta = result.get("meta", {}) if isinstance(result, dict) else {}
    ds = de = None
    try:
        dr = meta.get("dateRange", [])
        if dr and isinstance(dr, list):
            ds = _safe_ts(dr[0].get("startTime"))
            de = _safe_ts(dr[0].get("endTime"))
    except:
        pass

    ver_map = (
        (result.get("ip_version") if isinstance(result, dict) else None)
        or (result.get("version") if isinstance(result, dict) else None)
        or (result.get("protocol") if isinstance(result, dict) else None)
        or (result if isinstance(result, dict) else {})
    )
    if not isinstance(ver_map, dict):
        print("⚠️ summary: mapa de versiones no reconocido.")
        return

    keys = [k for k in ver_map.keys() if _normalize_version_key(k) in ("ipv4", "ipv6")]

    now_utc = _now_utc()
    location_id = (location.upper() if location else "WORLD")
    l_type = "global" if location_id == "WORLD" else "country"

    rows = []
    for k in keys:
        ver = _normalize_version_key(k)
        val_raw = ver_map.get(k)
        try:
            val = float(val_raw)
        except:
            continue
        row = {
            "grain": "summary",
            "location_type": l_type,
            "location_id": location_id,
            "ip_version": ver,
            "share": val,
            "metric_ts": None,
            "date_start": ds,
            "date_end": de,
            "agg_interval": "",
            "rank": None,
            "top_scope": None,
            "source_endpoint": "http.summary.ip_version",
            "ingestion_ts": now_utc
        }
        rows.append(_ensure_defaults(row, "summary", timedelta(0)))

    df = pd.DataFrame(rows)
    _bulk_insert_ipv(df, "uq_ipv_summary")

def ingest_top_ipv(ip_version: str, date_range: str | None, start: str | None, end: str | None, limit: int, top_scope: str):
    ip_version = _normalize_version_key(ip_version)
    if ip_version not in ("ipv4", "ipv6"):
        raise ValueError("ip_version debe ser ipv4 o ipv6")

    endpoint = f"/http/top/locations/ip_version/{ip_version}"
    params = {"limit": limit}
    if date_range: params["dateRange"] = date_range
    if start and end:
        params["dateStart"] = start
        params["dateEnd"] = end

    result = _req(endpoint, params)
    if result is None:
        print("⏭️ Sin datos.")
        return

    meta = result.get("meta", {}) if isinstance(result, dict) else {}
    ds = de = None
    try:
        dr = meta.get("dateRange", [])
        if dr and isinstance(dr, list):
            ds = _safe_ts(dr[0].get("startTime"))
            de = _safe_ts(dr[0].get("endTime"))
    except:
        pass

    candidates = None
    if isinstance(result, dict):
        candidates = (
            result.get("locations")
            or result.get("countries")
            or result.get("top")
            or result.get("items")
            or result.get("data")
        )
    if candidates is None:
        candidates = result if isinstance(result, list) else []

    now_utc = _now_utc()
    rows = []
    rank = 0
    for it in candidates:
        if not isinstance(it, dict):
            continue
        iso = it.get("location") or it.get("country") or it.get("code") or it.get("alpha2") or it.get("alpha_2")
        if not iso:
            continue
        iso = str(iso).upper()
        raw_val = it.get("share") or it.get("value") or it.get("requests") or it.get("count")
        try:
            val = float(raw_val)
        except:
            continue
        rank += 1
        row = {
            "grain": "top",
            "location_type": "country",
            "location_id": iso,
            "ip_version": ip_version,
            "share": val,
            "metric_ts": None,
            "date_start": ds,
            "date_end": de,
            "agg_interval": "",
            "rank": rank,
            "top_scope": top_scope,
            "source_endpoint": "http.top.locations.ip_version",
            "ingestion_ts": now_utc
        }
        rows.append(_ensure_defaults(row, "top", timedelta(0), top_scope_default=top_scope))

    df = pd.DataFrame(rows)
    _bulk_insert_ipv(df, "uq_ipv_top")

def run_http_ipv_all():
    CENTROAMERICA_PAISES = ["BZ", "GT", "HN", "SV", "NI", "CR", "PA"]
    DATE_RANGE_TIMESERIES = "30d"
    DATE_RANGE_SUMMARY   = "90d"

    print(f"\n--- 1A. Ingestando Timeseries (30 días, Centroamérica) ---")
    for location_code in CENTROAMERICA_PAISES:
        print(f"-> Ingestando tendencia diaria para: {location_code}")
        ingest_timeseries_ipv(
            location=location_code,
            date_range=DATE_RANGE_TIMESERIES,
            start=None,
            end=None,
            agg_interval="1d"
        )

    print(f"\n--- 1B. Ingestando Timeseries (30 días, Global) ---")
    ingest_timeseries_ipv(
        location="",
        date_range=DATE_RANGE_TIMESERIES,
        start=None,
        end=None,
        agg_interval="1d"
    )

    print(f"\n--- 2. Ingestando Summary (90 días, El Salvador: SV) ---")
    ingest_summary_ipv(
        location="SV",
        date_range=DATE_RANGE_SUMMARY,
        start=None,
        end=None
    )

    print(f"\n--- 3. Ingestando Top IPv4 Global (7 días, 50 países) ---")
    ingest_top_ipv(
        ip_version="ipv4",
        date_range="7d",
        start=None,
        end=None,
        limit=50,
        top_scope="global_7d"
    )

    print(f"\n--- 4. Ingestando Top IPv6 Global (7 días, 50 países) ---")
    ingest_top_ipv(
        ip_version="ipv6",
        date_range="7d",
        start=None,
        end=None,
        limit=50,
        top_scope="global_7d"
    )

    print("\n✅ http_ipv_all completado.")


# ====================================================================
# 3) CODE 3: L3 summaries (protocol + ip_version) (sin cambios de lógica)
# ====================================================================

TABLE_L3_PROTO = "attacks_l3_summary_protocol"
TABLE_L3_IPVER = "attacks_l3_summary_ip_version"
EP_L3_SUMMARY_PROTOCOL   = "/attacks/layer3/summary/protocol"
EP_L3_SUMMARY_IP_VERSION = "/attacks/layer3/summary/ip_version"

def fetch_summary(endpoint: str, date_range: str = "30d") -> dict | None:
    url = f"{API_BASE_RADAR}{endpoint}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {"dateRange": date_range}

    print(f"-> Consultando {url}  ?dateRange={date_range}")
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        if not resp.ok:
            print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
            resp.raise_for_status()
        data = resp.json()
        if "result" not in data:
            raise ValueError("Respuesta sin 'result'")
        return data
    except Exception as e:
        print(f"❌ Error en fetch_summary({endpoint}): {e}")
        return None

def _cast_confidence_level(meta_obj) -> int | None:
    try:
        lvl = meta_obj.get("confidenceInfo", {}).get("level")
    except Exception:
        return None
    if lvl is None:
        return None
    try:
        return int(lvl)
    except Exception:
        pass
    mapping = {
        "low": 1,
        "medium": 2,
        "med": 2,
        "high": 3,
        "very_high": 4,
    }
    try:
        s = str(lvl).strip().lower()
        return mapping.get(s, None)
    except Exception:
        return None

def extract_meta_fields(result: dict):
    meta = result.get("meta", {})
    window_start = window_end = last_updated = None
    unit = None
    try:
        dr = meta.get("dateRange", [])
        if dr and isinstance(dr, list) and isinstance(dr[0], dict):
            window_start = pd.to_datetime(dr[0].get("startTime"), utc=True)
            window_end   = pd.to_datetime(dr[0].get("endTime"), utc=True)
    except Exception:
        pass
    try:
        units = meta.get("units", [])
        if units and isinstance(units, list) and isinstance(units[0], dict):
            unit = units[0].get("value")
    except Exception:
        pass
    confidence_level = _cast_confidence_level(meta)
    try:
        last_updated = pd.to_datetime(meta.get("lastUpdated"), utc=True)
    except Exception:
        pass
    return window_start, window_end, unit, confidence_level, last_updated

def transform_summary_generic(payload: dict, item_column: str) -> pd.DataFrame:
    if not payload or "result" not in payload:
        return pd.DataFrame()
    result = payload["result"]
    summary = result.get("summary_0", {})
    if not isinstance(summary, dict) or not summary:
        print("⚠️ 'summary_0' vacío o no dict.")
        return pd.DataFrame()
    window_start, window_end, unit, confidence_level, last_updated = extract_meta_fields(result)
    if window_start is None or window_end is None:
        print("⚠️ Meta.dateRange no disponible; se omiten filas.")
        return pd.DataFrame()
    rows = []
    now_utc = _now_utc()
    for key, raw_val in summary.items():
        try:
            val = float(raw_val)
        except Exception:
            val = 0.0
        rows.append({
            "window_start": window_start,
            "window_end": window_end,
            item_column: key,
            "value": val,
            "unit": unit,
            "confidence_level": confidence_level,
            "last_updated": last_updated,
            "source_json": payload,
            "ingestion_timestamp": now_utc
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
        df["window_end"]   = pd.to_datetime(df["window_end"], utc=True)
        df.sort_values(["window_start", "window_end", item_column], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ Transformación {item_column}: {len(df)} filas")
    return df

def _to_pg_value(v):
    try:
        if pd.isna(v):
            return None
    except Exception:
        pass
    if isinstance(v, pd.Timestamp):
        if pd.isna(v):
            return None
        return v.to_pydatetime()
    return v

def upsert_dataframe(df: pd.DataFrame, table_name: str, conflict_cols: list[str]):
    if df.empty:
        print(f"⚠️ No hay datos para cargar en {table_name}.")
        return
    cols = list(df.columns)
    colnames_sql = ",".join(cols)
    placeholders = "(" + ",".join(["%s"] * len(cols)) + ")"
    rows = []
    for _, r in df.iterrows():
        row = []
        for c in cols:
            v = r[c]
            if c == "source_json":
                if isinstance(v, str):
                    try:
                        v = json.loads(v)
                    except Exception:
                        v = {"raw": v}
                v = pg_extras.Json(v)
            else:
                v = _to_pg_value(v)
            row.append(v)
        rows.append(tuple(row))
    conn = None
    try:
        conn = _pg_conn()
        cur = conn.cursor()
        values_block = ",".join(cur.mogrify(placeholders, tup).decode("utf-8") for tup in rows)
        conflict_sql = ", ".join(conflict_cols)
        insert_sql = f"""
            INSERT INTO {table_name} ({colnames_sql})
            VALUES {values_block}
            ON CONFLICT ({conflict_sql}) DO NOTHING;
        """
        cur.execute(insert_sql)
        conn.commit()
        print(f"✅ Carga OK: {cur.rowcount} filas nuevas en '{table_name}'.")
    except Exception as e:
        print(f"❌ Error al cargar en {table_name}: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def run_attacks_l3_summaries(date_range: str = "30d"):
    print(f"=== Ingesta SUMMARY L3 (dateRange={date_range}) ===")
    payload_proto = fetch_summary(EP_L3_SUMMARY_PROTOCOL, date_range=date_range)
    df_proto = transform_summary_generic(payload_proto, item_column="attack_protocol")
    if not df_proto.empty:
        upsert_dataframe(df_proto, TABLE_L3_PROTO, conflict_cols=["window_start", "window_end", "attack_protocol"])
    payload_ipver = fetch_summary(EP_L3_SUMMARY_IP_VERSION, date_range=date_range)
    df_ipver = transform_summary_generic(payload_ipver, item_column="ip_version")
    if not df_ipver.empty:
        upsert_dataframe(df_ipver, TABLE_L3_IPVER, conflict_cols=["window_start", "window_end", "ip_version"])
    print("=== L3 summaries Finalizado ===")


# ====================================================================
# 4) CODE 4: netflows_top_locations (sin cambios de lógica)
# ====================================================================

TABLE_TOP_LOCS = "netflows_top_locations"

def fetch_netflows_top_locations(date_range="30d", product="ALL", location_type="country", limit_requested=100, geo_id=None):
    url = f"{API_BASE_RADAR}/netflows/top/locations"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {
        "dateRange": date_range,
        "product": product,
        "locationType": location_type,
        "limit": limit_requested,
        "format": "json"
    }
    if geo_id:
        params["geoId"] = geo_id

    print(f"-> GET {url}  params={params}")
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        if not resp.ok:
            print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
            resp.raise_for_status()
        data = resp.json()
        if "result" not in data:
            raise ValueError("Respuesta sin 'result'")
        return data
    except Exception as e:
        print(f"❌ Error en fetch_netflows_top_locations: {e}")
        return None

def _meta_fields(result: dict):
    meta = result.get("meta", {}) or {}
    window_start = window_end = last_updated = None
    unit = None
    try:
        dr = meta.get("dateRange", [])
        if dr and isinstance(dr, list) and isinstance(dr[0], dict):
            window_start = pd.to_datetime(dr[0].get("startTime"), utc=True)
            window_end   = pd.to_datetime(dr[0].get("endTime"), utc=True)
    except Exception:
        pass
    try:
        units = meta.get("units", [])
        if units and isinstance(units, list) and isinstance(units[0], dict):
            unit = units[0].get("value")
    except Exception:
        pass
    try:
        last_updated = pd.to_datetime(meta.get("lastUpdated"), utc=True)
    except Exception:
        pass
    return window_start, window_end, unit, last_updated

def _best_location_fields(item: dict, default_location_type: str):
    loc_type = default_location_type
    loc_id = None
    loc_name = None

    loc = item.get("location")
    if isinstance(loc, dict):
        loc_type = loc.get("type") or loc.get("locationType") or default_location_type
        loc_id = (
            loc.get("code") or loc.get("id") or loc.get("geoId") or loc.get("slug")
            or loc.get("alpha2") or loc.get("alpha3") or loc.get("cca2") or loc.get("cca3")
            or loc.get("isoCode") or loc.get("iso2") or loc.get("iso3") or loc.get("iso_code")
        )
        loc_name = (
            loc.get("name") or loc.get("label") or loc.get("countryName") or loc.get("displayName")
            or loc.get("fullName")
        )

    if not loc_id:
        loc_id = (item.get("clientCountryAlpha2")
                  or item.get("client_alpha2")
                  or item.get("alpha2"))
    if not loc_name:
        loc_name = (item.get("clientCountryName")
                    or item.get("client_country_name")
                    or item.get("name") or item.get("label"))

    if not loc_id:
        loc_id = item.get("key") or item.get("code") or item.get("id")

    if not loc_type:
        loc_type = default_location_type
    if not loc_id:
        loc_id = "UNKNOWN"

    return loc_type, loc_id, loc_name

def transform_netflows_top_locations(payload: dict, product: str, location_type: str, limit_requested: int) -> pd.DataFrame:
    if not payload or "result" not in payload:
        return pd.DataFrame()
    result = payload["result"]
    window_start, window_end, unit, last_updated = _meta_fields(result)
    if window_start is None or window_end is None:
        print("⚠️ Meta.dateRange no disponible; se omiten filas.")
        return pd.DataFrame()

    top = result.get("top_0", []) or []
    rows = []
    now_utc = _now_utc()

    for idx, item in enumerate(top, start=1):
        try:
            value = float(item.get("value"))
        except Exception:
            value = 0.0
        rnk = item.get("rank")
        try:
            rank = int(rnk) if rnk is not None else idx
        except Exception:
            rank = idx
        loc_type, loc_id, loc_name = _best_location_fields(item, location_type)
        rows.append({
            "window_start": window_start,
            "window_end": window_end,
            "location_type": loc_type,
            "location_id": loc_id,
            "location_name": loc_name,
            "value": value,
            "rank": rank,
            "unit": unit,
            "product": product,
            "limit_requested": limit_requested,
            "last_updated": last_updated,
            "source_json": payload,
            "ingestion_timestamp": now_utc
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
        df["window_end"]   = pd.to_datetime(df["window_end"], utc=True)
        df.sort_values(["window_start", "window_end", "rank"], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ Transformación netflows top locations: {len(df)} filas")
    return df

def upsert_netflows_df(df: pd.DataFrame, table_name: str, conflict_cols: list[str]):
    if df.empty:
        print(f"⚠️ No hay datos para cargar en {table_name}.")
        return
    cols = list(df.columns)
    colnames_sql = ",".join(cols)
    placeholders = "(" + ",".join(["%s"] * len(cols)) + ")"
    rows = []
    for _, r in df.iterrows():
        row = []
        for c in cols:
            v = r[c]
            if c == "source_json":
                if isinstance(v, str):
                    try:
                        v = json.loads(v)
                    except Exception:
                        v = {"raw": v}
                v = pg_extras.Json(v)
            else:
                try:
                    if pd.isna(v):
                        v = None
                except Exception:
                    pass
                if isinstance(v, pd.Timestamp):
                    v = None if pd.isna(v) else v.to_pydatetime()
            row.append(v)
        rows.append(tuple(row))

    conn = None
    try:
        conn = _pg_conn()
        cur = conn.cursor()
        values_block = ",".join(cur.mogrify(placeholders, tup).decode("utf-8") for tup in rows)
        conflict_sql = ", ".join(conflict_cols)
        insert_sql = f"""
            INSERT INTO {table_name} ({colnames_sql})
            VALUES {values_block}
            ON CONFLICT ({conflict_sql}) DO NOTHING;
        """
        cur.execute(insert_sql)
        conn.commit()
        print(f"✅ Carga OK: {cur.rowcount} filas nuevas en '{table_name}'.")
    except Exception as e:
        print(f"❌ Error al cargar en {table_name}: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def run_netflows_top_locations(date_range="30d", product="ALL", location_type="country", limit=100, geo_id=None):
    print(f"=== NetFlows Top Locations (dateRange={date_range}, product={product}, locationType={location_type}) ===")
    payload = fetch_netflows_top_locations(date_range=date_range, product=product, location_type=location_type, limit_requested=limit, geo_id=geo_id)
    df = transform_netflows_top_locations(payload, product=product, location_type=location_type, limit_requested=limit)
    if not df.empty:
        upsert_netflows_df(df, TABLE_TOP_LOCS, conflict_cols=["window_start", "window_end", "location_type", "location_id", "product"])
    print("=== NetFlows Top Locations Finalizado ===")


# ====================================================================
# 5) CODE 5: http_summary_browsers (sin cambios de lógica)
# ====================================================================

TABLE_HTTP_BROWSERS = "http_summary_browsers"
EP_HTTP_SUMMARY_BROWSERS = "/radar/http/summary/browser"  # ojo: aquí base v4 + /radar

def fetch_cloudflare_summary_browsers(start_dt_utc, end_dt_utc):
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {
        "dateStart": start_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd":   end_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    url = f"{API_BASE_V4}{EP_HTTP_SUMMARY_BROWSERS}"
    print(f"-> GET {url}")
    print(f"   Rango: {params['dateStart']}  a  {params['dateEnd']}")
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if not resp.ok:
        print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success", False):
        raise ValueError(f"Respuesta de API sin 'success=true'. Errores: {data.get('errors')}")
    return data.get("result")

def transform_top_browsers(result_json: dict) -> pd.DataFrame:
    if not isinstance(result_json, dict):
        return pd.DataFrame()
    meta = result_json.get("meta", {}) or {}
    date_range = meta.get("dateRange", [])
    if not date_range:
        print("⚠️ meta.dateRange vacío")
        return pd.DataFrame()
    window = date_range[0] or {}
    window_start = _to_dt_utc(window.get("startTime"))
    window_end   = _to_dt_utc(window.get("endTime"))
    if window_start is None or window_end is None:
        print("⚠️ window_start/window_end no válidos")
        return pd.DataFrame()
    normalization = meta.get("normalization")
    unit = None
    units = meta.get("units", []) or []
    if isinstance(units, list) and units:
        unit = units[0].get("value") or units[0].get("name")
    conf_info = meta.get("confidenceInfo", {}) or {}
    confidence_level = conf_info.get("level")
    annotations      = conf_info.get("annotations")
    last_updated     = _to_dt_utc(meta.get("lastUpdated"))
    summary = result_json.get("summary_0", {}) or {}
    rows = []
    now_utc = _now_utc()
    ranked_summary = sorted(
        summary.items(),
        key=lambda item: float(item[1]) if _isnum(item[1]) else 0,
        reverse=True
    )
    for idx, (browser_name, val_str) in enumerate(ranked_summary):
        try:
            val = float(val_str)
        except (TypeError, ValueError):
            val = None
        rows.append({
            "window_start":          window_start,
            "window_end":            window_end,
            "rank":                  idx + 1,
            "browser_name":          browser_name,
            "value":                 val,
            "normalization":         normalization,
            "unit":                  unit,
            "confidence_level":      confidence_level,
            "last_updated":          last_updated,
            "annotations":           annotations,
            "ingestion_timestamp":   now_utc
        })
    df = pd.DataFrame.from_records(rows)
    if not df.empty:
        df.drop_duplicates(subset=["window_start", "window_end", "browser_name"], keep="last", inplace=True)
        df.sort_values(["window_start", "window_end", "rank"], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ Transformación OK: {len(df)} filas")
    return df

def load_http_browsers(df: pd.DataFrame):
    if df.empty:
        print("⚠️ No hay datos para cargar.")
        return
    expected_cols = [
        "window_start", "window_end", "rank", "browser_name", "value",
        "normalization", "unit", "confidence_level", "last_updated",
        "annotations", "ingestion_timestamp"
    ]
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Faltan columnas en el DataFrame: {missing}")
    df = df[expected_cols]
    conn = None
    try:
        conn = _pg_conn()
        cur = conn.cursor()
        tuples = [tuple(x) for x in df.to_numpy()]
        cols = ",".join(expected_cols)
        placeholders_base = "(" + ",".join(["%s"] * len(expected_cols)) + ")"
        values_sql = ",".join(cur.mogrify(placeholders_base, row).decode("utf-8") for row in tuples)
        insert_sql = f"""
            INSERT INTO {TABLE_HTTP_BROWSERS} ({cols})
            VALUES {values_sql}
            ON CONFLICT (window_start, window_end, browser_name)
            DO UPDATE SET
                rank = EXCLUDED.rank,
                value = EXCLUDED.value,
                normalization = EXCLUDED.normalization,
                unit = EXCLUDED.unit,
                confidence_level = EXCLUDED.confidence_level,
                last_updated = EXCLUDED.last_updated,
                annotations = EXCLUDED.annotations,
                ingestion_timestamp = EXCLUDED.ingestion_timestamp;
        """
        cur.execute(insert_sql)
        conn.commit()
        print(f"✅ Carga/Actualización OK: {len(df)} filas procesadas en '{TABLE_HTTP_BROWSERS}'.")
    except psycopg2.Error as e:
        print(f"❌ Error PostgreSQL/Supabase: {e}")
    except Exception as e:
        print(f"❌ Error general al cargar: {e}")
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

def run_http_summary_browsers(days=1):
    now_utc = _now_utc()
    end_date = now_utc.replace(minute=0, second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)
    print(f"--- Summary Browsers: últimos {days} día(s) ---")
    try:
        result = fetch_cloudflare_summary_browsers(start_date, end_date)
        df = transform_top_browsers(result)
        load_http_browsers(df)
    except requests.exceptions.HTTPError as e:
        print(f"🛑 Error crítico de HTTP (4xx/5xx): {e}")
    except ValueError as e:
        print(f"🛑 Error de valor (API Success=False o Data): {e}")
    except Exception as e:
        print(f"🛑 Error inesperado: {e}")
    print("--- Proceso Finalizado (http_summary_browsers) ---")


# ====================================================================
# 7) CODE 7: attacks_l3_top_origin_locations (NUEVO)
# ====================================================================

TABLE_L3_TOP_ORIGIN = "attacks_l3_top_origin_locations"
EP_L3_TOP_ORIGIN = "/attacks/layer3/top/locations/origin"

def fetch_attacks_l3_top_origin(date_range: str = "30d", limit_requested: int = 100) -> dict | None:
    """
    Llama a /radar/attacks/layer3/top/locations/origin
    Devuelve el envelope completo (success, result={meta, top_0}, ...).
    """
    url = f"{API_BASE_RADAR}{EP_L3_TOP_ORIGIN}"
    headers = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}", "Accept": "application/json"}
    params = {"dateRange": date_range, "limit": limit_requested, "format": "json"}
    print(f"-> GET {url}  params={params}")
    try:
        r = requests.get(url, headers=headers, params=params, timeout=60)
        if not r.ok:
            print(f"❌ HTTP {r.status_code}: {r.text[:400]}")
            r.raise_for_status()
        data = r.json()
        if "result" not in data:
            raise ValueError("Respuesta sin 'result'")
        return data
    except Exception as e:
        print(f"❌ Error fetch L3 top origin: {e}")
        return None

def _meta_fields_l3_origin(result: dict):
    """ Extrae ventana, unidad, confidence y last_updated del envelope result. """
    meta = result.get("meta", {}) or {}
    window_start = window_end = last_updated = None
    unit = None
    confidence_level = None
    try:
        dr = meta.get("dateRange", [])
        if dr and isinstance(dr, list) and isinstance(dr[0], dict):
            window_start = _to_dt_utc(dr[0].get("startTime"))
            window_end   = _to_dt_utc(dr[0].get("endTime"))
    except: pass
    try:
        units = meta.get("units", [])
        if units and isinstance(units, list) and isinstance(units[0], dict):
            unit = units[0].get("value")
    except: pass
    try:
        confidence_level = meta.get("confidenceInfo", {}).get("level")
    except: pass
    try:
        last_updated = _to_dt_utc(meta.get("lastUpdated"))
    except: pass
    return window_start, window_end, unit, confidence_level, last_updated

def _best_location_fields_origin(item: dict, default_type: str = "country"):
    """
    Tolerante a claves del endpoint ORIGIN:
    - originCountryAlpha2 / originCountryName
    - location: { type, code/id/alpha2..., name/label/countryName }
    - clientCountryAlpha2 / clientCountryName / code / key...
    """
    loc_type = default_type
    loc_id = item.get("originCountryAlpha2")
    loc_name = item.get("originCountryName")

    loc = item.get("location")
    if (not loc_id or not loc_name) and isinstance(loc, dict):
        loc_type = loc.get("type") or default_type
        loc_id = loc_id or (
            loc.get("code") or loc.get("id") or loc.get("alpha2") or
            loc.get("alpha_2") or loc.get("iso2") or loc.get("cca2")
        )
        loc_name = loc_name or (loc.get("name") or loc.get("label") or loc.get("countryName"))

    if not loc_id:
        loc_id = (item.get("clientCountryAlpha2") or item.get("alpha2") or
                  item.get("key") or item.get("code") or item.get("id"))
    if not loc_name:
        loc_name = (item.get("clientCountryName") or item.get("name") or item.get("label"))

    if not loc_type:
        loc_type = default_type
    if not loc_id:
        loc_id = "UNKNOWN"
    return loc_type, str(loc_id).upper(), loc_name

def transform_l3_top_origin(payload: dict, limit_requested: int) -> pd.DataFrame:
    """
    Transforma { result: { meta, top_0 } } en DataFrame listo para upsert.
    """
    if not payload or "result" not in payload:
        return pd.DataFrame()

    result = payload["result"]
    window_start, window_end, unit, confidence_level, last_updated = _meta_fields_l3_origin(result)
    if window_start is None or window_end is None:
        print("⚠️ Meta.dateRange no disponible; se omiten filas.")
        return pd.DataFrame()

    items = result.get("top_0") or result.get("top") or []
    rows = []
    now_utc = _now_utc()

    for idx, it in enumerate(items, start=1):
        raw_val = it.get("value")
        try:
            value = float(raw_val)
        except:
            value = 0.0

        rnk = it.get("rank")
        try:
            rank = int(rnk) if rnk is not None else idx
        except:
            rank = idx

        loc_type, loc_id, loc_name = _best_location_fields_origin(it)

        rows.append({
            "window_start":        window_start,
            "window_end":          window_end,
            "location_type":       loc_type,
            "location_id":         loc_id,
            "location_name":       loc_name,
            "value":               value,
            "rank":                rank,
            "unit":                unit,
            "limit_requested":     limit_requested,
            "confidence_level":    confidence_level,
            "last_updated":        last_updated,
            "source_json":         payload,
            "ingestion_timestamp": now_utc
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
        df["window_end"]   = pd.to_datetime(df["window_end"],   utc=True)
        df.sort_values(["window_start","window_end","rank"], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ Transformación L3 top origin: {len(df)} filas")
    return df

def upsert_l3_top_origin_df(df: pd.DataFrame, table_name: str, conflict_cols: list[str]):
    """
    Inserta con JSONB y ON CONFLICT DO NOTHING (mismo patrón que netflows).
    """
    if df.empty:
        print(f"⚠️ No hay datos para cargar en {table_name}.")
        return
    cols = list(df.columns)
    colnames_sql = ",".join(cols)
    placeholders = "(" + ",".join(["%s"] * len(cols)) + ")"
    rows = []
    for _, r in df.iterrows():
        row = []
        for c in cols:
            v = r[c]
            if c == "source_json":
                if isinstance(v, str):
                    try:
                        v = json.loads(v)
                    except Exception:
                        v = {"raw": v}
                v = pg_extras.Json(v)
            else:
                try:
                    if pd.isna(v):
                        v = None
                except Exception:
                    pass
                if isinstance(v, pd.Timestamp):
                    v = None if pd.isna(v) else v.to_pydatetime()
            row.append(v)
        rows.append(tuple(row))

    conn = None
    try:
        conn = _pg_conn()
        cur = conn.cursor()
        values_block = ",".join(cur.mogrify(placeholders, tup).decode("utf-8") for tup in rows)
        conflict_sql = ", ".join(conflict_cols)
        insert_sql = f"""
            INSERT INTO {table_name} ({colnames_sql})
            VALUES {values_block}
            ON CONFLICT ({conflict_sql}) DO NOTHING;
        """
        cur.execute(insert_sql)
        conn.commit()
        print(f"✅ Carga OK: {cur.rowcount} filas nuevas en '{table_name}'.")
    except Exception as e:
        print(f"❌ Error al cargar en {table_name}: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def run_attacks_l3_top_origin(date_range: str = "30d", limit: int = 100):
    print(f"=== L3 Top Origin (dateRange={date_range}, limit={limit}) ===")
    payload = fetch_attacks_l3_top_origin(date_range=date_range, limit_requested=limit)
    df = transform_l3_top_origin(payload, limit_requested=limit)
    if not df.empty:
        upsert_l3_top_origin_df(
            df,
            TABLE_L3_TOP_ORIGIN,
            conflict_cols=["window_start", "window_end", "location_type", "location_id"]
        )
    print("=== L3 Top Origin Finalizado ===")


# ====================================================================
# 8) CODE 8: http_version_timeseries (HTTP/1.x vs HTTP/2 vs HTTP/3)
# ====================================================================

EP_HTTP_VERSION_TS_GROUPS = "/http/timeseries_groups/HTTP_VERSION"
TBL_HTTP_VERSION_TS = "http_version_timeseries"

def api_get_http_version_timeseries(start_dt_utc, end_dt_utc, agg_interval="1d", extra_params=None):
    """
    Llama a /http/timeseries_groups/HTTP_VERSION con dateStart/dateEnd.
    Devuelve TODO el payload JSON (incluyendo 'result', 'success', etc.).
    """
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }

    params = {
        "aggInterval": agg_interval,
        "dateStart": start_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd":   end_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "format":    "JSON"
    }
    if extra_params:
        params.update(extra_params)

    url = f"{API_BASE_RADAR}{EP_HTTP_VERSION_TS_GROUPS}"
    print(f"-> GET {url}")
    print(f"   Rango: {params['dateStart']}  a  {params['dateEnd']}  | aggInterval={params['aggInterval']}")

    if not CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN.strip() == "":
        raise ValueError("El token de Cloudflare API está vacío.")

    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if not resp.ok:
        print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
        resp.raise_for_status()

    data = resp.json()
    if not data.get("success", False):
        raise ValueError(f"Respuesta sin success=true. Errores: {data.get('errors')}")
    return data  # devolvemos el raíz con 'result'

def parse_meta_http(meta: dict):
    """
    Extrae metadatos de result['meta'].
    """
    meta = meta or {}

    agg_interval = meta.get("aggInterval")

    # dateRange en Radar puede venir como lista con objetos {startTime, endTime}
    date_range = meta.get("dateRange", {})
    if isinstance(date_range, list) and date_range:
        dr0 = date_range[0]
        start_time = dr0.get("startTime")
        end_time   = dr0.get("endTime")
    else:
        start_time = date_range.get("startTime")
        end_time   = date_range.get("endTime")

    window_start = _to_dt_utc(start_time)
    window_end   = _to_dt_utc(end_time)

    normalization = meta.get("normalization")

    # units es lista tipo [{"name":"*","value":"requests"}]
    unit = None
    units = meta.get("units", []) or []
    if isinstance(units, list) and units:
        unit = units[0].get("value") or units[0].get("name")

    conf_info = meta.get("confidenceInfo", {}) or {}
    confidence_level = conf_info.get("level")
    annotations = conf_info.get("annotations")

    last_updated = _to_dt_utc(meta.get("lastUpdated"))

    return {
        "agg_interval": agg_interval,
        "window_start": window_start,
        "window_end": window_end,
        "normalization": normalization,
        "unit": unit,
        "confidence_level": confidence_level,
        "annotations": annotations,
        "last_updated": last_updated,
    }

def transform_http_version_timeseries(payload: dict) -> pd.DataFrame:
    """
    Adapta el payload oficial:
    {
      "result": {
        "meta": {...},
        "serie_0": {
           "timestamps": [...],
           "HTTP/1.x": [...],
           "HTTP/2":   [...],
           "HTTP/3":   [...]
        }
      },
      "success": true
    }
    """
    if not isinstance(payload, dict):
        return pd.DataFrame()

    result_block = payload.get("result") or {}
    if not isinstance(result_block, dict):
        print("⚠️ Payload sin 'result' dict")
        return pd.DataFrame()

    # meta
    meta_info = parse_meta_http(result_block.get("meta"))

    # localizar 'serie_*' dentro de result_block
    serie_key = None
    for k in result_block.keys():
        if k.startswith("serie_"):
            serie_key = k
            break

    if serie_key is None:
        print("⚠️ result.* no trae serie_*")
        return pd.DataFrame()

    serie_block = result_block.get(serie_key, {})
    if not isinstance(serie_block, dict):
        print("⚠️ serie_* no es dict")
        return pd.DataFrame()

    # timestamps
    timestamps = serie_block.get("timestamps", [])
    if not isinstance(timestamps, list) or not timestamps:
        print("⚠️ No hay timestamps en la serie")
        return pd.DataFrame()

    # detectar llaves versión HTTP (todo menos 'timestamps')
    version_keys = [vk for vk in serie_block.keys() if vk != "timestamps"]

    now_utc = _now_utc()
    rows = []

    for idx, ts in enumerate(timestamps):
        ts_utc = _to_dt_utc(ts)

        # para cada versión disponible ("HTTP/2", "HTTP/3", etc.)
        for vk in version_keys:
            values_list = serie_block.get(vk, [])
            val_raw = values_list[idx] if idx < len(values_list) else None
            val = _coerce_float(val_raw)

            if ts_utc is None or vk is None:
                continue

            rows.append({
                "timestamp_utc":        ts_utc,
                "agg_interval":         meta_info["agg_interval"],
                "http_version":         vk,   # "HTTP/1.x", "HTTP/2", "HTTP/3"
                "value_share":          val,

                "window_start":         meta_info["window_start"],
                "window_end":           meta_info["window_end"],
                "normalization":        meta_info["normalization"],
                "unit":                 meta_info["unit"],
                "confidence_level":     meta_info["confidence_level"],
                "last_updated":         meta_info["last_updated"],
                "annotations":          json.dumps(meta_info["annotations"]) if meta_info["annotations"] is not None else None,

                "ingestion_timestamp":  now_utc
            })

    df = pd.DataFrame.from_records(rows)

    if not df.empty:
        # PK en la tabla es (timestamp_utc, agg_interval, http_version)
        df.drop_duplicates(
            subset=["timestamp_utc", "agg_interval", "http_version"],
            keep="last",
            inplace=True
        )
        df.sort_values(["timestamp_utc", "http_version"], inplace=True)
        df.reset_index(drop=True, inplace=True)

    print(f"✔️ HTTP_VERSION timeseries: {len(df)} filas (transformadas)")
    return df

def bulk_upsert(conn, table_name: str, df: pd.DataFrame, cols: list, conflict_cols: list) -> int:
    if df.empty:
        print(f"⚠️ No hay datos para cargar en {table_name}.")
        return 0

    # validación columnas
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise ValueError(f"{table_name}: faltan columnas en DataFrame: {missing}")

    df = df[cols]

    cur = conn.cursor()
    tuples = [tuple(x) for x in df.to_numpy()]
    placeholders = "(" + ",".join(["%s"] * len(cols)) + ")"
    values_sql = ",".join(cur.mogrify(placeholders, row).decode("utf-8") for row in tuples)

    conflict = ", ".join(conflict_cols)
    update_cols = [c for c in cols if c not in conflict_cols + ["ingestion_timestamp"]]
    update_set_parts = [f"{c} = EXCLUDED.{c}" for c in update_cols]
    update_set_parts.append("ingestion_timestamp = EXCLUDED.ingestion_timestamp")
    update_set = ", ".join(update_set_parts)

    sql = f"""
        INSERT INTO {table_name} ({",".join(cols)})
        VALUES {values_sql}
        ON CONFLICT ({conflict})
        DO UPDATE SET
            {update_set};
    """
    cur.execute(sql)
    conn.commit()
    cur.close()
    return len(df)

def run_http_version_timeseries(conn, start_dt, end_dt, agg_interval="1d"):
    print("\n--- HTTP VERSION TIMESERIES (HTTP/1.x vs HTTP/2 vs HTTP/3) ---")

    cols = [
        "timestamp_utc",
        "agg_interval",
        "http_version",
        "value_share",
        "window_start",
        "window_end",
        "normalization",
        "unit",
        "confidence_level",
        "last_updated",
        "annotations",
        "ingestion_timestamp"
    ]
    conflict = ["timestamp_utc", "agg_interval", "http_version"]

    payload = api_get_http_version_timeseries(start_dt, end_dt, agg_interval=agg_interval)
    df = transform_http_version_timeseries(payload)

    if df.empty:
        try:
            print("ℹ️ Payload (vista corta):", json.dumps(payload, default=str)[:900], "...")
        except Exception:
            pass

    n = bulk_upsert(conn, TBL_HTTP_VERSION_TS, df, cols, conflict)
    print(f"✅ Cargadas {n} filas en {TBL_HTTP_VERSION_TS}")

def run_http_version_all(days=30, agg_interval="1d"):
    end_date = _now_utc().replace(second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)
    print(f"=== HTTP VERSION Ingesta: últimos {days} días ===")

    conn = _pg_conn()
    try:
        run_http_version_timeseries(conn, start_date, end_date, agg_interval=agg_interval)
    finally:
        conn.close()
        print("--- Conexión a DB cerrada (http_version_timeseries) ---")

    print("=== HTTP VERSION Finalizado ===")


# ====================================================================
# 9) CODE 9: iqi_latency_summary (integrado)
# ====================================================================

TBL_IQI_LAT_SUMMARY = "iqi_latency_summary"
EP_IQI_LAT_SUMMARY = "/quality/iqi/summary"

def fetch_iqi_latency_summary(start_dt_utc, end_dt_utc):
    """
    Llama a /radar/quality/iqi/summary con metric=LATENCY y rango explícito.
    Devuelve el payload raíz (success, result, meta, summary_0, etc.).
    """
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {
        "metric": "LATENCY",
        "dateStart": start_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd":   end_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "format":    "JSON"
    }
    url = f"{API_BASE_RADAR}{EP_IQI_LAT_SUMMARY}"
    print(f"-> GET {url}")
    print(f"   Rango: {params['dateStart']}  a  {params['dateEnd']}")
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if not resp.ok:
        print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success", False):
        raise ValueError(f"Respuesta sin success=true: {data.get('errors')}")
    return data

def transform_iqi_summary(payload: dict) -> dict:
    """
    Extrae p25, p50, p75 y metadatos de fechas a una sola fila (dict).
    """
    if not isinstance(payload, dict):
        return {}
    result = payload.get("result", {}) or {}
    meta = result.get("meta", {}) or {}
    summary = result.get("summary_0", {}) or {}

    date_range = meta.get("dateRange", []) or []
    start_time = end_time = None
    if isinstance(date_range, list) and date_range:
        win = date_range[0] or {}
        start_time = win.get("startTime")
        end_time   = win.get("endTime")
    else:
        start_time = meta.get("startTime")
        end_time   = meta.get("endTime")

    ds = _to_dt_utc(start_time)
    de = _to_dt_utc(end_time)

    def _fget(k):
        try:
            v = summary.get(k)
            return float(v) if v is not None else None
        except Exception:
            return None

    row = {
        "date_start": ds,
        "date_end":   de,
        "p25_ms":     _fget("p25"),
        "p50_ms":     _fget("p50"),
        "p75_ms":     _fget("p75"),
        "ingestion_timestamp": _now_utc()
    }
    return row

def upsert_iqi_summary(conn, table_name: str, row: dict):
    """
    UPSERT por (date_start, date_end). Actualiza métricas y timestamp de ingesta.
    """
    if not row or not row.get("date_start") or not row.get("date_end"):
        print("⚠️ Fila IQI vacía o sin fechas; se omite carga.")
        return
    cols = list(row.keys())
    placeholders = ",".join(["%s"] * len(cols))
    updates = ", ".join([f"{c}=EXCLUDED.{c}" for c in cols if c not in ("date_start","date_end")])

    sql = f"""
        INSERT INTO {table_name} ({",".join(cols)})
        VALUES ({placeholders})
        ON CONFLICT (date_start, date_end)
        DO UPDATE SET {updates};
    """
    cur = conn.cursor()
    values = []
    for c in cols:
        v = row[c]
        if isinstance(v, pd.Timestamp):
            v = v.to_pydatetime()
        values.append(v)
    cur.execute(sql, values)
    conn.commit()
    cur.close()
    print(f"✅ IQI cargado: {row['date_start']} → {row['date_end']}")

def run_iqi_latency_summary(days=30):
    """
    Descarga IQI LATENCY summary para una ventana rolling de 'days' días y upsertea una fila.
    """
    end_date = _now_utc().replace(second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)
    print(f"=== IQI LATENCY Summary: últimos {days} días ===")
    payload = fetch_iqi_latency_summary(start_date, end_date)
    row = transform_iqi_summary(payload)
    conn = _pg_conn()
    try:
        upsert_iqi_summary(conn, TBL_IQI_LAT_SUMMARY, row)
    finally:
        conn.close()
        print("--- Conexión a DB cerrada (iqi_latency_summary) ---")
    print("=== IQI LATENCY Finalizado ===")


# ====================================================================
# ORQUESTADOR DIARIO (sin CLI)
# ====================================================================

def run_daily_default():
    """
    Ejecuta todo el pipeline con ventana rolling de 1 día (o rangos internos según cada módulo).
    - Mantiene rangos internos de http_ipv_all (30d/90d/7d) tal como fue probado.
    - http_version_timeseries: últimos 30 días.
    - iqi_latency_summary: últimos 30 días.
    """
    # 2) HTTP ip_version unificado (rangos internos ya probados)
    run_http_ipv_all()

    # 3) L3 summaries (último día)
    run_attacks_l3_summaries(date_range="1d")

    # 3B) Top países ORIGEN de ataques L3 (foto 30d, top 100)
    run_attacks_l3_top_origin(date_range="30d", limit=100)  # Nota: argumento correcto es date_range

    # 4) Netflows Top Locations (último día, product ALL, top 100)
    run_netflows_top_locations(date_range="1d", product="ALL", location_type="country", limit=100)

    # 5) HTTP summary browsers (último día)
    run_http_summary_browsers(days=1)

    # 7) HTTP Version Timeseries (últimos 30 días, agg_interval=1d)
    run_http_version_all(days=30, agg_interval="1d")

    # 9) IQI Latency Summary (últimos 30 días)
    run_iqi_latency_summary(days=30)


if __name__ == "__main__":
    # Ejecuta diariamente sin requerir parámetros
    run_daily_default()
