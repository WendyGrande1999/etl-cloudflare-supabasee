#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ETL diario (sin parámetros) para Cloudflare Radar -> Supabase/PostgreSQL.

Incluye los siguientes pipelines ya probados por el usuario (codes 1..6), unificados:
  1) attacks_layer3_timeseries_protocol
  2) radar_http_ip_version (timeseries/summary/top) [rangos internos 30d/90d/7d]
  3) attacks_l3_summary_protocol + attacks_l3_summary_ip_version
  4) netflows_top_locations
  5) http_summary_browsers
  6) quality_speed_{summary,histogram}  [con limit=50 eliminado para top/locations]

+ 7) attacks_l3_top_origin_locations (NUEVO)  ← integración solicitada

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
# 1) CODE 1: attacks_layer3_timeseries_protocol (sin cambios relevantes)
# ====================================================================

PROTOCOLS = ["TCP", "UDP", "ICMP", "GRE"]
TABLE_ATTACKS_TS = "attacks_layer3_timeseries_protocol"
ENDPOINT_ATTACKS_TS = "/attacks/layer3/timeseries_groups/protocol"  # Radar v4

def fetch_cloudflare_timeseries(start_dt_utc, end_dt_utc, agg_interval=None):
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {
        "dateStart": start_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd":   end_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if agg_interval:
        params["aggInterval"] = agg_interval

    url = f"{API_BASE_RADAR}{ENDPOINT_ATTACKS_TS}"
    print(f"-> Consultando {url}")
    print(f"   Rango: {params['dateStart']}  a  {params['dateEnd']}")

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        if not resp.ok:
            print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
            resp.raise_for_status()
        data = resp.json()
        if "result" not in data:
            raise ValueError("Respuesta sin 'result'")
        return data["result"]
    except Exception as e:
        print(f"❌ Error al conectar con Cloudflare Radar: {e}")
        return None

def transform_timeseries_result(result_json: dict) -> pd.DataFrame:
    if result_json is None:
        return pd.DataFrame()

    series_block = None
    if isinstance(result_json, dict):
        if "series" in result_json and isinstance(result_json["series"], dict):
            series_block = result_json["series"]
        elif "serie_0" in result_json and isinstance(result_json["serie_0"], dict):
            series_block = result_json["serie_0"]
        else:
            if "series" in result_json and isinstance(result_json["series"], list) and result_json["series"]:
                series_block = result_json["series"][0]

    if series_block is None:
        print("⚠️ No se encontró 'series' ni 'serie_0' en la respuesta.")
        return pd.DataFrame()

    meta = result_json.get("meta", {})
    unit = None
    confidence_level = None

    try:
        units = meta.get("units", [])
        if units and isinstance(units, list) and isinstance(units[0], dict):
            unit = units[0].get("value")
    except Exception:
        pass

    try:
        confidence_level = meta.get("confidenceInfo", {}).get("level")
    except Exception:
        pass

    timestamps = series_block.get("timestamps", []) or series_block.get("timeStamps", [])
    if not timestamps:
        print("⚠️ La serie no contiene 'timestamps'.")
        return pd.DataFrame()

    records = []
    now_utc = _now_utc()

    for idx, ts in enumerate(timestamps):
        ts_dt = pd.to_datetime(ts, utc=True, errors="coerce")
        if pd.isna(ts_dt):
            continue

        for proto in PROTOCOLS:
            values = series_block.get(proto, [])
            val = 0.0
            if isinstance(values, list) and idx < len(values) and values[idx] is not None:
                try:
                    val = float(values[idx])
                except Exception:
                    val = 0.0

            records.append({
                "data_end_time": ts_dt,
                "attack_protocol": proto,
                "total_requests": val,
                "unit": unit,
                "confidence_level": confidence_level,
                "ingestion_timestamp": now_utc
            })

    df = pd.DataFrame.from_records(records)
    if not df.empty:
        df.drop_duplicates(subset=["data_end_time", "attack_protocol"], keep="last", inplace=True)
        df.sort_values(["data_end_time", "attack_protocol"], inplace=True)
        df.reset_index(drop=True, inplace=True)

    print(f"✔️ Transformación OK: {len(df)} filas")
    return df

def load_attacks_ts(df: pd.DataFrame):
    if df.empty:
        print("⚠️ No hay datos para cargar.")
        return

    conn = None
    try:
        conn = _pg_conn()
        cur = conn.cursor()

        tuples = [tuple(x) for x in df.to_numpy()]
        cols = ",".join(df.columns)
        placeholders = "(" + ",".join(["%s"] * len(df.columns)) + ")"
        values_sql = ",".join(cur.mogrify(placeholders, row).decode("utf-8") for row in tuples)

        insert_sql = f"""
            INSERT INTO {TABLE_ATTACKS_TS} ({cols})
            VALUES {values_sql}
            ON CONFLICT (data_end_time, attack_protocol)
            DO NOTHING;
        """
        cur.execute(insert_sql)
        conn.commit()
        print(f"✅ Carga OK: {cur.rowcount} filas nuevas en '{TABLE_ATTACKS_TS}'.")
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

def run_attacks_ts_protocol(days=1):
    end_date = _now_utc().replace(second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)
    print(f"--- Iniciando Ingesta attacks_ts_protocol últimos {days} día(s) ---")
    result = fetch_cloudflare_timeseries(start_date, end_date, agg_interval=None)
    if result is None:
        print("--- Proceso finalizado (sin datos) ---")
        return
    df = transform_timeseries_result(result)
    load_attacks_ts(df)
    print("--- Proceso Finalizado (attacks_ts_protocol) ---")


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
    units = meta.get("units", [])
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
# 6) CODE 6: quality/speed (summary + histogram)  [top_locations removido]
# ====================================================================

TBL_QS_SUMMARY   = "quality_speed_summary"
TBL_QS_HISTOGRAM = "quality_speed_histogram"

EP_QS_SUMMARY   = "/quality/speed/summary"
EP_QS_HISTOGRAM = "/quality/speed/histogram"

def qs_api_get(path, start_dt_utc, end_dt_utc, extra_params=None):
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Accept": "application/json",
    }
    params = {
        "dateStart": start_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd":   end_dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if extra_params:
        params.update(extra_params)
    url = f"{API_BASE_RADAR}{path}"
    print(f"-> GET {url}")
    print(f"   Rango: {params['dateStart']}  a  {params['dateEnd']}")
    if not CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN.strip() == "":
        raise ValueError("El token de Cloudflare API está vacío.")
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    if not resp.ok:
        print(f"❌ HTTP {resp.status_code}: {resp.text[:400]}")
        resp.raise_for_status()
    data = resp.json()
    if not data.get("success", False):
        raise ValueError(f"Respuesta sin success=true en {path}. Errores: {data.get('errors')}")
    return data.get("result")

def qs_parse_meta(meta: dict):
    meta = meta or {}
    date_range = meta.get("dateRange", []) or []
    win = date_range[0] if date_range else {}
    window_start = _to_dt_utc(win.get("startTime"))
    window_end   = _to_dt_utc(win.get("endTime"))
    normalization = meta.get("normalization")
    unit = None
    units = meta.get("units", []) or []
    if isinstance(units, list) and units:
        unit = units[0].get("value") or units[0].get("name")
    conf_info = meta.get("confidenceInfo", {}) or {}
    confidence_level = conf_info.get("level")
    annotations = conf_info.get("annotations")
    last_updated = _to_dt_utc(meta.get("lastUpdated"))
    location_type = meta.get("locationType")
    bucket_size = meta.get("bucketSize")
    return {
        "window_start": window_start,
        "window_end": window_end,
        "normalization": normalization,
        "unit": unit,
        "confidence_level": confidence_level,
        "annotations": annotations,
        "last_updated": last_updated,
        "location_type": location_type,
        "bucket_size": bucket_size,
    }

def qs_explode_metric_pair(name, value):
    out = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.append((f"{name}.{k}", _coerce_float(v)))
    else:
        out.append((str(name), _coerce_float(value)))
    return out

def qs_iter_summaries(result: dict):
    pairs = []
    if not isinstance(result, dict):
        return pairs
    candidate_objs = []
    for k, v in result.items():
        if "summary" in str(k):
            candidate_objs.append(v)
    if not candidate_objs:
        v = result.get("summary") or result.get("summary_0")
        if v is not None:
            candidate_objs.append(v)
    for obj in candidate_objs:
        if isinstance(obj, dict):
            for k, v in obj.items():
                pairs.extend(qs_explode_metric_pair(k, v))
        elif isinstance(obj, list):
            for elem in obj:
                if isinstance(elem, dict):
                    name = elem.get("name") or elem.get("metric") or elem.get("key")
                    if name is None:
                        for k, v in elem.items():
                            if k not in ("name","metric","key","value"):
                                pairs.extend(qs_explode_metric_pair(k, v))
                        continue
                    value = elem.get("value")
                    pairs.extend(qs_explode_metric_pair(name, value))
                elif isinstance(elem, (list, tuple)) and len(elem) >= 2:
                    name, value = elem[0], elem[1]
                    pairs.extend(qs_explode_metric_pair(name, value))
                else:
                    continue
    return [(n, v) for (n, v) in pairs if n is not None]

def transform_qs_summary(result: dict) -> pd.DataFrame:
    if not isinstance(result, dict):
        return pd.DataFrame()
    meta = qs_parse_meta(result.get("meta"))
    if meta["window_start"] is None or meta["window_end"] is None:
        print("⚠️ summary: ventana inválida")
        return pd.DataFrame()
    pairs = qs_iter_summaries(result)
    if not pairs:
        print("⚠️ summary: no se detectaron métricas en el payload")
        try:
            print("ℹ️ Claves en result:", list(result.keys()))
            print("ℹ️ meta:", json.dumps(result.get("meta", {}), default=str)[:400], "...")
        except Exception:
            pass
        return pd.DataFrame()
    now_utc = _now_utc()
    rows = []
    for metric_name, val in pairs:
        rows.append({
            "window_start":        meta["window_start"],
            "window_end":          meta["window_end"],
            "metric_name":         str(metric_name),
            "value":               _coerce_float(val),
            "normalization":       meta["normalization"],
            "unit":                meta["unit"],
            "confidence_level":    meta["confidence_level"],
            "last_updated":        meta["last_updated"],
            "annotations":         meta["annotations"],
            "ingestion_timestamp": now_utc
        })
    df = pd.DataFrame.from_records(rows)
    if not df.empty:
        df.drop_duplicates(subset=["window_start","window_end","metric_name"], keep="last", inplace=True)
        df.sort_values(["window_start","window_end","metric_name"], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ summary: {len(df)} filas")
    return df

def qs_iter_histogram_by_index(result: dict):
    if not isinstance(result, dict):
        return []
    h = result.get("histogram_0") or result.get("histogram") or {}
    if not isinstance(h, dict):
        return []
    out = []
    bucket_min = None
    try:
        bm = h.get("bucketMin")
        if isinstance(bm, list) and bm:
            bucket_min = float(bm[0])
        elif isinstance(bm, (int, float, str)):
            bucket_min = float(bm)
    except Exception:
        bucket_min = None
    for metric_name, series in h.items():
        if metric_name == "bucketMin":
            continue
        if isinstance(series, list):
            for idx, raw in enumerate(series):
                val = _coerce_float(raw)
                out.append((str(metric_name), idx, val, bucket_min))
    return out

def transform_qs_histogram(result: dict) -> pd.DataFrame:
    if not isinstance(result, dict):
        return pd.DataFrame()
    meta = qs_parse_meta(result.get("meta"))
    if meta["window_start"] is None or meta["window_end"] is None:
        print("⚠️ histogram: ventana inválida")
        return pd.DataFrame()
    bucket_size = None
    try:
        bs = (result.get("meta") or {}).get("bucketSize")
        if bs is not None:
            bucket_size = float(bs)
    except Exception:
        bucket_size = None
    entries = qs_iter_histogram_by_index(result)
    if not entries:
        print("⚠️ histogram: no se detectaron bins en el payload (por índice)")
        try:
            print("ℹ️ Claves en result:", list(result.keys()))
            print("ℹ️ meta:", json.dumps(result.get("meta", {}), default=str)[:400], "...")
        except Exception:
            pass
        return pd.DataFrame()
    now_utc = _now_utc()
    rows = []
    for metric_name, idx, val, bucket_min in entries:
        bin_start = None
        bin_end = None
        if bucket_min is not None and bucket_size is not None and bucket_size > 0:
            bin_start = bucket_min + idx * bucket_size
            bin_end   = bin_start + bucket_size
        share, count = None, None
        if (meta["normalization"] or "").upper() in ("PERCENTAGE", "RATIO", "SHARE"):
            share = val
        else:
            count = val
        rows.append({
            "window_start":        meta["window_start"],
            "window_end":          meta["window_end"],
            "metric_name":         metric_name,
            "bin_index":           idx,
            "bin_start":           bin_start,
            "bin_end":             bin_end,
            "share":               share,
            "count":               count,
            "normalization":       meta["normalization"],
            "unit":                meta["unit"],
            "confidence_level":    meta["confidence_level"],
            "last_updated":        meta["last_updated"],
            "annotations":         meta["annotations"],
            "ingestion_timestamp": now_utc
        })
    df = pd.DataFrame.from_records(rows)
    if not df.empty:
        df.drop_duplicates(
            subset=["window_start","window_end","metric_name","bin_index","normalization","unit"],
            keep="last",
            inplace=True
        )
        df.sort_values(["window_start","window_end","metric_name","bin_index"], inplace=True)
        df.reset_index(drop=True, inplace=True)
    print(f"✔️ histogram: {len(df)} filas")
    return df

def qs_bulk_insert(conn, table_name: str, df: pd.DataFrame, expected_cols: list, conflict_cols: list):
    if df.empty:
        print(f"⚠️ No hay datos para cargar en {table_name}.")
        return 0
    missing = [c for c in expected_cols if c not in df.columns]
    if missing:
        raise ValueError(f"{table_name}: Faltan columnas en DataFrame: {missing}")
    df = df[expected_cols]
    cur = conn.cursor()
    tuples = [tuple(x) for x in df.to_numpy()]
    placeholders = "(" + ",".join(["%s"] * len(expected_cols)) + ")"
    values_sql = ",".join(cur.mogrify(placeholders, row).decode("utf-8") for row in tuples)
    conflict = ", ".join(conflict_cols)
    update_cols = [c for c in expected_cols if c not in conflict_cols + ["ingestion_timestamp"]]
    update_set_parts = [f"{col} = EXCLUDED.{col}" for col in update_cols]
    update_set_parts.append("ingestion_timestamp = EXCLUDED.ingestion_timestamp")
    update_set = ", ".join(update_set_parts)
    insert_sql = f"""
        INSERT INTO {table_name} ({",".join(expected_cols)})
        VALUES {values_sql}
        ON CONFLICT ({conflict})
        DO UPDATE SET
            {update_set};
    """
    cur.execute(insert_sql)
    conn.commit()
    cur.close()
    return len(df)

def run_qs_summary(conn, start_dt, end_dt):
    print("\n--- QUALITY/SPEED SUMMARY ---")
    cols = [
        "window_start","window_end","metric_name","value",
        "normalization","unit","confidence_level","last_updated",
        "annotations","ingestion_timestamp"
    ]
    conflict = ["window_start","window_end","metric_name"]
    result = qs_api_get(EP_QS_SUMMARY, start_dt, end_dt)
    df = transform_qs_summary(result)
    if df.empty:
        try:
            print("ℹ️ Payload (vista corta):", json.dumps(result, default=str)[:800], "...")
        except Exception:
            pass
    n = qs_bulk_insert(conn, TBL_QS_SUMMARY, df, cols, conflict)
    print(f"✅ SUMMARY: filas procesadas {n}.")

def run_qs_histogram(conn, start_dt, end_dt):
    print("\n--- QUALITY/SPEED HISTOGRAM ---")
    cols = [
        "window_start","window_end","metric_name","bin_index","bin_start","bin_end",
        "share","count","normalization","unit","confidence_level","last_updated",
        "annotations","ingestion_timestamp"
    ]
    conflict = ["window_start","window_end","metric_name","bin_index","normalization","unit"]
    result = qs_api_get(EP_QS_HISTOGRAM, start_dt, end_dt)
    df = transform_qs_histogram(result)
    n = qs_bulk_insert(conn, TBL_QS_HISTOGRAM, df, cols, conflict)
    print(f"✅ HISTOGRAM: filas procesadas {n}.")

def run_quality_speed_all(days=1, which="all"):
    end_date = _now_utc().replace(second=0, microsecond=0)
    start_date = end_date - timedelta(days=days)
    print(f"=== QUALITY/SPEED Ingesta: últimos {days} días ===")
    conn = _pg_conn()
    try:
        if which in ("all","summary"):
            run_qs_summary(conn, start_date, end_date)
        if which in ("all","histogram"):
            run_qs_histogram(conn, start_date, end_date)
        # Nota: top_locations eliminado
    finally:
        conn.close()
        print("--- Conexión a DB cerrada (quality/speed) ---")
    print("=== QUALITY/SPEED Finalizado ===")


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
# ORQUESTADOR DIARIO (sin CLI)
# ====================================================================

def run_daily_default():
    """
    Ejecuta todo el pipeline con ventana rolling de 1 día.
    - Mantiene rangos internos de http_ipv_all (30d/90d/7d) tal como fue probado.
    """
    # 1) Attacks L3 timeseries (último día)
    run_attacks_ts_protocol(days=1)

    # 2) HTTP ip_version unificado (rangos internos ya probados)
    run_http_ipv_all()

    # 3) L3 summaries (último día)
    run_attacks_l3_summaries(date_range="1d")

    # 3B) NUEVO: Top países ORIGEN de ataques L3 (foto 30d, top 100)
    run_attacks_l3_top_origin(date_range="30d", limit=100)

    # 4) Netflows Top Locations (último día, product ALL, top 100)
    run_netflows_top_locations(date_range="1d", product="ALL", location_type="country", limit=100)

    # 5) HTTP summary browsers (último día)
    run_http_summary_browsers(days=1)

    # 6) Quality/Speed (summary + histogram) para último día
    run_quality_speed_all(days=1, which="all")


if __name__ == "__main__":
    # Ejecuta diariamente sin requerir parámetros
    run_daily_default()
