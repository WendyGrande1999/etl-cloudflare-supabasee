-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.attacks_l3_summary_ip_version (
  id bigint NOT NULL DEFAULT nextval('attacks_l3_summary_ip_version_id_seq'::regclass),
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  ip_version text NOT NULL,
  value numeric NOT NULL,
  unit text,
  confidence_level integer,
  last_updated timestamp with time zone,
  source_json jsonb NOT NULL,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT attacks_l3_summary_ip_version_pkey PRIMARY KEY (id)
);
CREATE TABLE public.attacks_l3_summary_protocol (
  id bigint NOT NULL DEFAULT nextval('attacks_l3_summary_protocol_id_seq'::regclass),
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  attack_protocol text NOT NULL,
  value numeric NOT NULL,
  unit text,
  confidence_level integer,
  last_updated timestamp with time zone,
  source_json jsonb NOT NULL,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT attacks_l3_summary_protocol_pkey PRIMARY KEY (id)
);
CREATE TABLE public.attacks_l3_top_origin_locations (
  id bigint NOT NULL DEFAULT nextval('attacks_l3_top_origin_locations_id_seq'::regclass),
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  location_type text NOT NULL DEFAULT 'country'::text,
  location_id text NOT NULL,
  location_name text,
  value numeric NOT NULL,
  rank integer,
  unit text,
  limit_requested integer,
  confidence_level integer,
  last_updated timestamp with time zone,
  source_json jsonb NOT NULL,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT attacks_l3_top_origin_locations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.backfill_speed_rank_power (
  month_utc date NOT NULL,
  country_alpha2 text NOT NULL,
  country_name text NOT NULL,
  avg_rank_power numeric NOT NULL,
  CONSTRAINT backfill_speed_rank_power_pkey PRIMARY KEY (month_utc, country_alpha2)
);
CREATE TABLE public.dim_country_continent (
  alpha2 text NOT NULL,
  continent text NOT NULL,
  CONSTRAINT dim_country_continent_pkey PRIMARY KEY (alpha2)
);
CREATE TABLE public.http_summary_browsers (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  browser_name text NOT NULL,
  rank integer,
  value numeric,
  normalization text,
  unit text,
  confidence_level integer,
  last_updated timestamp with time zone,
  annotations jsonb,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT http_summary_browsers_pkey PRIMARY KEY (id)
);
CREATE TABLE public.http_version_timeseries (
  timestamp_utc timestamp with time zone NOT NULL,
  agg_interval text NOT NULL,
  http_version text NOT NULL,
  value_share double precision,
  window_start timestamp with time zone,
  window_end timestamp with time zone,
  normalization text,
  unit text,
  confidence_level text,
  last_updated timestamp with time zone,
  annotations jsonb,
  ingestion_timestamp timestamp with time zone NOT NULL,
  CONSTRAINT http_version_timeseries_pkey PRIMARY KEY (timestamp_utc, agg_interval, http_version)
);
CREATE TABLE public.iqi_latency_summary (
  date_start timestamp with time zone NOT NULL,
  date_end timestamp with time zone NOT NULL,
  p25_ms double precision,
  p50_ms double precision,
  p75_ms double precision,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT iqi_latency_summary_pkey PRIMARY KEY (date_start, date_end)
);
CREATE TABLE public.netflows_top_locations (
  id bigint NOT NULL DEFAULT nextval('netflows_top_locations_id_seq'::regclass),
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  location_type text NOT NULL,
  location_id text NOT NULL,
  location_name text,
  value numeric NOT NULL,
  rank integer,
  unit text,
  product text NOT NULL DEFAULT 'ALL'::text,
  limit_requested integer,
  last_updated timestamp with time zone,
  source_json jsonb NOT NULL,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT netflows_top_locations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.quality_speed_snapshot_locationss (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  window_start timestamp with time zone NOT NULL,
  window_end timestamp with time zone NOT NULL,
  location_type text NOT NULL DEFAULT 'country'::text,
  location_id text NOT NULL,
  location_name text,
  rank integer NOT NULL,
  rank_power double precision,
  bandwidth_download double precision,
  bandwidth_upload double precision,
  latency_idle double precision,
  latency_loaded double precision,
  jitter_idle double precision,
  jitter_loaded double precision,
  num_tests bigint,
  normalization text,
  unit text,
  confidence_level integer,
  last_updated timestamp with time zone,
  annotations jsonb,
  ingestion_timestamp timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT quality_speed_snapshot_locationss_pkey PRIMARY KEY (id)
);
CREATE TABLE public.radar_http_ip_version (
  id bigint NOT NULL DEFAULT nextval('radar_http_ip_version_id_seq'::regclass),
  grain text NOT NULL CHECK (grain = ANY (ARRAY['timeseries'::text, 'summary'::text, 'top'::text])),
  location_type text NOT NULL DEFAULT 'country'::text,
  location_id text NOT NULL,
  ip_version text NOT NULL CHECK (ip_version = ANY (ARRAY['ipv4'::text, 'ipv6'::text])),
  share double precision NOT NULL,
  metric_ts timestamp with time zone,
  date_start timestamp with time zone,
  date_end timestamp with time zone,
  agg_interval text NOT NULL DEFAULT ''::text,
  rank integer NOT NULL DEFAULT 0,
  top_scope text NOT NULL DEFAULT ''::text,
  source_endpoint text NOT NULL,
  ingestion_ts timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT radar_http_ip_version_pkey PRIMARY KEY (id)
);




