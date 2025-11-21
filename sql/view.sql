create view public.v_netflows_traffic_distributionn as
select
  continent,
  location_id as country_alpha2,
  location_name as country_name,
  window_end as ultima_fecha,
  sum(value) as total_traffic_volume
from
  v_netflows_top_loc_with_continent t
where
  location_type = 'country'::text
  and continent is not null
group by
  continent,
  location_id,
  location_name,
  window_end
order by
  continent,
  (sum(value)) desc;

create view public.v_top_malicious_origin_countries as
select
  location_id as country_alpha2,
  location_name as country_name,
  continent,
  value as total_attack_volume,
  window_start,
  window_end
from
  v_attacks_l3_top_origin_with_continent t
where
  location_type = 'country'::text
  and continent is not null
  and window_end = (
    (
      select
        max(v_attacks_l3_top_origin_with_continent.window_end) as max
      from
        v_attacks_l3_top_origin_with_continent
    )
  )
order by
  value desc;

create view public.v_netflows_top10_last30d as
with
  latest_window as (
    select
      netflows_top_locations.window_start,
      netflows_top_locations.window_end
    from
      netflows_top_locations
    where
      netflows_top_locations.product = 'ALL'::text
      and netflows_top_locations.location_type = 'country'::text
    order by
      netflows_top_locations.window_end desc
    limit
      1
  ),
  ranked as (
    select
      n.window_start,
      n.window_end,
      n.location_type,
      n.location_id,
      n.location_name,
      n.value,
      n.rank,
      n.unit,
      n.product,
      n.limit_requested,
      n.last_updated,
      n.source_json,
      n.ingestion_timestamp,
      case
        when n.value is null then null::numeric
        when n.value <= 1::numeric then n.value * 100::numeric
        else n.value
      end as percent_0_100,
      case
        when n.value is null then null::numeric
        when n.value <= 1::numeric then n.value
        else n.value / 100.0
      end as ratio_0_1
    from
      netflows_top_locations n
      join latest_window w on n.window_start = w.window_start
      and n.window_end = w.window_end
    where
      n.product = 'ALL'::text
      and n.location_type = 'country'::text
  )
select
  window_start,
  window_end,
  location_type,
  location_id,
  location_name,
  value,
  rank,
  unit,
  product,
  limit_requested,
  last_updated,
  source_json,
  ingestion_timestamp,
  percent_0_100,
  ratio_0_1
from
  ranked
order by
  value desc,
  location_name
limit
  10;

create view public.v_camerica_speed_trend_12m_monthly_filled as
with
  base as (
    select
      date_trunc(
        'month'::text,
        v_camerica_speed_trend_12m_monthly_full.month_utc
      )::timestamp without time zone as month_utc,
      v_camerica_speed_trend_12m_monthly_full.country_alpha2,
      v_camerica_speed_trend_12m_monthly_full.country_name,
      v_camerica_speed_trend_12m_monthly_full.continent,
      v_camerica_speed_trend_12m_monthly_full.avg_rank_power,
      v_camerica_speed_trend_12m_monthly_full.weighted_rank_power,
      v_camerica_speed_trend_12m_monthly_full.avg_download_mbps,
      v_camerica_speed_trend_12m_monthly_full.avg_upload_mbps,
      v_camerica_speed_trend_12m_monthly_full.avg_latency_idle_ms,
      v_camerica_speed_trend_12m_monthly_full.avg_latency_loaded_ms,
      v_camerica_speed_trend_12m_monthly_full.total_tests,
      v_camerica_speed_trend_12m_monthly_full.n_samples
    from
      v_camerica_speed_trend_12m_monthly_full
  ),
  bf as (
    select
      backfill_speed_rank_power.month_utc::timestamp without time zone as month_utc,
      backfill_speed_rank_power.country_alpha2,
      backfill_speed_rank_power.country_name,
      'Central America'::text as continent,
      backfill_speed_rank_power.avg_rank_power,
      backfill_speed_rank_power.avg_rank_power as weighted_rank_power,
      null::numeric as avg_download_mbps,
      null::numeric as avg_upload_mbps,
      null::numeric as avg_latency_idle_ms,
      null::numeric as avg_latency_loaded_ms,
      0 as total_tests,
      1 as n_samples
    from
      backfill_speed_rank_power
  )
select
  base.month_utc,
  base.country_alpha2,
  base.country_name,
  base.continent,
  base.avg_rank_power,
  base.weighted_rank_power,
  base.avg_download_mbps,
  base.avg_upload_mbps,
  base.avg_latency_idle_ms,
  base.avg_latency_loaded_ms,
  base.total_tests,
  base.n_samples
from
  base
union all
select
  bfx.month_utc,
  bfx.country_alpha2,
  bfx.country_name,
  bfx.continent,
  bfx.avg_rank_power,
  bfx.weighted_rank_power,
  bfx.avg_download_mbps,
  bfx.avg_upload_mbps,
  bfx.avg_latency_idle_ms,
  bfx.avg_latency_loaded_ms,
  bfx.total_tests,
  bfx.n_samples
from
  bf bfx
  left join base b on b.country_alpha2 = bfx.country_alpha2
  and b.month_utc = bfx.month_utc
where
  b.country_alpha2 is null;

create view public.v_spain_netflows_20_28oct as
select
  (snapshot_day - '1 day'::interval)::date as snapshot_day,
  country_alpha2,
  country_name,
  product,
  avg_value,
  best_rank,
  window_start_min_utc,
  window_end_max_utc
from
  v_netflows_daily_country
where
  snapshot_day >= '2025-10-24'::date
  and snapshot_day <= '2025-10-31'::date
  and country_alpha2 = 'ES'::text
  and product = 'ALL'::text
order by
  ((snapshot_day - '1 day'::interval)::date);

create view public.v_camerica_netflows_20_28oct as
select
  (v.snapshot_day - '1 day'::interval)::date as snapshot_day,
  v.country_alpha2,
  v.country_name,
  v.product,
  v.avg_value,
  v.best_rank,
  v.window_start_min_utc,
  v.window_end_max_utc
from
  v_netflows_daily_country v
  join dim_country_continent d on v.country_alpha2 = d.alpha2
where
  v.snapshot_day >= '2025-10-24'::date
  and v.snapshot_day <= '2025-10-31'::date
  and d.continent = 'Central America'::text
  and v.product = 'ALL'::text
order by
  ((v.snapshot_day - '1 day'::interval)::date),
  v.country_name;
create view public.v_http_version_last_30d as
select
  date_trunc('day'::text, timestamp_utc) as day_utc,
  http_version,
  value_share,
  unit,
  normalization,
  confidence_level,
  last_updated,
  ingestion_timestamp
from
  http_version_timeseries
where
  (
    agg_interval = any (array['ONE_DAY'::text, '1d'::text])
  )
  and timestamp_utc >= (
    date_trunc('day'::text, (now() AT TIME ZONE 'UTC'::text)) - '30 days'::interval
  )
order by
  (date_trunc('day'::text, timestamp_utc)),
  http_version;

create view public.v_http_version_growth_30d as
with
  last_month as (
    select
      date_trunc(
        'day'::text,
        http_version_timeseries.timestamp_utc
      ) as day_utc,
      http_version_timeseries.http_version,
      http_version_timeseries.value_share
    from
      http_version_timeseries
    where
      (
        http_version_timeseries.agg_interval = any (array['ONE_DAY'::text, '1d'::text])
      )
      and http_version_timeseries.timestamp_utc >= (
        date_trunc('day'::text, (now() AT TIME ZONE 'UTC'::text)) - '30 days'::interval
      )
  )
select
  day_utc,
  http_version,
  first_value(value_share) over (
    partition by
      http_version
    order by
      day_utc
  ) as start_share,
  last_value(value_share) over (
    partition by
      http_version
    order by
      day_utc rows between UNBOUNDED PRECEDING
      and UNBOUNDED FOLLOWING
  ) as end_share,
  last_value(value_share) over (
    partition by
      http_version
    order by
      day_utc rows between UNBOUNDED PRECEDING
      and UNBOUNDED FOLLOWING
  ) - first_value(value_share) over (
    partition by
      http_version
    order by
      day_utc
  ) as abs_change_pp
from
  last_month
order by
  day_utc,
  http_version;

create view public.v_iqi_latency_latest_q1_q3 as
with
  latest as (
    select
      iqi_latency_summary.date_start,
      iqi_latency_summary.date_end,
      iqi_latency_summary.p25_ms,
      iqi_latency_summary.p50_ms,
      iqi_latency_summary.p75_ms,
      iqi_latency_summary.ingestion_timestamp
    from
      iqi_latency_summary
    where
      iqi_latency_summary.date_end = (
        (
          select
            max(iqi_latency_summary_1.date_end) as max
          from
            iqi_latency_summary iqi_latency_summary_1
        )
      )
  )
select
  date_end,
  p25_ms as q1_max,
  p50_ms as q2_max,
  p75_ms as q3_max,
  p25_ms - 0::double precision as q1_range,
  p50_ms - p25_ms as q2_range,
  p75_ms - p50_ms as q3_range,
  ingestion_timestamp
from
  latest;