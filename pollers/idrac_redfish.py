"""Dell iDRAC Redfish → Graylog (GELF HTTP) poller.

Targets iDRAC 8 (Redfish 1.4 — confirmed on the homelab box at
idrac.darknetian.com / 10.10.0.6, service tag DTMZ942). Should also work on
iDRAC 9 with the same endpoints — Dell kept `System.Embedded.1` and
`iDRAC.Embedded.1` as canonical IDs across versions.

Two modes, driven by separate systemd timers:

    python3 idrac_redfish.py health   # snapshot — system/thermal/power/drives
    python3 idrac_redfish.py logs     # tail Lclog + Sel, state-tracked, deduped by Id

Env vars:
    IDRAC_HOST          e.g. idrac.darknetian.com (or an IP)
    IDRAC_USER, IDRAC_PASS
    GELF_URL            default http://127.0.0.1:12202/gelf
    IDRAC_STATE_PATH    default /var/lib/idrac-poller/state.json
    IDRAC_INSECURE      "1" to skip TLS verify (default — iDRAC self-signed)

GELF messages:
    host                  = IDRAC_HOST (the existing iDRAC stream's source rule routes them)
    _idrac_event_type     categorical (system|thermal|fan|power|psu|drive|array_controller|lclog|sel)
    _idrac_*              event-specific structured fields

Differences vs the iLO poller:
  - Endpoints use Dell's `System.Embedded.1` / `iDRAC.Embedded.1` ids
    (vs iLO's `1`).
  - Storage is the proper Redfish Storage collection, not HPE's
    `SmartStorage` OEM extension.
  - Two log services instead of three: Lclog (Lifecycle Controller log)
    + Sel (System Event Log). Dell populates `Created` properly so we
    can backfill recent history on first run instead of skipping it
    the way the iLO poller has to.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import traceback
from pathlib import Path
from typing import Any
from urllib import error, request


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        print(f"ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


IDRAC_HOST = _env("IDRAC_HOST")
IDRAC_USER = _env("IDRAC_USER")
IDRAC_PASS = _env("IDRAC_PASS")
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("IDRAC_STATE_PATH", "/var/lib/idrac-poller/state.json"))
IDRAC_INSECURE = os.environ.get("IDRAC_INSECURE", "1") == "1"

SEVERITY_TO_GELF = {"OK": 6, "Warning": 4, "Critical": 2, "Fatal": 2}
BASE = f"https://{IDRAC_HOST}"

SYSTEM_ID = "System.Embedded.1"
MANAGER_ID = "iDRAC.Embedded.1"
CHASSIS_ID = "System.Embedded.1"   # Dell reuses the System id for the embedded chassis


# ── HTTP / session ──────────────────────────────────────────────────────────

class IdracSession:
    def __init__(self) -> None:
        self.token: str | None = None
        self.session_uri: str | None = None

    def _ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if IDRAC_INSECURE:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def open(self) -> None:
        body = json.dumps({"UserName": IDRAC_USER, "Password": IDRAC_PASS}).encode()
        req = request.Request(
            BASE + "/redfish/v1/SessionService/Sessions",
            data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with request.urlopen(req, context=self._ctx(), timeout=15) as r:
            self.token = r.headers.get("X-Auth-Token")
            self.session_uri = r.headers.get("Location")
        if not self.token:
            raise RuntimeError("iDRAC session opened but no X-Auth-Token returned")
        # Dell sometimes returns Location as a relative path; normalize to absolute.
        if self.session_uri and self.session_uri.startswith("/"):
            self.session_uri = BASE + self.session_uri

    def get(self, path: str) -> Any:
        assert self.token, "session not opened"
        url = path if path.startswith("http") else BASE + path
        req = request.Request(
            url,
            headers={"X-Auth-Token": self.token, "Accept": "application/json"},
        )
        with request.urlopen(req, context=self._ctx(), timeout=15) as r:
            return json.loads(r.read())

    def close(self) -> None:
        if not (self.token and self.session_uri):
            return
        req = request.Request(
            self.session_uri,
            method="DELETE",
            headers={"X-Auth-Token": self.token},
        )
        try:
            with request.urlopen(req, context=self._ctx(), timeout=10) as r:
                r.read()
        except error.URLError:
            pass
        self.token = None
        self.session_uri = None


def gelf(short_message: str, level: int = 6, **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": IDRAC_HOST,
        "short_message": short_message[:1024],
        "level": level,
        "timestamp": time.time(),
    }
    for k, v in fields.items():
        if v is None:
            continue
        key = k if k.startswith("_") else f"_{k}"
        msg[key] = v
    data = json.dumps(msg).encode()
    req = request.Request(GELF_URL, data=data, headers={"Content-Type": "application/json"})
    try:
        with request.urlopen(req, timeout=5) as r:
            r.read()
    except error.URLError as e:
        print(f"GELF POST failed: {e}", file=sys.stderr)


def _safe(label: str, fn):
    try:
        fn()
    except Exception:
        print(f"[{label}] failed:", file=sys.stderr)
        traceback.print_exc()


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def _oem_dell(obj: dict) -> dict:
    return (obj.get("Oem") or {}).get("Dell") or {}


# ── polls ────────────────────────────────────────────────────────────────────

def poll_system(s: IdracSession) -> None:
    sys_data = s.get(f"/redfish/v1/Systems/{SYSTEM_ID}")
    status = sys_data.get("Status") or {}
    cpu = sys_data.get("ProcessorSummary") or {}
    mem = sys_data.get("MemorySummary") or {}
    gelf(
        f"System {sys_data.get('HostName') or IDRAC_HOST}: power={sys_data.get('PowerState')} health={status.get('HealthRollup') or status.get('Health')}",
        level=SEVERITY_TO_GELF.get(status.get("HealthRollup") or status.get("Health"), 6),
        idrac_event_type="system",
        idrac_power_state=sys_data.get("PowerState"),
        idrac_health=status.get("HealthRollup") or status.get("Health"),
        idrac_model=(sys_data.get("Model") or "").strip(),
        idrac_manufacturer=(sys_data.get("Manufacturer") or "").strip(),
        idrac_serial=(sys_data.get("SerialNumber") or "").strip(),
        idrac_sku=(sys_data.get("SKU") or "").strip(),
        idrac_asset_tag=(sys_data.get("AssetTag") or "").strip() or None,
        idrac_bios_version=sys_data.get("BiosVersion"),
        idrac_hostname=sys_data.get("HostName"),
        idrac_indicator_led=sys_data.get("IndicatorLED"),
        idrac_cpu_model=(cpu.get("Model") or "").strip() or None,
        idrac_cpu_count=cpu.get("Count"),
        idrac_cpu_logical=cpu.get("LogicalProcessorCount"),
        idrac_mem_gib=mem.get("TotalSystemMemoryGiB"),
        idrac_mem_health=(mem.get("Status") or {}).get("HealthRollup") or (mem.get("Status") or {}).get("Health"),
    )


def poll_thermal(s: IdracSession) -> None:
    t = s.get(f"/redfish/v1/Chassis/{CHASSIS_ID}/Thermal")
    max_temp = None
    max_temp_name = None
    for temp in t.get("Temperatures") or []:
        status = temp.get("Status") or {}
        absent = status.get("State") == "Absent"
        c = temp.get("ReadingCelsius")
        if not absent and c is not None and (max_temp is None or c > max_temp):
            max_temp, max_temp_name = c, temp.get("Name")
        gelf(
            f"Temp {temp.get('Name')}: {('absent' if absent else f'{c}C')} ({status.get('Health') or status.get('State')})",
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            idrac_event_type="thermal",
            idrac_temp_name=temp.get("Name"),
            idrac_temp_c=None if absent else c,
            idrac_temp_health=status.get("Health"),
            idrac_temp_state=status.get("State"),
            idrac_temp_present=not absent,
            idrac_temp_upper_critical=temp.get("UpperThresholdCritical"),
            idrac_temp_upper_fatal=temp.get("UpperThresholdFatal"),
            idrac_temp_physical_context=temp.get("PhysicalContext"),
        )
    for fan in t.get("Fans") or []:
        status = fan.get("Status") or {}
        absent = status.get("State") == "Absent"
        reading = fan.get("Reading") if fan.get("Reading") is not None else fan.get("CurrentReading")
        units = fan.get("ReadingUnits") or fan.get("Units")
        gelf(
            f"Fan {fan.get('FanName') or fan.get('Name')}: {reading} {units or ''}".strip(),
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            idrac_event_type="fan",
            idrac_fan_name=fan.get("FanName") or fan.get("Name"),
            idrac_fan_reading=None if absent else reading,
            idrac_fan_reading_units=units,
            idrac_fan_health=status.get("Health"),
            idrac_fan_state=status.get("State"),
            idrac_fan_present=not absent,
        )
    if max_temp is not None:
        gelf(
            f"Chassis max temp {max_temp_name}: {max_temp}C",
            level=6,
            idrac_event_type="thermal_max",
            idrac_max_temp_c=max_temp,
            idrac_max_temp_name=max_temp_name,
        )


def poll_power(s: IdracSession) -> None:
    p = s.get(f"/redfish/v1/Chassis/{CHASSIS_ID}/Power")
    pc = (p.get("PowerControl") or [{}])[0]
    metrics = pc.get("PowerMetrics") or {}
    gelf(
        f"Power consumed {pc.get('PowerConsumedWatts')}W (cap {pc.get('PowerCapacityWatts')}W)",
        level=6,
        idrac_event_type="power",
        idrac_watts_consumed=pc.get("PowerConsumedWatts"),
        idrac_watts_capacity=pc.get("PowerCapacityWatts"),
        idrac_watts_limit=(pc.get("PowerLimit") or {}).get("LimitInWatts"),
        idrac_watts_min_interval=metrics.get("MinConsumedWatts"),
        idrac_watts_max_interval=metrics.get("MaxConsumedWatts"),
        idrac_watts_avg_interval=metrics.get("AverageConsumedWatts"),
        idrac_metric_interval_min=metrics.get("IntervalInMin"),
    )
    for idx, psu in enumerate(p.get("PowerSupplies") or []):
        status = psu.get("Status") or {}
        gelf(
            f"PSU {idx + 1}: {status.get('Health')}/{status.get('State')} model={psu.get('Model')} {psu.get('LineInputVoltage')}V",
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            idrac_event_type="psu",
            idrac_psu_index=idx + 1,
            idrac_psu_name=psu.get("Name"),
            idrac_psu_health=status.get("Health"),
            idrac_psu_state=status.get("State"),
            idrac_psu_input_watts=psu.get("PowerInputWatts"),
            idrac_psu_output_watts=psu.get("PowerOutputWatts"),
            idrac_psu_capacity_watts=psu.get("PowerCapacityWatts"),
            idrac_psu_input_voltage=psu.get("LineInputVoltage"),
            idrac_psu_model=psu.get("Model"),
            idrac_psu_serial=psu.get("SerialNumber"),
            idrac_psu_part_number=psu.get("PartNumber"),
            idrac_psu_firmware=psu.get("FirmwareVersion"),
            idrac_psu_input_type=psu.get("PowerSupplyType"),
        )


def poll_drives(s: IdracSession) -> None:
    """Walk Systems/<sys>/Storage/<ctrl>/(Drives,Volumes).

    On iDRAC the Storage collection lists each RAID/HBA controller; each
    controller's Drives is the list of physical disks. This is standard
    Redfish, not an OEM extension.
    """
    try:
        ctrls_coll = s.get(f"/redfish/v1/Systems/{SYSTEM_ID}/Storage")
    except error.HTTPError as e:
        if e.code == 404:
            return
        raise
    for cref in ctrls_coll.get("Members") or []:
        ctrl = s.get(cref["@odata.id"])
        cstatus = ctrl.get("Status") or {}
        # Storage controllers list — Dell usually has exactly one entry
        sc_list = ctrl.get("StorageControllers") or []
        sc = sc_list[0] if sc_list else {}
        sc_status = sc.get("Status") or {}
        gelf(
            f"Array controller {sc.get('Model') or ctrl.get('Name')}: {sc_status.get('Health') or cstatus.get('Health')}",
            level=SEVERITY_TO_GELF.get(sc_status.get("Health") or cstatus.get("Health"), 6),
            idrac_event_type="array_controller",
            idrac_ctrl_id=ctrl.get("Id"),
            idrac_ctrl_name=ctrl.get("Name"),
            idrac_ctrl_model=sc.get("Model"),
            idrac_ctrl_manufacturer=sc.get("Manufacturer"),
            idrac_ctrl_serial=sc.get("SerialNumber") or ctrl.get("SerialNumber"),
            idrac_ctrl_firmware=sc.get("FirmwareVersion"),
            idrac_ctrl_health=sc_status.get("Health") or cstatus.get("Health"),
            idrac_ctrl_state=sc_status.get("State") or cstatus.get("State"),
            idrac_ctrl_bus_speed=sc.get("SpeedGbps"),
            idrac_ctrl_supported_protocols=",".join(sc.get("SupportedDeviceProtocols") or []) or None,
        )
        for dref in ctrl.get("Drives") or []:
            drv = s.get(dref["@odata.id"])
            dstatus = drv.get("Status") or {}
            life_pct = drv.get("PredictedMediaLifeLeftPercent")
            ssd_endurance_used = (100 - life_pct) if isinstance(life_pct, (int, float)) else None
            gelf(
                f"Drive {drv.get('Name') or drv.get('Id')}: {dstatus.get('Health')} ({drv.get('Model')}, {drv.get('CapacityBytes')}B)",
                level=SEVERITY_TO_GELF.get(dstatus.get("Health"), 6),
                idrac_event_type="drive",
                idrac_drive_id=drv.get("Id"),
                idrac_drive_name=drv.get("Name"),
                idrac_drive_location=(drv.get("PhysicalLocation") or {}).get("PartLocation", {}).get("ServiceLabel") or drv.get("Name"),
                idrac_drive_model=drv.get("Model"),
                idrac_drive_manufacturer=drv.get("Manufacturer"),
                idrac_drive_serial=drv.get("SerialNumber"),
                idrac_drive_part_number=drv.get("PartNumber"),
                idrac_drive_revision=drv.get("Revision"),
                idrac_drive_health=dstatus.get("Health"),
                idrac_drive_state=dstatus.get("State"),
                idrac_drive_media=drv.get("MediaType"),
                idrac_drive_protocol=drv.get("Protocol"),
                idrac_drive_capacity_bytes=drv.get("CapacityBytes"),
                idrac_drive_block_bytes=drv.get("BlockSizeBytes"),
                idrac_drive_rotational_rpm=drv.get("RotationSpeedRPM"),
                idrac_drive_hotspare=drv.get("HotspareType"),
                idrac_drive_failure_predicted=drv.get("FailurePredicted"),
                idrac_drive_life_left_pct=life_pct,
                idrac_drive_ssd_endurance_used_pct=ssd_endurance_used,
            )


def poll_logs(s: IdracSession, state: dict) -> None:
    """Tail Lclog (Lifecycle Controller log) and Sel (System Event Log).

    Both live under /redfish/v1/Managers/<id>/LogServices/. Dell numbers
    entries with monotonically-increasing integer Ids, so we track a high
    water mark per log and only emit anything beyond it.

    Unlike iLO 4 (which doesn't populate `Created`), iDRAC stamps a real
    timestamp on every entry, so we don't have to skip backfill on first
    run — we just take the most recent N if state is empty.
    """
    candidates = [
        ("lclog", f"/redfish/v1/Managers/{MANAGER_ID}/LogServices/Lclog/Entries"),
        ("sel",   f"/redfish/v1/Managers/{MANAGER_ID}/LogServices/Sel/Entries"),
    ]
    INITIAL_BACKFILL = 100  # emit up to this many recent entries on first run per log
    for kind, path in candidates:
        try:
            page = s.get(path)
        except error.HTTPError as e:
            if e.code == 404:
                continue
            raise
        members = page.get("Members") or []
        last_id_key = f"{kind}_last_id"
        last_id_raw = state.get(last_id_key)
        all_ids: list[tuple[int, str]] = []
        for m in members:
            uri = m.get("@odata.id") or ""
            try:
                eid = int(uri.rstrip("/").rsplit("/", 1)[-1])
            except ValueError:
                continue
            all_ids.append((eid, uri))
        if not all_ids:
            continue
        if last_id_raw is None:
            # First run: emit up to INITIAL_BACKFILL most recent, then HWM at max
            all_ids.sort(reverse=True)
            recent = sorted(all_ids[:INITIAL_BACKFILL])
            for eid, uri in recent:
                entry = page_member_or_get(s, members, uri)
                _emit_log_entry(kind, entry, eid)
            state[last_id_key] = max(eid for eid, _ in all_ids)
            continue
        last_id = int(last_id_raw)
        new_refs = sorted([t for t in all_ids if t[0] > last_id])
        max_id_seen = last_id
        for eid, uri in new_refs:
            entry = page_member_or_get(s, members, uri)
            _emit_log_entry(kind, entry, eid)
            max_id_seen = max(max_id_seen, eid)
        if max_id_seen > last_id:
            state[last_id_key] = max_id_seen


def page_member_or_get(s: IdracSession, members: list[dict], uri: str) -> dict:
    """Dell often returns LogEntry objects inline in the Entries page —
    if Message is already present we don't need a second GET. Falls back
    to fetching the URI when only the @odata.id stub is there."""
    for m in members:
        if m.get("@odata.id") == uri and "Message" in m:
            return m
    return s.get(uri)


def _emit_log_entry(kind: str, entry: dict, eid: int) -> None:
    sev = entry.get("Severity") or "OK"
    oem = _oem_dell(entry)
    gelf(
        (entry.get("Message") or "")[:1024],
        level=SEVERITY_TO_GELF.get(sev, 6),
        idrac_event_type=kind,
        idrac_entry_id=str(eid),
        idrac_severity=sev,
        idrac_created=entry.get("Created"),
        idrac_entry_type=entry.get("EntryType"),
        idrac_message_id=entry.get("MessageId"),
        idrac_event_id=entry.get("EventId"),
        idrac_event_timestamp=entry.get("EventTimestamp"),
        idrac_sensor_type=entry.get("SensorType"),
        idrac_sensor_number=entry.get("SensorNumber"),
        idrac_oem_record_id=oem.get("LCLogRecordId") or oem.get("RecordId"),
        idrac_oem_category=oem.get("Category"),
    )


# ── entry points ────────────────────────────────────────────────────────────

def with_session(fn) -> None:
    s = IdracSession()
    try:
        s.open()
        fn(s)
    finally:
        s.close()


def health_cycle() -> None:
    def go(s: IdracSession) -> None:
        _safe("system", lambda: poll_system(s))
        _safe("thermal", lambda: poll_thermal(s))
        _safe("power", lambda: poll_power(s))
        _safe("drives", lambda: poll_drives(s))
    with_session(go)


def logs_cycle() -> None:
    state = load_state()
    def go(s: IdracSession) -> None:
        _safe("logs", lambda: poll_logs(s, state))
    with_session(go)
    save_state(state)


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "health"
    if mode == "health":
        health_cycle()
    elif mode == "logs":
        logs_cycle()
    elif mode == "all":
        health_cycle()
        logs_cycle()
    else:
        print(f"unknown mode: {mode!r}; use health|logs|all", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
