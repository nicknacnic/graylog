"""HPE iLO Redfish → Graylog (GELF HTTP) poller.

Targets iLO 4 (v2.x firmware, RESTful service version 1.0.0) which uses
session-based auth and HPE-OEM extensions under `Oem.Hp`. Should also work
on iLO 5 — defensive lookups try Hp then Hpe.

Two modes, driven by separate systemd timers:

    python3 ilo_redfish.py health   # snapshot — system/thermal/power/drives
    python3 ilo_redfish.py logs     # tail IEL (state-tracked, deduped by Id)

Env vars:
    ILO_HOST          e.g. ilo-esxi2.darknetian.com (or an IP)
    ILO_USER, ILO_PASS
    GELF_URL          default http://127.0.0.1:12202/gelf
    ILO_STATE_PATH    default /var/lib/ilo-poller/state.json
    ILO_INSECURE      "1" to skip TLS verify (default — iLO self-signed)

GELF messages:
    host                  = ILO_HOST (so the existing iLO stream's source rule routes them)
    _ilo_event_type       categorical (system|thermal|fan|power|psu|drive|iel)
    _ilo_*                event-specific structured fields
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import traceback
from base64 import b64encode
from pathlib import Path
from typing import Any
from urllib import error, request


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        print(f"ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


ILO_HOST = _env("ILO_HOST")
ILO_USER = _env("ILO_USER")
ILO_PASS = _env("ILO_PASS")
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("ILO_STATE_PATH", "/var/lib/ilo-poller/state.json"))
ILO_INSECURE = os.environ.get("ILO_INSECURE", "1") == "1"

SEVERITY_TO_GELF = {"OK": 6, "Warning": 4, "Critical": 2, "Fatal": 2}
BASE = f"https://{ILO_HOST}"


# ── HTTP / session ──────────────────────────────────────────────────────────

class IloSession:
    def __init__(self) -> None:
        self.token: str | None = None
        self.session_uri: str | None = None

    def _ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if ILO_INSECURE:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def open(self) -> None:
        body = json.dumps({"UserName": ILO_USER, "Password": ILO_PASS}).encode()
        req = request.Request(
            BASE + "/redfish/v1/SessionService/Sessions/",
            data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with request.urlopen(req, context=self._ctx(), timeout=15) as r:
            self.token = r.headers.get("X-Auth-Token")
            self.session_uri = r.headers.get("Location")
        if not self.token:
            raise RuntimeError("iLO session opened but no X-Auth-Token returned")

    def get(self, path: str) -> Any:
        assert self.token, "session not opened"
        req = request.Request(
            BASE + path,
            headers={"X-Auth-Token": self.token, "Accept": "application/json"},
        )
        with request.urlopen(req, context=self._ctx(), timeout=15) as r:
            return json.loads(r.read())

    def close(self) -> None:
        if not (self.token and self.session_uri):
            return
        # session_uri is absolute already
        req = request.Request(
            self.session_uri,
            method="DELETE",
            headers={"X-Auth-Token": self.token},
        )
        try:
            with request.urlopen(req, context=self._ctx(), timeout=10) as r:
                r.read()
        except error.URLError:
            pass  # session will expire on its own
        self.token = None
        self.session_uri = None


def gelf(short_message: str, level: int = 6, **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": ILO_HOST,
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


def _oem_hp(obj: dict) -> dict:
    oem = obj.get("Oem") or {}
    return oem.get("Hp") or oem.get("Hpe") or {}


# ── polls ────────────────────────────────────────────────────────────────────

def poll_system(s: IloSession) -> None:
    sys_data = s.get("/redfish/v1/Systems/1/")
    status = sys_data.get("Status") or {}
    cpu = sys_data.get("ProcessorSummary") or {}
    mem = sys_data.get("MemorySummary") or {}
    gelf(
        f"System {sys_data.get('HostName') or ILO_HOST}: power={sys_data.get('PowerState')} health={status.get('Health')}",
        level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
        ilo_event_type="system",
        ilo_power_state=sys_data.get("PowerState"),
        ilo_health=status.get("Health"),
        ilo_model=(sys_data.get("Model") or "").strip(),
        ilo_serial=(sys_data.get("SerialNumber") or "").strip(),
        ilo_bios_version=sys_data.get("BiosVersion"),
        ilo_hostname=sys_data.get("HostName"),
        ilo_indicator_led=sys_data.get("IndicatorLED"),
        ilo_cpu_model=(cpu.get("Model") or "").strip() or None,
        ilo_cpu_count=cpu.get("Count"),
        ilo_mem_gib=mem.get("TotalSystemMemoryGiB"),
    )


def poll_thermal(s: IloSession) -> None:
    t = s.get("/redfish/v1/Chassis/1/Thermal/")
    max_temp = None
    max_temp_name = None
    for temp in t.get("Temperatures") or []:
        status = temp.get("Status") or {}
        absent = status.get("State") == "Absent"
        c = temp.get("ReadingCelsius")
        if not absent and c is not None and (max_temp is None or c > max_temp):
            max_temp, max_temp_name = c, temp.get("Name")
        # Keep absent slots — they're useful for a "physical inventory" page
        gelf(
            f"Temp {temp.get('Name')}: {('absent' if absent else f'{c}C')} ({status.get('Health') or status.get('State')})",
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            ilo_event_type="thermal",
            ilo_temp_name=temp.get("Name"),
            ilo_temp_c=None if absent else c,
            ilo_temp_health=status.get("Health"),
            ilo_temp_state=status.get("State"),
            ilo_temp_present=not absent,
            ilo_temp_upper_critical=temp.get("UpperThresholdCritical"),
            ilo_temp_physical_context=temp.get("PhysicalContext"),
        )
    for fan in t.get("Fans") or []:
        status = fan.get("Status") or {}
        absent = status.get("State") == "Absent"
        gelf(
            f"Fan {fan.get('FanName') or fan.get('Name')}: {fan.get('CurrentReading') or fan.get('Reading')} {fan.get('Units') or fan.get('ReadingUnits') or ''}".strip(),
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            ilo_event_type="fan",
            ilo_fan_name=fan.get("FanName") or fan.get("Name"),
            ilo_fan_reading=None if absent else (fan.get("CurrentReading") or fan.get("Reading")),
            ilo_fan_reading_units=fan.get("Units") or fan.get("ReadingUnits"),
            ilo_fan_health=status.get("Health"),
            ilo_fan_state=status.get("State"),
            ilo_fan_present=not absent,
        )
    if max_temp is not None:
        gelf(
            f"Chassis max temp {max_temp_name}: {max_temp}C",
            level=6,
            ilo_event_type="thermal_max",
            ilo_max_temp_c=max_temp,
            ilo_max_temp_name=max_temp_name,
        )


def poll_power(s: IloSession) -> None:
    p = s.get("/redfish/v1/Chassis/1/Power/")
    pc = (p.get("PowerControl") or [{}])[0]
    metrics = pc.get("PowerMetrics") or {}
    gelf(
        f"Power consumed {pc.get('PowerConsumedWatts')}W (cap {pc.get('PowerCapacityWatts')}W)",
        level=6,
        ilo_event_type="power",
        ilo_watts_consumed=pc.get("PowerConsumedWatts"),
        ilo_watts_capacity=pc.get("PowerCapacityWatts"),
        ilo_watts_limit=(pc.get("PowerLimit") or {}).get("LimitInWatts"),
        ilo_watts_min_interval=metrics.get("MinConsumedWatts"),
        ilo_watts_max_interval=metrics.get("MaxConsumedWatts"),
        ilo_watts_avg_interval=metrics.get("AverageConsumedWatts"),
        ilo_metric_interval_min=metrics.get("IntervalInMin"),
    )
    for idx, psu in enumerate(p.get("PowerSupplies") or []):
        status = psu.get("Status") or {}
        gelf(
            f"PSU {idx + 1}: {status.get('Health')}/{status.get('State')} model={psu.get('Model')} {psu.get('LineInputVoltage')}V",
            level=SEVERITY_TO_GELF.get(status.get("Health"), 6),
            ilo_event_type="psu",
            ilo_psu_index=idx + 1,
            ilo_psu_name=psu.get("Name"),
            ilo_psu_health=status.get("Health"),
            ilo_psu_state=status.get("State"),
            ilo_psu_input_watts=psu.get("PowerInputWatts"),
            ilo_psu_output_watts=psu.get("PowerOutputWatts"),
            ilo_psu_input_voltage=psu.get("LineInputVoltage"),
            ilo_psu_model=psu.get("Model"),
            ilo_psu_serial=psu.get("SerialNumber"),
            ilo_psu_firmware=psu.get("FirmwareVersion"),
        )


def poll_drives(s: IloSession) -> None:
    # iLO 4 path: SmartStorage/ArrayControllers/{n}/DiskDrives
    try:
        ctrls = s.get("/redfish/v1/Systems/1/SmartStorage/ArrayControllers/")
    except error.HTTPError as e:
        if e.code == 404:
            return  # no smart-storage on this iLO
        raise
    for cref in ctrls.get("Members") or []:
        ctrl = s.get(cref["@odata.id"])
        cstatus = ctrl.get("Status") or {}
        gelf(
            f"Array controller {ctrl.get('Model')}: {cstatus.get('Health')}",
            level=SEVERITY_TO_GELF.get(cstatus.get("Health"), 6),
            ilo_event_type="array_controller",
            ilo_ctrl_model=ctrl.get("Model"),
            ilo_ctrl_serial=ctrl.get("SerialNumber"),
            ilo_ctrl_firmware=(ctrl.get("FirmwareVersion") or {}).get("Current", {}).get("VersionString") if isinstance(ctrl.get("FirmwareVersion"), dict) else ctrl.get("FirmwareVersion"),
            ilo_ctrl_health=cstatus.get("Health"),
            ilo_ctrl_cache_mib=ctrl.get("CacheMemorySizeMiB"),
            ilo_ctrl_backup_status=ctrl.get("BackupPowerSourceStatus"),
            ilo_ctrl_encryption=ctrl.get("EncryptionEnabled"),
        )
        # Walk drive children
        try:
            drives = s.get(cref["@odata.id"].rstrip("/") + "/DiskDrives/")
        except error.HTTPError:
            continue
        for dref in drives.get("Members") or []:
            drv = s.get(dref["@odata.id"])
            dstatus = drv.get("Status") or {}
            gelf(
                f"Drive {drv.get('Location')}: {dstatus.get('Health')} ({drv.get('Model')}, {drv.get('CapacityGB')}GB)",
                level=SEVERITY_TO_GELF.get(dstatus.get("Health"), 6),
                ilo_event_type="drive",
                ilo_drive_location=drv.get("Location"),
                ilo_drive_model=drv.get("Model"),
                ilo_drive_serial=drv.get("SerialNumber"),
                ilo_drive_health=dstatus.get("Health"),
                ilo_drive_state=dstatus.get("State"),
                ilo_drive_media=drv.get("MediaType"),
                ilo_drive_interface=drv.get("InterfaceType"),
                ilo_drive_capacity_gb=drv.get("CapacityGB"),
                ilo_drive_rotational_rpm=drv.get("RotationalSpeedRpm"),
                ilo_drive_temp_c=drv.get("CurrentTemperatureCelsius"),
                ilo_drive_temp_max_c=drv.get("MaximumTemperatureCelsius"),
                ilo_drive_uptime_h=drv.get("PowerOnHours"),
                ilo_drive_ssd_endurance_pct=drv.get("SSDEnduranceUtilizationPercentage"),
                ilo_drive_firmware=(drv.get("FirmwareVersion") or {}).get("Current", {}).get("VersionString") if isinstance(drv.get("FirmwareVersion"), dict) else drv.get("FirmwareVersion"),
            )


def poll_logs(s: IloSession, state: dict) -> None:
    candidates = [
        ("iel", "/redfish/v1/Managers/1/LogServices/IEL/Entries/"),
        ("iml", "/redfish/v1/Managers/1/LogServices/IML/Entries/"),
        ("security", "/redfish/v1/Managers/1/LogServices/Security/Entries/"),
    ]
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
        # Member URIs end in /<id>/ — pull the id from the URI
        all_ids: list[tuple[int, str]] = []
        for m in members:
            uri = m["@odata.id"]
            try:
                eid = int(uri.rstrip("/").rsplit("/", 1)[-1])
            except ValueError:
                continue
            all_ids.append((eid, uri))
        if not all_ids:
            continue
        # First run for this log: set the high-water mark to the current max
        # without emitting. iLO 4 doesn't populate Created on most entries, so
        # backfilling history would assign `now()` to every old entry and make
        # them look like they all just happened.
        if last_id_raw is None:
            state[last_id_key] = max(eid for eid, _ in all_ids)
            continue
        last_id = int(last_id_raw)
        new_refs = sorted([t for t in all_ids if t[0] > last_id])
        max_id_seen = last_id
        for eid, uri in new_refs:
            entry = s.get(uri)
            sev = entry.get("Severity") or "OK"
            gelf(
                (entry.get("Message") or "")[:1024],
                level=SEVERITY_TO_GELF.get(sev, 6),
                ilo_event_type=kind,
                ilo_entry_id=str(eid),
                ilo_severity=sev,
                ilo_created=entry.get("Created"),
                ilo_entry_type=entry.get("EntryType"),
                ilo_sensor_type=entry.get("SensorType"),
                ilo_sensor_number=entry.get("SensorNumber"),
                ilo_oem_event_number=_oem_hp(entry).get("EventNumber"),
                ilo_oem_class=_oem_hp(entry).get("Class"),
                ilo_oem_code=_oem_hp(entry).get("Code"),
            )
            max_id_seen = max(max_id_seen, eid)
        if max_id_seen > last_id:
            state[last_id_key] = max_id_seen


# ── entry points ────────────────────────────────────────────────────────────

def with_session(fn) -> None:
    s = IloSession()
    try:
        s.open()
        fn(s)
    finally:
        s.close()


def health_cycle() -> None:
    def go(s: IloSession) -> None:
        _safe("system", lambda: poll_system(s))
        _safe("thermal", lambda: poll_thermal(s))
        _safe("power", lambda: poll_power(s))
        _safe("drives", lambda: poll_drives(s))
    with_session(go)


def logs_cycle() -> None:
    state = load_state()
    def go(s: IloSession) -> None:
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
