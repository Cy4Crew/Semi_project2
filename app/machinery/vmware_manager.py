from __future__ import annotations

from dataclasses import dataclass, field
import time
import threading
import requests


@dataclass
class VmSlot:
    name: str
    snapshot: str
    bridge_url: str
    healthy: bool = False
    reason: str | None = None
    busy: bool = False
    inflight_jobs: int = 0
    last_healthcheck: float = 0.0
    cooldown_until: float = 0.0
    last_assigned_at: float = 0.0
    metadata: dict = field(default_factory=dict)


class VMwareManager:
    def __init__(self, bridge_urls: list[str], vm_names: list[str], snapshot: str, health_ttl_seconds: int = 10, cooldown_seconds: int = 20):
        self._slots: list[VmSlot] = []
        for idx, name in enumerate(vm_names):
            bridge = bridge_urls[min(idx, len(bridge_urls) - 1)] if bridge_urls else ''
            self._slots.append(VmSlot(name=name, snapshot=snapshot, bridge_url=bridge))
        self._health_ttl = max(1, int(health_ttl_seconds))
        self._cooldown = max(0, int(cooldown_seconds))
        self._lock = threading.Lock()

    def _refresh_slot_health(self, slot: VmSlot, force: bool = False) -> VmSlot:
        now = time.time()
        if not force and slot.last_healthcheck and now - slot.last_healthcheck < self._health_ttl:
            return slot
        try:
            payload = requests.get(
                f"{slot.bridge_url.rstrip('/')}/health",
                params={"vm_name": slot.name, "snapshot_name": slot.snapshot},
                timeout=5,
            ).json()
            vm_running = bool(payload.get('vm_running'))
            startable = (
                bool(payload.get('vmrun_exists'))
                and bool(payload.get('vmx_path'))
                and bool(payload.get('snapshot_exists'))
                and bool(payload.get('shared_dir_ready'))
            )
            guest_ready = bool(payload.get('guest_ready'))

            if 'slot_healthy' in payload:
                slot.healthy = bool(payload.get('slot_healthy'))
            else:
                slot.healthy = (startable and not vm_running) or (startable and vm_running and guest_ready)

            slot.reason = None if slot.healthy else payload.get('reason') or self._build_reason(payload)
            slot.metadata = payload
        except Exception as exc:
            slot.healthy = False
            slot.reason = str(exc)
            slot.metadata = {}
        slot.last_healthcheck = now
        return slot

    @staticmethod
    def _build_reason(payload: dict) -> str:
        if not payload.get('vmrun_exists'):
            return 'vmrun_missing'
        if not payload.get('vmx_path'):
            return 'vmx_missing'
        if not payload.get('snapshot_exists'):
            return 'snapshot_missing'
        if not payload.get('shared_dir_ready'):
            return 'shared_dir_not_ready'
        if payload.get('vm_running') and not payload.get('guest_ready'):
            return payload.get('reason') or 'guest_not_ready'
        if not payload.get('vm_running'):
            return 'vm_powered_off_but_startable'
        return 'bridge_unhealthy'

    def healthcheck(self, force: bool = False) -> list[VmSlot]:
        with self._lock:
            return [self._refresh_slot_health(slot, force=force) for slot in self._slots]

    def pick_available(self) -> VmSlot | None:
        with self._lock:
            now = time.time()
            candidates: list[tuple[tuple[float, float, float], VmSlot]] = []
            for slot in self._slots:
                slot = self._refresh_slot_health(slot)
                if slot.busy or now < slot.cooldown_until or not slot.healthy:
                    continue
                readiness_bonus = 0.0 if slot.metadata.get('guest_ready') else 1000.0
                score = (float(slot.inflight_jobs), float(slot.last_assigned_at), readiness_bonus)
                candidates.append((score, slot))
            if not candidates:
                return None
            _, slot = sorted(candidates, key=lambda item: item[0])[0]
            slot.busy = True
            slot.inflight_jobs += 1
            slot.last_assigned_at = now
            return slot

    def release(self, slot_name: str, success: bool = True, reason: str | None = None) -> None:
        with self._lock:
            for slot in self._slots:
                if slot.name != slot_name:
                    continue
                slot.busy = False
                slot.inflight_jobs = max(0, int(slot.inflight_jobs) - 1)
                slot.reason = None if success else (reason or slot.reason)
                if not success:
                    slot.cooldown_until = time.time() + self._cooldown
                return
