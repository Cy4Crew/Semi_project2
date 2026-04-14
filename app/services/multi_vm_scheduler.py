from __future__ import annotations

from dataclasses import dataclass
from queue import Queue, Empty
from threading import Lock
from typing import Iterable

from app.core.config import settings
from app.machinery.vmware_manager import VMwareManager, VmSlot


@dataclass
class ScheduledJob:
    report_id: str
    sample_path: str
    artifact_root: str


class MultiVMScheduler:
    def __init__(self):
        bridges = [x.strip() for x in str(getattr(settings, "sandbox_bridge_urls", "") or "").split(",") if x.strip()]
        if not bridges:
            bridges = [str(settings.sandbox_bridge_url)]
        vms = [x.strip() for x in str(getattr(settings, "sandbox_vm_names", "") or "").split(",") if x.strip()]
        if not vms:
            vms = [str(settings.sandbox_vm_name)]
        self.manager = VMwareManager(
            bridges,
            vms,
            str(settings.sandbox_vm_snapshot),
            int(getattr(settings, 'sandbox_bridge_health_ttl_seconds', 10)),
            int(getattr(settings, 'sandbox_vm_slot_cooldown_seconds', 20)),
        )
        self.queue: Queue[ScheduledJob] = Queue()
        self._leases: dict[str, str] = {}
        self._lock = Lock()

    def submit(self, job: ScheduledJob) -> None:
        self.queue.put(job)

    def next_job(self) -> ScheduledJob | None:
        try:
            return self.queue.get_nowait()
        except Empty:
            return None

    def acquire_vm(self, report_id: str | None = None) -> VmSlot | None:
        slot = self.manager.pick_available()
        if slot and report_id:
            with self._lock:
                self._leases[report_id] = slot.name
        return slot

    def release_vm(self, report_id: str | None, success: bool = True, reason: str | None = None) -> None:
        if not report_id:
            return
        with self._lock:
            slot_name = self._leases.pop(report_id, None)
        if slot_name:
            self.manager.release(slot_name, success=success, reason=reason)

    def health(self, force: bool = False) -> Iterable[VmSlot]:
        return self.manager.healthcheck(force=force)
