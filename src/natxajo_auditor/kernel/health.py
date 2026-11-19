from natxajo_auditor.kernel.lifecycle import LifecycleState


class HealthChecker:
    def check(self, kernel: object) -> dict[str, object]:
        state = getattr(kernel, "state", LifecycleState.FAILED)
        healthy = state == LifecycleState.RUNNING
        return {"status": "healthy" if healthy else "degraded", "state": state.value}
