package security

import "context"

// auditDropRecorder is the hook the [Auditor] calls when an audit event is
// dropped (e.g. because the auditor is disabled). Set via
// [SetAuditDropRecorder] from a package that owns the metric instrument
// (the instrumentation package, which would otherwise cause an import
// cycle here).
type auditDropRecorder func(ctx context.Context, reason string)

var auditDropFn auditDropRecorder

// SetAuditDropRecorder registers a callback invoked whenever an audit
// event is dropped. Setting nil disables the hook. Intended to be called
// once at startup from instrumentation wiring code; not safe to swap at
// request time (no synchronization on the package-level global).
func SetAuditDropRecorder(fn auditDropRecorder) {
	auditDropFn = fn
}

func recordAuditDrop(ctx context.Context, reason string) {
	if fn := auditDropFn; fn != nil {
		fn(ctx, reason)
	}
}
