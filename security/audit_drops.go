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
// event is dropped. Setting nil disables the hook. The intended caller is
// the instrumentation wiring code, which records a counter labelled by
// reason.
func SetAuditDropRecorder(fn auditDropRecorder) {
	auditDropFn = fn
}

func recordAuditDrop(ctx context.Context, _ *Auditor, reason string) {
	if fn := auditDropFn; fn != nil {
		fn(ctx, reason)
	}
}
