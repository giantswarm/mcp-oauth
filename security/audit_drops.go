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
//
// The hook is process-wide. Constructing a second [instrumentation.Instrumentation]
// re-registers it, so audit drops from any [Auditor] in the process
// route to the most recently constructed Instrumentation's meter — even
// if a different Auditor is attached to a different Server. Production
// deployments build one Server; tests that spin up multiple in parallel
// will see the second one win.
func SetAuditDropRecorder(fn auditDropRecorder) {
	auditDropFn = fn
}

func recordAuditDrop(ctx context.Context, reason string) {
	if fn := auditDropFn; fn != nil {
		fn(ctx, reason)
	}
}
