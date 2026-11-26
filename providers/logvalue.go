package providers

import "log/slog"

// LogValue implements [slog.LogValuer]. It names the user by issuer and
// subject, the pair OpenID Connect Core 5.7 lets a relying party rely on,
// and, for a delegated call, the current actor of the RFC 8693 4.1 act claim:
//
//	logger.Info("model deleted", slog.Any("user", userInfo))
//	// user.issuer, user.subject, user.actor.issuer, user.actor.subject
//
// It omits profile fields (Email, Name, Groups) and credentials. Subject values
// may themselves contain personal data. Actor fields are included only when
// present; an actor issuer is never inferred from the token issuer. A nil
// receiver or missing user issuer or subject produces an empty group.
func (u *UserInfo) LogValue() slog.Value {
	if u == nil || u.Issuer == "" || u.ID == "" {
		return slog.GroupValue()
	}
	attributes := []slog.Attr{slog.String("issuer", u.Issuer), slog.String("subject", u.ID)}
	var actor []slog.Attr
	if u.ActorIssuer != "" {
		actor = append(actor, slog.String("issuer", u.ActorIssuer))
	}
	if u.ActorSubject != "" {
		actor = append(actor, slog.String("subject", u.ActorSubject))
	}
	if len(actor) != 0 {
		attributes = append(attributes, slog.Attr{Key: "actor", Value: slog.GroupValue(actor...)})
	}
	return slog.GroupValue(attributes...)
}
