package providers

import "log/slog"

// LogValue implements [slog.LogValuer]. It names the user by issuer and
// subject, the pair OpenID Connect Core 5.7 lets a relying party rely on,
// and, for a delegated call, the current actor of the RFC 8693 4.1 act claim:
//
//	logger.Info("model deleted", slog.Any("user", userInfo))
//	// user.issuer, user.subject, user.actor.issuer, user.actor.subject
//
// It never includes profile data (email, name, groups) or credentials. A nil
// or incomplete UserInfo is an empty group, which handlers omit.
func (u *UserInfo) LogValue() slog.Value {
	if u == nil || u.Issuer == "" || u.ID == "" || (u.ActorIssuer == "") != (u.ActorSubject == "") {
		return slog.GroupValue()
	}
	attributes := []slog.Attr{slog.String("issuer", u.Issuer), slog.String("subject", u.ID)}
	if u.ActorSubject != "" {
		attributes = append(attributes, slog.Group("actor", slog.String("issuer", u.ActorIssuer), slog.String("subject", u.ActorSubject)))
	}
	return slog.GroupValue(attributes...)
}
