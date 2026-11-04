package dex

import (
	"encoding/base64"

	"google.golang.org/protobuf/encoding/protowire"
)

// Field numbers of Dex's IDTokenSubject message.
const (
	subjectUserIDField    protowire.Number = 1
	subjectConnectorField protowire.Number = 2
)

// ConnectorFromSubject returns the connector a Dex sub claim was issued
// through. Dex issues the sub as its IDTokenSubject message (user_id,
// conn_id), protobuf-encoded and base64url without padding, so one person
// signing in through two connectors gets two subjects. ok is false for a
// subject that is not of that form or names no connector.
//
// Pass the connector to server.WithIdentityConnector to have an identity flow
// yield a subject of the same connector.
func ConnectorFromSubject(subject string) (connector string, ok bool) {
	data, err := base64.RawURLEncoding.DecodeString(subject)
	if err != nil || len(data) == 0 {
		return "", false
	}
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 || typ != protowire.BytesType || (num != subjectUserIDField && num != subjectConnectorField) {
			return "", false
		}
		data = data[n:]
		value, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return "", false
		}
		data = data[n:]
		if num == subjectConnectorField {
			connector = string(value)
		}
	}
	return connector, connector != ""
}
