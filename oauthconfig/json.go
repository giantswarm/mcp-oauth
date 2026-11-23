package oauthconfig

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func decodeJSON(raw string, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("expected one JSON value")
	}
	return nil
}
