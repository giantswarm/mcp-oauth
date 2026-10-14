package providers

import "fmt"

// UserInfoStatusError is returned by a provider's ValidateToken when the
// userinfo endpoint answers with a status other than 200 OK. Match it with
// errors.As to tell an unavailable IdP (5xx, 429) from a rejected token.
type UserInfoStatusError struct {
	StatusCode int
}

func (e *UserInfoStatusError) Error() string {
	return fmt.Sprintf("userinfo request failed with status %d", e.StatusCode)
}
