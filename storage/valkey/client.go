package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	// clientIPTrackingTTL is the TTL for client IP tracking keys (24 hours)
	clientIPTrackingTTL = 24 * time.Hour
)

// ============================================================
// ClientStore Implementation
// ============================================================

// SaveClient saves a registered client
func (s *Store) SaveClient(ctx context.Context, client *storage.Client) (err error) {
	op := s.startTracedOp(ctx, "save_client")
	defer op.end(&err)

	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client")
	}

	data, err := json.Marshal(toClientJSON(client))
	if err != nil {
		return fmt.Errorf("failed to marshal client: %w", err)
	}

	key := s.clientKey(client.ClientID)

	if err = s.client.Do(op.ctx, s.client.B().Set().Key(key).Value(string(data)).Build()).Error(); err != nil {
		return fmt.Errorf("failed to save client: %w", err)
	}

	s.logger.Debug("Saved client", "client_id", client.ClientID)
	return nil
}

// GetClient retrieves a client by ID
func (s *Store) GetClient(ctx context.Context, clientID string) (result *storage.Client, err error) {
	op := s.startTracedOp(ctx, "get_client")
	defer op.end(&err)

	result, err = getAndUnmarshal(op.ctx, s, s.clientKey(clientID), storage.ErrClientNotFound, fromClientJSON)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ValidateClientSecret validates a client's secret using bcrypt
// Uses constant-time operations to prevent timing attacks
func (s *Store) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) (err error) {
	op := s.startTracedOp(ctx, "validate_client_secret")
	defer op.end(&err)

	// SECURITY: Always perform the same operations to prevent timing attacks
	// that could reveal whether a client exists or not

	client, clientErr := s.GetClient(op.ctx, clientID)

	// Determine which hash to use (real or dummy)
	// Use shared dummy hash constant for timing attack mitigation
	hashToCompare := storage.DummyBcryptHash
	isPublicClient := false

	if clientErr == nil {
		if client.IsPublic() {
			isPublicClient = true
		} else if client.ClientSecretHash != "" {
			hashToCompare = client.ClientSecretHash
		}
	}

	// ALWAYS perform bcrypt comparison (constant-time by design)
	// This prevents timing attacks based on whether we skip the comparison
	bcryptErr := bcrypt.CompareHashAndPassword([]byte(hashToCompare), []byte(clientSecret))

	// For public clients, authentication always succeeds
	if isPublicClient && clientErr == nil {
		return nil
	}

	// If client lookup failed, return generic error (but only after bcrypt comparison)
	// SECURITY: Generic error message prevents client enumeration attacks
	if clientErr != nil {
		return errInvalidCredentials
	}

	// If bcrypt comparison failed, return generic error
	// SECURITY: Generic error message prevents distinguishing between
	// "client not found" and "wrong password" scenarios
	if bcryptErr != nil {
		return errInvalidCredentials
	}

	return nil
}

// ListClients lists all registered clients
func (s *Store) ListClients(ctx context.Context) (result []*storage.Client, err error) {
	op := s.startTracedOp(ctx, "list_clients")
	defer op.end(&err)

	pattern := s.clientKey("*")

	// Use a map to deduplicate results (SCAN can return duplicates across iterations)
	clientMap := make(map[string]*storage.Client)

	var cursor uint64
	for {
		var keys []string
		var newCursor uint64
		keys, newCursor, err = s.scanClientKeys(op.ctx, pattern, cursor)
		if err != nil {
			return nil, err
		}

		if err = s.fetchClientsFromKeys(op.ctx, keys, clientMap); err != nil {
			return nil, err
		}

		cursor = newCursor
		if cursor == 0 {
			break
		}
	}

	return s.clientMapToSlice(clientMap), nil
}

// scanClientKeys executes a SCAN command for client keys.
func (s *Store) scanClientKeys(ctx context.Context, pattern string, cursor uint64) ([]string, uint64, error) {
	result, err := s.client.Do(
		ctx,
		s.client.B().Scan().Cursor(cursor).Match(pattern).Count(scanBatchSize).Build(),
	).AsScanEntry()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to scan clients: %w", err)
	}
	return result.Elements, result.Cursor, nil
}

// fetchClientsFromKeys fetches client data for the given keys and adds to clientMap.
func (s *Store) fetchClientsFromKeys(ctx context.Context, keys []string, clientMap map[string]*storage.Client) error {
	for _, key := range keys {
		if _, exists := clientMap[key]; exists {
			continue // Skip duplicates (SCAN can return duplicates)
		}

		client, err := s.fetchClientByKey(ctx, key)
		if err != nil {
			return err
		}
		if client != nil {
			clientMap[key] = client
		}
	}
	return nil
}

// fetchClientByKey fetches a single client by its Valkey key.
func (s *Store) fetchClientByKey(ctx context.Context, key string) (*storage.Client, error) {
	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, nil // Key may have been deleted between SCAN and GET
		}
		return nil, fmt.Errorf("failed to get client %s: %w", key, err)
	}

	var j clientJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		s.logger.Warn("Failed to unmarshal client, skipping",
			"key", key,
			"error", err)
		return nil, nil
	}

	return fromClientJSON(&j), nil
}

// clientMapToSlice converts a client map to a slice.
func (s *Store) clientMapToSlice(clientMap map[string]*storage.Client) []*storage.Client {
	clients := make([]*storage.Client, 0, len(clientMap))
	for _, c := range clientMap {
		clients = append(clients, c)
	}
	return clients
}

// DeleteClient removes a registered client by ID.
func (s *Store) DeleteClient(ctx context.Context, clientID string) (err error) {
	op := s.startTracedOp(ctx, "delete_client")
	defer op.end(&err)

	key := s.clientKey(clientID)
	n, err := s.client.Do(op.ctx, s.client.B().Del().Key(key).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	if n == 0 {
		return storage.ErrClientNotFound
	}
	return nil
}

// CheckIPLimit checks if an IP has reached the client registration limit
func (s *Store) CheckIPLimit(ctx context.Context, ip string, maxClientsPerIP int) (err error) {
	op := s.startTracedOp(ctx, "check_ip_limit")
	defer op.end(&err)

	if maxClientsPerIP <= 0 {
		return nil // No limit
	}

	key := s.clientIPKey(ip)

	countStr, err := s.client.Do(op.ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			// No registrations yet for this IP
			return nil
		}
		return fmt.Errorf("failed to check IP limit: %w", err)
	}

	count, err := strconv.Atoi(countStr)
	if err != nil {
		// Invalid count, reset to 0
		return nil
	}

	if count >= maxClientsPerIP {
		// SECURITY: Generic error message prevents revealing current count
		// or confirming the IP is being tracked
		s.logger.Warn("Client registration limit reached",
			"ip", ip,
			"current_count", count,
			"max_allowed", maxClientsPerIP)
		return errRateLimitExceeded
	}

	return nil
}

// TrackClientIP increments the client count for an IP address
func (s *Store) TrackClientIP(ctx context.Context, ip string) (err error) {
	op := s.startTracedOp(ctx, "track_client_ip")
	defer op.end(&err)

	key := s.clientIPKey(ip)

	// Use INCR to atomically increment the count
	_, err = s.client.Do(op.ctx, s.client.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("failed to track client IP: %w", err)
	}

	// Set TTL on the key (reset daily)
	if expErr := s.client.Do(op.ctx, s.client.B().Expire().Key(key).Seconds(int64(clientIPTrackingTTL.Seconds())).Build()).Error(); expErr != nil {
		s.logger.Warn("Failed to set TTL on client IP tracking key",
			"ip", ip,
			"error", expErr)
	}

	return nil
}
