// Package valkey provides a Valkey storage backend for the mcp-oauth library.
//
// Valkey is a high-performance key-value store that is wire-compatible with Redis.
// This package implements all storage interfaces required by the mcp-oauth library,
// making it suitable for production deployments that require:
//
//   - Distributed storage for horizontal scaling
//   - Persistence across server restarts
//   - Automatic TTL-based expiration
//   - High availability with clustering
//
// # Implemented Interfaces
//
// The Store type implements all required storage interfaces:
//
//   - [storage.TokenStore]: Token management (save, get, delete tokens and user info)
//   - [storage.ClientStore]: OAuth client management (save, get, validate clients)
//   - [storage.FlowStore]: Authorization flow management (states, codes)
//   - [storage.RefreshTokenFamilyStore]: OAuth 2.1 token family tracking for reuse detection
//   - [storage.TokenRevocationStore]: Bulk token revocation for security scenarios
//
// # Key Schema
//
// All keys use a configurable prefix (default "mcp:") to avoid conflicts with
// other applications sharing the same Valkey instance:
//
//	{prefix}:token:{userID}           -> JSON(oauth2.Token)
//	{prefix}:userinfo:{userID}        -> JSON(UserInfo)
//	{prefix}:refresh:{token}          -> userID (with TTL)
//	{prefix}:refresh:meta:{token}     -> JSON(familyMetadata)
//	{prefix}:client:{clientID}        -> JSON(Client)
//	{prefix}:client:ip:{ip}           -> count (with TTL)
//	{prefix}:state:{stateID}          -> JSON(AuthorizationState)
//	{prefix}:state:provider:{state}   -> stateID (for reverse lookup)
//	{prefix}:code:{code}              -> JSON(AuthorizationCode)
//	{prefix}:meta:{tokenID}           -> JSON(TokenMetadata)
//	{prefix}:userclient:{uid}:{cid}   -> SET of tokenIDs
//	{prefix}:family:{familyID}        -> SET of refresh tokens in family
//
// # Atomic Operations
//
// OAuth 2.1 requires certain operations to be atomic to prevent security issues:
//
//   - AtomicCheckAndMarkAuthCodeUsed: Prevents authorization code replay attacks
//   - AtomicGetAndDeleteRefreshToken: Prevents refresh token reuse attacks
//
// These operations use Lua scripts to ensure atomicity in Valkey, providing
// the same security guarantees as the in-memory implementation but with
// distributed storage benefits.
//
// # Configuration
//
// Basic usage:
//
//	store, err := valkey.New(valkey.Config{
//	    Address:   "localhost:6379",
//	    KeyPrefix: "mcp:",
//	})
//
// With TLS:
//
//	store, err := valkey.New(valkey.Config{
//	    Address:   "valkey.example.com:6379",
//	    Password:  os.Getenv("VALKEY_PASSWORD"),
//	    TLS:       &tls.Config{MinVersion: tls.VersionTLS12},
//	    KeyPrefix: "mcp:",
//	})
//
// # Security Considerations
//
//   - All tokens are stored with TTLs to prevent unbounded growth
//   - Lua scripts ensure atomic operations for security-critical flows
//   - Constant-time bcrypt comparison prevents timing attacks in client validation
//   - TLS support enables encrypted connections to Valkey servers
//   - Family metadata is retained for configurable period for security forensics
//   - Optional token encryption at rest via SetEncryptor() using AES-256-GCM
//   - Input size validation prevents DoS attacks via oversized payloads
//   - Generic error messages prevent information leakage
//
// # Token Encryption at Rest
//
// Sensitive oauth2.Token fields (AccessToken, RefreshToken) can be encrypted
// before storing in Valkey:
//
//	key, _ := security.GenerateKey()
//	encryptor, _ := security.NewEncryptor(key)
//	store.SetEncryptor(encryptor)
//
// When enabled, tokens are encrypted with AES-256-GCM before storage and
// automatically decrypted when retrieved.
//
// # Best Practices
//
//   - Always use TLS in production environments
//   - Set strong passwords for Valkey authentication
//   - Enable token encryption at rest for sensitive deployments
//   - Use dedicated Valkey instances or databases for OAuth storage
//   - Monitor key count and memory usage for potential DoS attacks
//   - Configure appropriate TTLs based on your security requirements
package valkey
