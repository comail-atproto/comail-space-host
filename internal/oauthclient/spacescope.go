package oauthclient

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
)

const maxSpaceScopeBytes = 4096

var appendOnlyMailboxCollections = []string{
	mailbox.FolderOperationCollection,
	mailbox.FolderRevisionCollection,
	mailbox.MessageCollection,
	mailbox.MessageStateOperationCollection,
	mailbox.MessageStateRevisionCollection,
}

type spaceGrant struct {
	spaceType  string
	authority  string
	skey       string
	collection []string
	action     []string
	manage     []string
}

// MailboxScopes returns the steady-state, append-only grant for one exact
// member mailbox. It intentionally excludes space management and all mutation
// verbs other than record creation.
func MailboxScopes(authorityDID, spaceKey string) ([]string, error) {
	did, rkey, err := parseSteadyTarget(authorityDID, spaceKey)
	if err != nil {
		return nil, err
	}
	// The pinned getDelegationToken handler requires read; read_self cannot
	// mint the whole-space credential needed for provider synchronization.
	// Exact authority and skey binding contain that unavoidable breadth.
	grant := spaceGrant{
		spaceType:  mailbox.MailboxSpaceType,
		authority:  did.String(),
		skey:       rkey.String(),
		collection: appendOnlyMailboxCollections,
		action:     []string{"read", "create"},
	}
	return []string{"atproto", "blob:" + mailbox.MessageMIMEType, formatSpaceGrant(grant)}, nil
}

// ProvisioningScopes returns a separate one-time grant used only to create a
// predetermined mailbox key. Callers must revoke this session after verifying
// the new declaration and reauthorize with MailboxScopes.
func ProvisioningScopes(authorityDID string) ([]string, error) {
	did, err := syntax.ParseDID(authorityDID)
	if err != nil {
		return nil, fmt.Errorf("oauthclient: parse exact DID: %w", err)
	}
	grant := spaceGrant{
		spaceType:  mailbox.MailboxSpaceType,
		authority:  did.String(),
		skey:       "*",
		collection: appendOnlyMailboxCollections,
		action:     []string{"read_self"},
		manage:     []string{"create"},
	}
	return []string{"atproto", formatSpaceGrant(grant)}, nil
}

// ValidateSteadyGrant rejects omitted, substituted, or widened OAuth
// capabilities while tolerating provider-side ordering normalization.
func ValidateSteadyGrant(granted []string, authorityDID, spaceKey string) error {
	did, rkey, err := parseSteadyTarget(authorityDID, spaceKey)
	if err != nil {
		return err
	}
	if len(granted) != 3 {
		return errors.New("oauthclient: OAuth grant must contain exactly three scopes")
	}
	var atprotoCount, blobCount, spaceCount int
	for _, scope := range granted {
		switch {
		case scope == "atproto":
			atprotoCount++
		case scope == "blob:"+mailbox.MessageMIMEType:
			blobCount++
		case strings.HasPrefix(scope, "space:"):
			spaceCount++
			parsed, err := parseSpaceGrant(scope)
			if err != nil {
				return err
			}
			if parsed.spaceType != mailbox.MailboxSpaceType || parsed.authority != did.String() || parsed.skey != rkey.String() {
				return errors.New("oauthclient: OAuth space grant target mismatch")
			}
			if !sameStringSet(parsed.collection, appendOnlyMailboxCollections) {
				return errors.New("oauthclient: OAuth space grant collection mismatch")
			}
			if !sameStringSet(parsed.action, []string{"read", "create"}) || len(parsed.manage) != 0 {
				return errors.New("oauthclient: OAuth space grant is missing or widens append-only actions")
			}
		default:
			return errors.New("oauthclient: OAuth grant contained an unexpected scope")
		}
	}
	if atprotoCount != 1 || blobCount != 1 || spaceCount != 1 {
		return errors.New("oauthclient: OAuth grant omitted or duplicated a required scope")
	}
	return nil
}

// ValidateProvisioningGrant ensures the wildcard key exists only in the
// isolated one-time session and carries no record or blob write capability.
func ValidateProvisioningGrant(granted []string, authorityDID string) error {
	did, err := syntax.ParseDID(authorityDID)
	if err != nil {
		return fmt.Errorf("oauthclient: parse exact DID: %w", err)
	}
	if len(granted) != 2 {
		return errors.New("oauthclient: provisioning grant must contain exactly two scopes")
	}
	var atprotoCount, spaceCount int
	for _, scope := range granted {
		switch {
		case scope == "atproto":
			atprotoCount++
		case strings.HasPrefix(scope, "space:"):
			spaceCount++
			parsed, err := parseSpaceGrant(scope)
			if err != nil {
				return err
			}
			if parsed.spaceType != mailbox.MailboxSpaceType || parsed.authority != did.String() || parsed.skey != "*" {
				return errors.New("oauthclient: provisioning space grant target mismatch")
			}
			if !sameStringSet(parsed.collection, appendOnlyMailboxCollections) {
				return errors.New("oauthclient: provisioning space grant collection mismatch")
			}
			if !sameStringSet(parsed.action, []string{"read_self"}) || !sameStringSet(parsed.manage, []string{"create"}) {
				return errors.New("oauthclient: provisioning grant is missing or widens create-only management")
			}
		default:
			return errors.New("oauthclient: provisioning grant contained an unexpected scope")
		}
	}
	if atprotoCount != 1 || spaceCount != 1 {
		return errors.New("oauthclient: provisioning grant omitted or duplicated a required scope")
	}
	return nil
}

func parseSteadyTarget(authorityDID, spaceKey string) (syntax.DID, syntax.RecordKey, error) {
	did, err := syntax.ParseDID(authorityDID)
	if err != nil {
		return "", "", fmt.Errorf("oauthclient: parse exact DID: %w", err)
	}
	rkey, err := syntax.ParseRecordKey(spaceKey)
	if err != nil || spaceKey == "*" {
		if err == nil {
			err = errors.New("wildcard space key is not allowed")
		}
		return "", "", fmt.Errorf("oauthclient: parse exact space key: %w", err)
	}
	return did, rkey, nil
}

func formatSpaceGrant(grant spaceGrant) string {
	var builder strings.Builder
	builder.WriteString("space:")
	builder.WriteString(grant.spaceType)
	builder.WriteString("?authority=")
	builder.WriteString(grant.authority)
	builder.WriteString("&skey=")
	builder.WriteString(grant.skey)
	for _, collection := range grant.collection {
		builder.WriteString("&collection=")
		builder.WriteString(collection)
	}
	for _, action := range grant.action {
		builder.WriteString("&action=")
		builder.WriteString(action)
	}
	for _, manage := range grant.manage {
		builder.WriteString("&manage=")
		builder.WriteString(manage)
	}
	return builder.String()
}

func parseSpaceGrant(scope string) (spaceGrant, error) {
	if len(scope) == 0 || len(scope) > maxSpaceScopeBytes || strings.ContainsAny(scope, " \t\r\n") {
		return spaceGrant{}, errors.New("oauthclient: malformed OAuth space scope")
	}
	position, query, ok := strings.Cut(strings.TrimPrefix(scope, "space:"), "?")
	if !ok || position == "" || query == "" || strings.Contains(query, "?") {
		return spaceGrant{}, errors.New("oauthclient: malformed OAuth space scope")
	}
	spaceType, err := url.QueryUnescape(position)
	if err != nil {
		return spaceGrant{}, errors.New("oauthclient: malformed OAuth space type")
	}
	if _, err := syntax.ParseNSID(spaceType); err != nil {
		return spaceGrant{}, fmt.Errorf("oauthclient: parse OAuth space type: %w", err)
	}
	grant := spaceGrant{spaceType: spaceType}
	seenScalar := make(map[string]bool, 2)
	for _, field := range strings.Split(query, "&") {
		rawKey, rawValue, ok := strings.Cut(field, "=")
		if !ok || rawKey == "" || rawValue == "" {
			return spaceGrant{}, errors.New("oauthclient: malformed OAuth space parameter")
		}
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return spaceGrant{}, errors.New("oauthclient: malformed OAuth space parameter name")
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return spaceGrant{}, errors.New("oauthclient: malformed OAuth space parameter value")
		}
		switch key {
		case "authority":
			if seenScalar[key] {
				return spaceGrant{}, errors.New("oauthclient: duplicate OAuth space authority")
			}
			seenScalar[key] = true
			if _, err := syntax.ParseDID(value); err != nil {
				return spaceGrant{}, fmt.Errorf("oauthclient: parse OAuth space authority: %w", err)
			}
			grant.authority = value
		case "skey":
			if seenScalar[key] {
				return spaceGrant{}, errors.New("oauthclient: duplicate OAuth space key")
			}
			seenScalar[key] = true
			if value != "*" {
				if _, err := syntax.ParseRecordKey(value); err != nil {
					return spaceGrant{}, fmt.Errorf("oauthclient: parse OAuth space key: %w", err)
				}
			}
			grant.skey = value
		case "collection":
			if _, err := syntax.ParseNSID(value); err != nil {
				return spaceGrant{}, fmt.Errorf("oauthclient: parse OAuth space collection: %w", err)
			}
			grant.collection = append(grant.collection, value)
		case "action":
			if !containsString([]string{"read_self", "read", "create", "update", "delete"}, value) {
				return spaceGrant{}, errors.New("oauthclient: unknown OAuth space action")
			}
			grant.action = append(grant.action, value)
		case "manage":
			if !containsString([]string{"create", "update", "delete"}, value) {
				return spaceGrant{}, errors.New("oauthclient: unknown OAuth space management operation")
			}
			grant.manage = append(grant.manage, value)
		default:
			return spaceGrant{}, errors.New("oauthclient: unknown OAuth space parameter")
		}
	}
	if grant.authority == "" || grant.skey == "" {
		return spaceGrant{}, errors.New("oauthclient: OAuth space grant omitted an exact target")
	}
	return grant, nil
}

func sameStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
