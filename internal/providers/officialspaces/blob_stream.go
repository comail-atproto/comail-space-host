package officialspaces

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const maxRecoveryBlobBytes int64 = 64 << 20

// StreamSourceMessageBlobs reads an ordered message-blob inventory under one
// fresh exact-target credential while proving the live repository remains at
// the source-authenticated state before and after the stream. Each data slice
// is borrowed only for the callback and is cleared immediately afterward.
// The callback runs before the final source-state check and must only populate
// bounded private staging; it must not publish or durably project content.
func (c *Client) StreamSourceMessageBlobs(
	ctx context.Context,
	source *SourceAuthenticatedRepository,
	cids []string,
	consume func(index int, cid string, data []byte) error,
) error {
	return c.streamSourceMessageBlobs(ctx, source, cids, maxRecoveryBlobBytes, consume)
}

func (c *Client) streamSourceMessageBlobs(
	ctx context.Context,
	source *SourceAuthenticatedRepository,
	cids []string,
	maxTotalBytes int64,
	consume func(index int, cid string, data []byte) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || source == nil {
		return ErrSnapshotVerification
	}
	if source.target != c.target {
		return repository.ErrTarget
	}
	if source.ValidateSeal() != nil {
		return ErrSnapshotVerification
	}
	if consume == nil || len(cids) > maxInventoryItems || maxTotalBytes < 1 || maxTotalBytes > maxRecoveryBlobBytes {
		return mailbox.ErrInvalidRecord
	}
	for index, blobCID := range cids {
		if !validRawCID(blobCID) || (index > 0 && cids[index-1] >= blobCID) {
			return mailbox.ErrInvalidRecord
		}
	}
	if err := c.validateRepoSourceOrigin(ctx); err != nil {
		return err
	}

	var totalBytes int64
	err := c.withReader(ctx, func(credential ScopedDoer) error {
		before, err := c.readSourceCommit(ctx, credential)
		if err != nil {
			return err
		}
		if err := verifyCommitConsistency(ctx, before, c.target, c.repoKeys); err != nil || !source.matchesCommit(before) {
			return fmt.Errorf("%w: blob read did not start at source snapshot", ErrSnapshotVerification)
		}
		for index, blobCID := range cids {
			if err := ctx.Err(); err != nil {
				return err
			}
			data, err := c.readMessageBlob(ctx, credential, blobCID)
			if err != nil {
				return err
			}
			if int64(len(data)) > maxTotalBytes-totalBytes {
				clear(data)
				return mailbox.ErrMessageTooLarge
			}
			totalBytes += int64(len(data))
			consumeErr := consume(index, blobCID, data)
			clear(data)
			if consumeErr != nil {
				if errors.Is(consumeErr, context.Canceled) || errors.Is(consumeErr, context.DeadlineExceeded) {
					return consumeErr
				}
				return errors.New("officialspaces: blob consumer rejected content")
			}
		}
		after, err := c.readSourceCommit(ctx, credential)
		if err != nil {
			return err
		}
		if err := verifyCommitConsistency(ctx, after, c.target, c.repoKeys); err != nil || !source.matchesCommit(after) {
			return fmt.Errorf("%w: blob read did not end at source snapshot", ErrSnapshotVerification)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if source.ValidateSeal() != nil {
		return ErrSnapshotVerification
	}
	return nil
}

func (c *Client) readMessageBlob(ctx context.Context, credential ScopedDoer, blobCID string) ([]byte, error) {
	query := targetQuery(c.target)
	query.Set("cid", blobCID)
	response, err := c.request(ctx, credential, http.MethodGet, getBlobEndpoint, query, nil, "", mailbox.MessageMIMEType)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, decodeProviderError(response)
	}
	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || !strings.EqualFold(mediaType, mailbox.MessageMIMEType) {
		return nil, fmt.Errorf("%w: blob media type mismatch", mailbox.ErrIntegrity)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, mailbox.MaxRawMessageBytes+1))
	if readErr != nil {
		clear(data)
		return nil, errors.New("officialspaces: read blob")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: blob is empty", mailbox.ErrIntegrity)
	}
	if len(data) > mailbox.MaxRawMessageBytes {
		clear(data)
		return nil, mailbox.ErrMessageTooLarge
	}
	if !validBlobCID(blobCID, data) {
		clear(data)
		return nil, fmt.Errorf("%w: blob CID does not match content", mailbox.ErrIntegrity)
	}
	return data, nil
}
