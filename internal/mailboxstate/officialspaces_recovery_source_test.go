package mailboxstate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/providers/officialspaces"
	"github.com/comail-atproto/comail-space-host/internal/spacecredential"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"lukechampine.com/blake3"
)

func TestReduceOfficialSpacesSourceAcceptsOnlyAuthenticatedSourceCapability(t *testing.T) {
	inventory := validOfficialInventory(t)
	source := readSyntheticAuthenticatedSource(t, inventory)

	reduced, err := ReduceOfficialSpacesSource(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if reduced.Target() != inventory.target || reduced.Revision() != inventory.revision ||
		len(reduced.Messages()) != 1 || len(reduced.MessageStates()) != 1 ||
		len(reduced.Folders()) != len(standardFolderRoles) {
		t.Fatalf("unexpected public reduction: target=%+v revision=%q messages=%d states=%d folders=%d",
			reduced.Target(), reduced.Revision(), len(reduced.Messages()), len(reduced.MessageStates()), len(reduced.Folders()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReduceOfficialSpacesSource(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled public reduction error=%v", err)
	}
	if _, err := ReduceOfficialSpacesSource(context.Background(), &officialspaces.SourceAuthenticatedRepository{}); !errors.Is(err, ErrSourceReduction) {
		t.Fatalf("zero source error=%v", err)
	}
}

func TestReduceOfficialSpacesSourceRedactsSemanticRecordFailure(t *testing.T) {
	inventory := validOfficialInventory(t)
	secretRKey := ""
	for index, record := range inventory.records {
		if record.Collection != "email.atmos.message" {
			continue
		}
		message := sourceMessageRecord(t, inventory.target.RepoDID, "", "message")
		message.InitialMailbox = strings.Repeat("x", 256)
		inventory.records[index] = sourceRecord(t, record.Collection, record.RKey, message)
		secretRKey = record.RKey
	}
	if secretRKey == "" {
		t.Fatal("synthetic inventory has no message record")
	}
	source := readSyntheticAuthenticatedSource(t, inventory)
	_, err := ReduceOfficialSpacesSource(context.Background(), source)
	if !errors.Is(err, ErrSourceReduction) || err.Error() != ErrSourceReduction.Error() || strings.Contains(err.Error(), secretRKey) {
		t.Fatalf("public reduction leaked semantic failure: %v", err)
	}
}

func readSyntheticAuthenticatedSource(t *testing.T, inventory officialSpacesInventory) *officialspaces.SourceAuthenticatedRepository {
	t.Helper()
	client, credentials := newSyntheticAuthenticatedClient(t, inventory, nil)
	source, err := client.ReadSourceAuthenticatedRepository(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if credentials.acquired != 1 || credentials.closed != 1 {
		t.Fatalf("credential acquired=%d closed=%d", credentials.acquired, credentials.closed)
	}
	return source
}

func newSyntheticAuthenticatedClient(
	t *testing.T,
	inventory officialSpacesInventory,
	blobs map[string][]byte,
) (*officialspaces.Client, *syntheticSourceCredentials) {
	t.Helper()
	privateKey, err := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	plc := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/"+inventory.target.RepoDID {
			t.Errorf("unexpected PLC path %q", request.URL.Path)
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"id": inventory.target.RepoDID,
			"verificationMethod": []map[string]string{{
				"id": inventory.target.RepoDID + "#atproto", "type": "Multikey",
				"controller": inventory.target.RepoDID, "publicKeyMultibase": publicKey.Multibase(),
			}},
			"service": []map[string]string{{
				"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": inventory.target.Origin,
			}},
		})
	}))
	t.Cleanup(plc.Close)
	resolver, err := spacecredential.NewPLCSigningKeyResolver(plc.URL, true)
	if err != nil {
		t.Fatal(err)
	}

	latest, car := encodeSyntheticSource(t, inventory, privateKey)
	credentials := &syntheticSourceCredentials{t: t, target: inventory.target, latest: latest, car: car, blobs: blobs}
	client, err := officialspaces.New(officialspaces.Config{
		Origin: inventory.target.Origin, SpaceAuthorityDID: "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
		RepoDID: inventory.target.RepoDID, SpaceKey: "primary", Epoch: officialspaces.PinnedEpoch,
		RepoSigningKeys: resolver,
	}, credentials, credentials)
	if err != nil {
		t.Fatal(err)
	}
	return client, credentials
}

type syntheticSourceCredentials struct {
	t        *testing.T
	target   officialspaces.Target
	latest   string
	after    string
	car      []byte
	blobs    map[string][]byte
	acquired int
	closed   int
	blobGets int
}

func (source *syntheticSourceCredentials) AcquireReader(_ context.Context, target officialspaces.Target) (officialspaces.ScopedDoer, error) {
	if target != source.target {
		return nil, errors.New("synthetic source target mismatch")
	}
	source.acquired++
	return &syntheticSourceDoer{source: source, acquisition: source.acquired}, nil
}

func (source *syntheticSourceCredentials) AcquireWriter(context.Context, officialspaces.Target) (officialspaces.ScopedDoer, error) {
	return nil, errors.New("synthetic writer must remain unused")
}

type syntheticSourceDoer struct {
	source      *syntheticSourceCredentials
	acquisition int
	calls       int
}

func (doer *syntheticSourceDoer) Do(_ context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	doer.calls++
	var contentType string
	var body []byte
	if doer.acquisition > 1 {
		switch {
		case doer.calls == 1:
			if endpoint != "com.atproto.space.getLatestCommit" {
				doer.source.t.Fatalf("blob pre-read endpoint=%q", endpoint)
			}
			contentType, body = "application/json", []byte(doer.source.latest)
		case doer.calls == len(doer.source.blobs)+2:
			if endpoint != "com.atproto.space.getLatestCommit" {
				doer.source.t.Fatalf("blob post-read endpoint=%q", endpoint)
			}
			latest := doer.source.after
			if latest == "" {
				latest = doer.source.latest
			}
			contentType, body = "application/json", []byte(latest)
		default:
			if endpoint != "com.atproto.space.getBlob" {
				doer.source.t.Fatalf("blob endpoint=%q", endpoint)
			}
			blobCID := request.URL.Query().Get("cid")
			data, ok := doer.source.blobs[blobCID]
			if !ok {
				doer.source.t.Fatalf("unexpected blob CID %q", blobCID)
			}
			doer.source.blobGets++
			contentType, body = mailbox.MessageMIMEType, data
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}},
			Body: io.NopCloser(bytes.NewReader(body)), Request: request,
		}, nil
	}
	switch doer.calls {
	case 1, 3:
		if endpoint != "com.atproto.space.getLatestCommit" {
			doer.source.t.Fatalf("call %d endpoint=%q", doer.calls, endpoint)
		}
		contentType, body = "application/json", []byte(doer.source.latest)
	case 2:
		if endpoint != "com.atproto.space.getRepo" || request.URL.Query().Get("excludeValues") != "false" {
			doer.source.t.Fatalf("repo endpoint=%q URL=%s", endpoint, request.URL)
		}
		contentType, body = "application/vnd.ipld.car", doer.source.car
	default:
		doer.source.t.Fatalf("unexpected source call %d", doer.calls)
	}
	return &http.Response{
		StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}},
		Body: io.NopCloser(bytes.NewReader(body)), Request: request,
	}, nil
}

func (doer *syntheticSourceDoer) Close() {
	if doer.acquisition == 1 && doer.calls != 3 {
		doer.source.t.Errorf("source credential closed after %d calls", doer.calls)
	}
	doer.source.closed++
}

type syntheticCommit struct {
	hash, ikm, signature, mac []byte
	revision                  string
}

func encodeSyntheticSource(t *testing.T, inventory officialSpacesInventory, privateKey atcrypto.PrivateKey) (string, []byte) {
	t.Helper()
	records := append([]officialspaces.SourceRecord(nil), inventory.records...)
	sort.Slice(records, func(left, right int) bool {
		leftPath := records[left].Collection + "/" + records[left].RKey
		rightPath := records[right].Collection + "/" + records[right].RKey
		if len(leftPath) != len(rightPath) {
			return len(leftPath) < len(rightPath)
		}
		return leftPath < rightPath
	})
	indexNode := fluent.MustBuildMap(basicnode.Prototype.Any, int64(len(records)), func(index fluent.MapAssembler) {
		for _, record := range records {
			recordCID, err := cid.Parse(record.CID)
			if err != nil {
				t.Fatal(err)
			}
			index.AssembleEntry(record.Collection + "/" + record.RKey).AssignLink(cidlink.Link{Cid: recordCID})
		}
	})
	indexBytes := encodeSyntheticNode(t, indexNode)
	indexCID := sourceDAGCBORCID(t, indexBytes)

	hash := syntheticLtHash(records)
	ikm := bytes.Repeat([]byte{0x72}, sha256.Size)
	commitContext := []byte("atproto-space-v1")
	for _, field := range [][]byte{[]byte(inventory.target.SpaceURI), []byte(inventory.target.RepoDID), []byte(inventory.revision), ikm} {
		commitContext = binary.BigEndian.AppendUint16(commitContext, uint16(len(field)))
		commitContext = append(commitContext, field...)
	}
	signature, err := privateKey.HashAndSign(commitContext)
	if err != nil {
		t.Fatal(err)
	}
	expander := hmac.New(sha256.New, ikm)
	_, _ = expander.Write(commitContext)
	_, _ = expander.Write([]byte{1})
	macKey := expander.Sum(nil)
	macHash := hmac.New(sha256.New, macKey)
	_, _ = macHash.Write(hash[:])
	commit := syntheticCommit{hash: hash[:], ikm: ikm, signature: signature, mac: macHash.Sum(nil), revision: inventory.revision}
	commitBytes := encodeSyntheticNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 6, func(value fluent.MapAssembler) {
		value.AssembleEntry("ver").AssignInt(1)
		value.AssembleEntry("hash").AssignBytes(commit.hash)
		value.AssembleEntry("ikm").AssignBytes(commit.ikm)
		value.AssembleEntry("sig").AssignBytes(commit.signature)
		value.AssembleEntry("mac").AssignBytes(commit.mac)
		value.AssembleEntry("rev").AssignString(commit.revision)
	}))
	commitCID := sourceDAGCBORCID(t, commitBytes)
	header := encodeSyntheticNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 2, func(value fluent.MapAssembler) {
		value.AssembleEntry("roots").CreateList(2, func(roots fluent.ListAssembler) {
			roots.AssembleValue().AssignLink(cidlink.Link{Cid: commitCID})
			roots.AssembleValue().AssignLink(cidlink.Link{Cid: indexCID})
		})
		value.AssembleEntry("version").AssignInt(1)
	}))
	car := appendSyntheticCARSection(nil, header)
	car = appendSyntheticCARBlock(car, commitCID, commitBytes)
	car = appendSyntheticCARBlock(car, indexCID, indexBytes)
	for _, record := range records {
		recordCID, err := cid.Parse(record.CID)
		if err != nil {
			t.Fatal(err)
		}
		car = appendSyntheticCARBlock(car, recordCID, record.Value)
	}
	latestBytes, err := json.Marshal(map[string]any{"commit": map[string]any{
		"$type": "com.atproto.space.defs#signedCommit",
		"ver":   1, "hash": syntheticLexBytes(commit.hash), "ikm": syntheticLexBytes(commit.ikm),
		"sig": syntheticLexBytes(commit.signature), "mac": syntheticLexBytes(commit.mac), "rev": commit.revision,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return string(latestBytes), car
}

func syntheticLtHash(records []officialspaces.SourceRecord) [sha256.Size]byte {
	var state [2048]byte
	for _, record := range records {
		digest := blake3.New(0, nil)
		_, _ = io.WriteString(digest, record.Collection+"/"+record.RKey+"/"+record.CID)
		expanded := make([]byte, len(state))
		_, _ = io.ReadFull(digest.XOF(), expanded)
		for offset := 0; offset < len(state); offset += 2 {
			current := binary.LittleEndian.Uint16(state[offset : offset+2])
			addition := binary.LittleEndian.Uint16(expanded[offset : offset+2])
			binary.LittleEndian.PutUint16(state[offset:offset+2], current+addition)
		}
	}
	return sha256.Sum256(state[:])
}

func syntheticLexBytes(value []byte) map[string]string {
	return map[string]string{"$bytes": base64.RawStdEncoding.EncodeToString(value)}
}

func encodeSyntheticNode(t *testing.T, node datamodel.Node) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := (dagcbor.EncodeOptions{AllowLinks: true, MapSortMode: codec.MapSortMode_RFC7049}).Encode(node, &output); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func appendSyntheticCARBlock(output []byte, blockCID cid.Cid, value []byte) []byte {
	section := append(append([]byte(nil), blockCID.Bytes()...), value...)
	return appendSyntheticCARSection(output, section)
}

func appendSyntheticCARSection(output, value []byte) []byte {
	var prefix [binary.MaxVarintLen64]byte
	size := binary.PutUvarint(prefix[:], uint64(len(value)))
	output = append(output, prefix[:size]...)
	return append(output, value...)
}
