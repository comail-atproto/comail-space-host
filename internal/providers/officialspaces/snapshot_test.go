package officialspaces

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime/codec"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/fluent"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	"github.com/multiformats/go-multihash"
)

const testRepoRevision = "3jzfcijpj2z2a"

func TestLtHashMatchesPinnedUpstreamVectors(t *testing.T) {
	tests := []struct {
		name     string
		elements []string
		want     string
	}{
		{name: "empty", want: "e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad"},
		{name: "one and two", elements: []string{"one", "two"}, want: "ae05cb6d224379d9710c290c8529945c5b0e0fde9ead30b9699057ce701c63e7"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ltHashDigest(test.elements)
			if hex.EncodeToString(got[:]) != test.want {
				t.Fatalf("digest=%x want=%s", got, test.want)
			}
		})
	}
}

func TestReadAuthenticatedRepositoryUsesStablePinnedSource(t *testing.T) {
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			calls++
			switch calls {
			case 1, 3:
				if endpoint != getLatestCommitEndpoint {
					t.Fatalf("call %d endpoint=%q", calls, endpoint)
				}
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			case 2:
				if endpoint != getRepoEndpoint || request.URL.Query().Get("excludeValues") != "false" {
					t.Fatalf("repo request=%s endpoint=%q", request.URL, endpoint)
				}
				return rawBytesResponse(request, http.StatusOK, "application/vnd.ipld.car", fixture.car), nil
			default:
				t.Fatalf("unexpected call %d", calls)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}

	snapshot, err := client.ReadSourceAuthenticatedRepository(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reader.closed != 1 || snapshot == nil || snapshot.Revision() != testRepoRevision {
		t.Fatalf("closed=%d snapshot=%v", reader.closed, snapshot)
	}
	if got := snapshot.Target(); got.Origin != "https://spaces.example" || got.SpaceURI != testSpaceURI || got.RepoDID != testDID || got.Epoch != PinnedEpoch {
		t.Fatalf("target=%+v", got)
	}
	records := snapshot.Records()
	if len(records) != 3 || records[0].Collection != "email.atmos.message" || records[0].RKey != "a" || records[0].CID == "" {
		t.Fatalf("records=%+v", records)
	}
	records[0].Value[0] ^= 0xff
	if bytes.Equal(records[0].Value, snapshot.Records()[0].Value) {
		t.Fatal("record bytes escaped without a defensive copy")
	}
	if snapshot.SnapshotID() == "" || snapshot.CommitCID() == "" || snapshot.IndexCID() == "" {
		t.Fatalf("snapshot identifiers are incomplete: %#v", snapshot)
	}
	snapshot.records[0].Value[0] ^= 0xff
	if !errors.Is(snapshot.ValidateSeal(), ErrSnapshotVerification) || snapshot.Records() != nil {
		t.Fatal("mutated source capability retained authority")
	}
}

func TestReadAuthenticatedRepositoryRejectsDriftAndIncompleteCAR(t *testing.T) {
	fixture := newRepoFixture(t)
	drifted := fixture.commit
	driftedHash := sha256.Sum256([]byte("different authenticated PDS state"))
	drifted.Hash = driftedHash[:]
	drifted.MAC = computeCommitMAC(drifted.IKM, commitContext(testSpaceURI, testDID, drifted.Revision, drifted.IKM), drifted.Hash)
	driftJSON := encodeLatestJSON(t, drifted)

	tests := []struct {
		name      string
		car       []byte
		afterJSON string
	}{
		{name: "latest state changed", car: fixture.car, afterJSON: driftJSON},
		{name: "index only", car: fixture.indexOnlyCAR, afterJSON: fixture.latestJSON},
		{name: "extra block", car: appendExtraBlock(t, fixture.car), afterJSON: fixture.latestJSON},
		{name: "reversed roots", car: fixture.reversedRootsCAR, afterJSON: fixture.latestJSON},
		{name: "record blocks out of index order", car: fixture.outOfOrderCAR, afterJSON: fixture.latestJSON},
		{name: "tampered record bytes", car: tamperLastByte(fixture.car), afterJSON: fixture.latestJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
				calls := 0
				return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
					calls++
					switch calls {
					case 1:
						return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
					case 2:
						return rawBytesResponse(request, http.StatusOK, "application/vnd.ipld.car", test.car), nil
					case 3:
						return jsonResponse(request, http.StatusOK, test.afterJSON), nil
					default:
						return nil, errors.New("unexpected call")
					}
				}}
			}}
			client := newTestClient(t, &scriptedDoer{}, reader)
			client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
			if _, err := client.ReadSourceAuthenticatedRepository(context.Background()); !errors.Is(err, ErrSnapshotVerification) {
				t.Fatalf("error=%v", err)
			}
			if reader.closed != 1 {
				t.Fatalf("closed=%d", reader.closed)
			}
		})
	}
}

func TestReadAuthenticatedRepositoryRejectsRepoPDSOriginMismatch(t *testing.T) {
	fixture := newRepoFixture(t)
	reader := &scriptedSource{}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = wrongHostRepoKeyResolver{staticRepoKeyResolver{key: fixture.publicKey}}
	if _, err := client.ReadSourceAuthenticatedRepository(context.Background()); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("error=%v", err)
	}
	if reader.acquired != 0 {
		t.Fatalf("reader acquired before repo PDS origin validation: %d", reader.acquired)
	}
}

// The pinned alpha MAC uses only material serialized with the commit. This
// test prevents a future caller from mistaking commit consistency checks for
// an author signature over the repository hash.
func TestCommitHashBindingIsNotStandaloneAuthorAuthentication(t *testing.T) {
	fixture := newRepoFixture(t)
	forged := fixture.commit
	forgedHash := sha256.Sum256([]byte("replacement record set"))
	forged.Hash = forgedHash[:]
	forged.MAC = computeCommitMAC(forged.IKM, commitContext(testSpaceURI, testDID, forged.Revision, forged.IKM), forged.Hash)
	if !bytes.Equal(forged.Signature, fixture.commit.Signature) {
		t.Fatal("test must retain the original author signature")
	}
	if err := verifyCommitConsistency(context.Background(), forged, Target{
		Origin: "https://spaces.example", SpaceURI: testSpaceURI, RepoDID: testDID, Epoch: PinnedEpoch,
	}, staticRepoKeyResolver{key: fixture.publicKey}); err != nil {
		t.Fatalf("the upstream consistency algorithm changed: %v", err)
	}
}

func TestCommitConsistencySupportsPinnedRepoKeyTypes(t *testing.T) {
	p256, err := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	k256, err := atcrypto.ParsePrivateBytesK256(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  atcrypto.PrivateKey
	}{{"p256", p256}, {"k256", k256}} {
		t.Run(test.name, func(t *testing.T) {
			ikm := bytes.Repeat([]byte{0x41}, sha256.Size)
			hash := sha256.Sum256([]byte("synthetic repo state"))
			ctx := commitContext(testSpaceURI, testDID, testRepoRevision, ikm)
			signature, err := test.key.HashAndSign(ctx)
			if err != nil {
				t.Fatal(err)
			}
			public, err := test.key.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			commit := signedRepoCommit{
				Version: 1, Hash: hash[:], IKM: ikm, Signature: signature,
				MAC: computeCommitMAC(ikm, ctx, hash[:]), Revision: testRepoRevision,
			}
			if err := verifyCommitConsistency(context.Background(), commit, Target{
				Origin: "https://spaces.example", SpaceURI: testSpaceURI, RepoDID: testDID, Epoch: PinnedEpoch,
			}, staticRepoKeyResolver{key: public}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommitConsistencyRejectsMalformedCryptoAndWrongTarget(t *testing.T) {
	fixture := newRepoFixture(t)
	validTarget := Target{
		Origin: "https://spaces.example", SpaceURI: testSpaceURI, RepoDID: testDID, Epoch: PinnedEpoch,
	}
	otherPrivate, err := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := otherPrivate.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	badMAC := cloneSignedCommit(fixture.commit)
	badMAC.MAC[0] ^= 0x01
	badSignature := cloneSignedCommit(fixture.commit)
	badSignature.Signature[0] ^= 0x01
	badHashLength := cloneSignedCommit(fixture.commit)
	badHashLength.Hash = badHashLength.Hash[:sha256.Size-1]
	badIKMLength := cloneSignedCommit(fixture.commit)
	badIKMLength.IKM = badIKMLength.IKM[:sha256.Size-1]
	badMACLength := cloneSignedCommit(fixture.commit)
	badMACLength.MAC = badMACLength.MAC[:sha256.Size-1]
	badSignatureLength := cloneSignedCommit(fixture.commit)
	badSignatureLength.Signature = badSignatureLength.Signature[:63]
	badVersion := cloneSignedCommit(fixture.commit)
	badVersion.Version++
	badRevision := cloneSignedCommit(fixture.commit)
	badRevision.Revision = "not-a-tid"

	tests := []struct {
		name     string
		commit   signedRepoCommit
		target   Target
		resolver repoSigningKeyResolver
	}{
		{name: "bad MAC", commit: badMAC, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "bad signature", commit: badSignature, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "wrong key", commit: fixture.commit, target: validTarget, resolver: staticRepoKeyResolver{key: otherPublic}},
		{name: "short hash", commit: badHashLength, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "short IKM", commit: badIKMLength, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "short MAC", commit: badMACLength, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "short signature", commit: badSignatureLength, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "wrong version", commit: badVersion, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "malformed revision", commit: badRevision, target: validTarget, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "wrong space", commit: fixture.commit, target: Target{Origin: validTarget.Origin, SpaceURI: validTarget.SpaceURI + "-other", RepoDID: validTarget.RepoDID, Epoch: validTarget.Epoch}, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "wrong author", commit: fixture.commit, target: Target{Origin: validTarget.Origin, SpaceURI: validTarget.SpaceURI, RepoDID: "did:plc:cccccccccccccccccccccccc", Epoch: validTarget.Epoch}, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
		{name: "wrong epoch", commit: fixture.commit, target: Target{Origin: validTarget.Origin, SpaceURI: validTarget.SpaceURI, RepoDID: validTarget.RepoDID, Epoch: "other"}, resolver: staticRepoKeyResolver{key: fixture.publicKey}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyCommitConsistency(context.Background(), test.commit, test.target, test.resolver); !errors.Is(err, ErrSnapshotVerification) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCommitContextAndMACMatchIndependentNodeCryptoVector(t *testing.T) {
	space := "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/email.atmos.mailbox/primary"
	author := "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	ikm := bytes.Repeat([]byte{0x41}, sha256.Size)
	hash := sha256.Sum256([]byte("synthetic repo state"))
	contextBytes := commitContext(space, author, testRepoRevision, ikm)
	if got := hex.EncodeToString(contextBytes); got != "617470726f746f2d73706163652d7631004761743a2f2f6469643a706c633a6161616161616161616161616161616161616161616161612f73706163652f656d61696c2e61746d6f732e6d61696c626f782f7072696d61727900206469643a706c633a626262626262626262626262626262626262626262626262000d336a7a6663696a706a327a326100204141414141414141414141414141414141414141414141414141414141414141" {
		t.Fatalf("context=%s", got)
	}
	if got := hex.EncodeToString(computeCommitMAC(ikm, contextBytes, hash[:])); got != "5c014a1049c76d0619e46b809a376a4605c3cc72f6505d34a281bc8cffd572b1" {
		t.Fatalf("mac=%s", got)
	}
}

func TestCommitConsistencyRejectsAtomicKeyAndRepoHostMove(t *testing.T) {
	current, _ := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x52}, 32))
	currentPublic, _ := current.PublicKey()
	ikm := bytes.Repeat([]byte{0x53}, sha256.Size)
	hash := sha256.Sum256([]byte("synthetic rotated repo state"))
	ctx := commitContext(testSpaceURI, testDID, testRepoRevision, ikm)
	signature, err := current.HashAndSign(ctx)
	if err != nil {
		t.Fatal(err)
	}
	commit := signedRepoCommit{
		Version: 1, Hash: hash[:], IKM: ikm, Signature: signature,
		MAC: computeCommitMAC(ikm, ctx, hash[:]), Revision: testRepoRevision,
	}
	resolver := &movedRepoResolver{current: currentPublic}
	if err := verifyCommitConsistency(context.Background(), commit, Target{
		Origin: "https://spaces.example", SpaceURI: testSpaceURI, RepoDID: testDID, Epoch: PinnedEpoch,
	}, resolver); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("error=%v", err)
	}
	if !resolver.resolved {
		t.Fatal("test did not exercise atomic repo source resolution")
	}
}

func TestCanonicalDAGCBORRejectsDuplicateAndUnsortedKeys(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "duplicate", value: []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}},
		{name: "unsorted", value: []byte{0xa2, 0x64, 'l', 'o', 'n', 'g', 0x01, 0x61, 'a', 0x02}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeCanonicalDAGCBOR(test.value); err == nil {
				t.Fatal("expected strict DAG-CBOR rejection")
			}
		})
	}
}

func TestCanonicalDAGCBORBoundsStructuralDepthBeforeDecode(t *testing.T) {
	boundary := append(bytes.Repeat([]byte{0x81}, maxCBORNestingDepth), 0xf6)
	if _, err := decodeCanonicalDAGCBOR(boundary); err != nil {
		t.Fatalf("boundary depth rejected: %v", err)
	}
	tooDeep := append(bytes.Repeat([]byte{0x81}, maxCBORNestingDepth+1), 0xf6)
	if _, err := decodeCanonicalDAGCBOR(tooDeep); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("deep nesting error=%v", err)
	}
	wide := []byte{0x9a}
	wide = binary.BigEndian.AppendUint32(wide, uint32(maxCBORDataItems))
	wide = append(wide, bytes.Repeat([]byte{0xf6}, maxCBORDataItems)...)
	if _, err := decodeCanonicalDAGCBOR(wide); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("wide value error=%v", err)
	}
}

func TestStrictJSONBytesRejectsUnknownAndNonCanonicalEncoding(t *testing.T) {
	for _, encoded := range []string{
		`{"$bytes":"YQ","extra":true}`,
		`{"$bytes":"YQ=="}`,
		`{"$bytes":""}`,
	} {
		var value strictJSONBytes
		if err := json.Unmarshal([]byte(encoded), &value); err == nil {
			t.Fatalf("accepted %s", encoded)
		}
	}
}

func TestCARBlockRejectsRecordOverLimit(t *testing.T) {
	value := bytes.Repeat([]byte{0x01}, maxRecordBlockBytes+1)
	blockCID := dagCBORCID(t, value)
	section := append(append([]byte(nil), blockCID.Bytes()...), value...)
	reader := bufio.NewReader(bytes.NewReader(appendCARSection(nil, section)))
	if _, _, err := readCARBlock(reader, maxRecordBlockBytes); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("error=%v", err)
	}
}

func TestCARSectionRejectsNonCanonicalVarint(t *testing.T) {
	reader := bufio.NewReader(bytes.NewReader([]byte{0x81, 0x00, 0x01}))
	if _, err := readCARSection(reader, 10); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("error=%v", err)
	}
}

func TestRepoIndexRejectsCollectionsOutsideExactMailboxProfile(t *testing.T) {
	record := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 1, func(m fluent.MapAssembler) {
		m.AssembleEntry("$type").AssignString("app.example.other")
	}))
	recordCID := dagCBORCID(t, record)
	index := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 1, func(m fluent.MapAssembler) {
		m.AssembleEntry("app.example.other/one").AssignLink(cidlink.Link{Cid: recordCID})
	}))
	if _, _, err := parseRepoIndex(index); !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("error=%v", err)
	}
}

func TestRepoIndexAcceptsOnlyTheFiveMailboxCollections(t *testing.T) {
	collections := []string{
		"email.atmos.message",
		"email.atmos.messageStateRevision",
		"email.atmos.messageStateOperation",
		"email.atmos.folderRevision",
		"email.atmos.folderOperation",
	}
	record := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 1, func(m fluent.MapAssembler) {
		m.AssembleEntry("$type").AssignString("email.atmos.message")
	}))
	recordCID := dagCBORCID(t, record)
	index := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, int64(len(collections)), func(m fluent.MapAssembler) {
		for _, collection := range collections {
			m.AssembleEntry(collection + "/one").AssignLink(cidlink.Link{Cid: recordCID})
		}
	}))
	entries, _, err := parseRepoIndex(index)
	if err != nil || len(entries) != len(collections) {
		t.Fatalf("entries=%d error=%v", len(entries), err)
	}
}

func TestFullSourceCARRejectsCommitHashForDifferentRecordSet(t *testing.T) {
	fixture := newRepoFixture(t)
	_, err := verifyFullSourceCAR(context.Background(), bytes.NewReader(fixture.mismatchedSetHashCAR), Target{
		Origin: "https://spaces.example", SpaceURI: testSpaceURI, RepoDID: testDID, Epoch: PinnedEpoch,
	}, staticRepoKeyResolver{key: fixture.publicKey})
	if !errors.Is(err, ErrSnapshotVerification) {
		t.Fatalf("error=%v", err)
	}
}

type repoFixture struct {
	car                  []byte
	indexOnlyCAR         []byte
	reversedRootsCAR     []byte
	outOfOrderCAR        []byte
	mismatchedSetHashCAR []byte
	latestJSON           string
	commit               signedRepoCommit
	publicKey            atcrypto.PublicKey
}

func newRepoFixture(t *testing.T) repoFixture {
	t.Helper()
	privateKey, err := atcrypto.ParsePrivateBytesP256(bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	type fixtureRecord struct {
		path  string
		value []byte
		cid   cid.Cid
	}
	records := []fixtureRecord{
		{path: "email.atmos.messageStateRevision/middle"},
		{path: "email.atmos.message/a"},
		{path: "email.atmos.folderOperation/longer"},
	}
	for index := range records {
		collection, _, ok := parseRecordPath(records[index].path)
		if !ok {
			t.Fatalf("invalid fixture path %q", records[index].path)
		}
		records[index].value = encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 2, func(m fluent.MapAssembler) {
			m.AssembleEntry("text").AssignString("synthetic")
			m.AssembleEntry("$type").AssignString(collection)
		}))
		records[index].cid = dagCBORCID(t, records[index].value)
	}
	sort.Slice(records, func(left, right int) bool {
		if len(records[left].path) != len(records[right].path) {
			return len(records[left].path) < len(records[right].path)
		}
		return records[left].path < records[right].path
	})
	index := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, int64(len(records)), func(m fluent.MapAssembler) {
		for _, record := range records {
			m.AssembleEntry(record.path).AssignLink(cidlink.Link{Cid: record.cid})
		}
	}))
	indexCID := dagCBORCID(t, index)
	hashElements := make([]string, len(records))
	for index, record := range records {
		hashElements[index] = record.path + "/" + record.cid.String()
	}
	hash := ltHashDigest(hashElements)
	ikm := bytes.Repeat([]byte{0x22}, sha256.Size)
	ctx := commitContext(testSpaceURI, testDID, testRepoRevision, ikm)
	signature, err := privateKey.HashAndSign(ctx)
	if err != nil {
		t.Fatal(err)
	}
	commit := signedRepoCommit{
		Version: 1, Hash: hash[:], IKM: ikm, Signature: signature,
		MAC: computeCommitMAC(ikm, ctx, hash[:]), Revision: testRepoRevision,
	}
	commitBytes := encodeCommitNode(t, commit)
	commitCID := dagCBORCID(t, commitBytes)
	blocks := []carBlock{{commitCID, commitBytes}, {indexCID, index}}
	for _, record := range records {
		blocks = append(blocks, carBlock{record.cid, record.value})
	}
	outOfOrderBlocks := append([]carBlock(nil), blocks...)
	outOfOrderBlocks[2], outOfOrderBlocks[3] = outOfOrderBlocks[3], outOfOrderBlocks[2]
	mismatchedCommit := cloneSignedCommit(commit)
	mismatchedHash := sha256.Sum256([]byte("different internally consistent record set"))
	mismatchedCommit.Hash = mismatchedHash[:]
	mismatchedCommit.MAC = computeCommitMAC(mismatchedCommit.IKM, ctx, mismatchedCommit.Hash)
	mismatchedCommitBytes := encodeCommitNode(t, mismatchedCommit)
	mismatchedCommitCID := dagCBORCID(t, mismatchedCommitBytes)
	mismatchedBlocks := append([]carBlock{{mismatchedCommitCID, mismatchedCommitBytes}, {indexCID, index}}, blocks[2:]...)
	return repoFixture{
		car:                  encodeCAR(t, []cid.Cid{commitCID, indexCID}, blocks),
		indexOnlyCAR:         encodeCAR(t, []cid.Cid{commitCID, indexCID}, []carBlock{{commitCID, commitBytes}, {indexCID, index}}),
		reversedRootsCAR:     encodeCAR(t, []cid.Cid{indexCID, commitCID}, blocks),
		outOfOrderCAR:        encodeCAR(t, []cid.Cid{commitCID, indexCID}, outOfOrderBlocks),
		mismatchedSetHashCAR: encodeCAR(t, []cid.Cid{mismatchedCommitCID, indexCID}, mismatchedBlocks),
		latestJSON:           encodeLatestJSON(t, commit),
		commit:               commit,
		publicKey:            publicKey,
	}
}

func cloneSignedCommit(input signedRepoCommit) signedRepoCommit {
	result := input
	result.Hash = append([]byte(nil), input.Hash...)
	result.IKM = append([]byte(nil), input.IKM...)
	result.Signature = append([]byte(nil), input.Signature...)
	result.MAC = append([]byte(nil), input.MAC...)
	return result
}

func tamperLastByte(input []byte) []byte {
	result := append([]byte(nil), input...)
	result[len(result)-1] ^= 0x01
	return result
}

func encodeCommitNode(t *testing.T, commit signedRepoCommit) []byte {
	t.Helper()
	node := fluent.MustBuildMap(basicnode.Prototype.Any, 6, func(m fluent.MapAssembler) {
		m.AssembleEntry("ver").AssignInt(commit.Version)
		m.AssembleEntry("hash").AssignBytes(commit.Hash)
		m.AssembleEntry("ikm").AssignBytes(commit.IKM)
		m.AssembleEntry("sig").AssignBytes(commit.Signature)
		m.AssembleEntry("mac").AssignBytes(commit.MAC)
		m.AssembleEntry("rev").AssignString(commit.Revision)
	})
	return encodeNode(t, node)
}

func encodeNode(t *testing.T, node datamodel.Node) []byte {
	t.Helper()
	var output bytes.Buffer
	if err := (dagcbor.EncodeOptions{AllowLinks: true, MapSortMode: codec.MapSortMode_RFC7049}).Encode(node, &output); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func dagCBORCID(t *testing.T, value []byte) cid.Cid {
	t.Helper()
	result, err := (cid.Prefix{Version: 1, Codec: cid.DagCBOR, MhType: multihash.SHA2_256, MhLength: -1}).Sum(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type carBlock struct {
	cid   cid.Cid
	value []byte
}

func encodeCAR(t *testing.T, roots []cid.Cid, blocks []carBlock) []byte {
	t.Helper()
	header := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 2, func(m fluent.MapAssembler) {
		m.AssembleEntry("roots").CreateList(int64(len(roots)), func(list fluent.ListAssembler) {
			for _, root := range roots {
				list.AssembleValue().AssignLink(cidlink.Link{Cid: root})
			}
		})
		m.AssembleEntry("version").AssignInt(1)
	}))
	var output []byte
	output = appendCARSection(output, header)
	for _, block := range blocks {
		section := append(append([]byte(nil), block.cid.Bytes()...), block.value...)
		output = appendCARSection(output, section)
	}
	return output
}

func appendExtraBlock(t *testing.T, input []byte) []byte {
	t.Helper()
	value := encodeNode(t, fluent.MustBuildMap(basicnode.Prototype.Any, 1, func(m fluent.MapAssembler) {
		m.AssembleEntry("$type").AssignString("email.atmos.message")
	}))
	result := append([]byte(nil), input...)
	section := append(append([]byte(nil), dagCBORCID(t, value).Bytes()...), value...)
	return append(result, appendCARSection(nil, section)...)
}

func appendCARSection(output, section []byte) []byte {
	var prefix [binary.MaxVarintLen64]byte
	count := binary.PutUvarint(prefix[:], uint64(len(section)))
	output = append(output, prefix[:count]...)
	return append(output, section...)
}

func encodeLatestJSON(t *testing.T, commit signedRepoCommit) string {
	t.Helper()
	value := struct {
		Commit struct {
			Version   int64            `json:"ver"`
			Hash      lexutil.LexBytes `json:"hash"`
			IKM       lexutil.LexBytes `json:"ikm"`
			Signature lexutil.LexBytes `json:"sig"`
			MAC       lexutil.LexBytes `json:"mac"`
			Revision  string           `json:"rev"`
		} `json:"commit"`
	}{}
	value.Commit.Version = commit.Version
	value.Commit.Hash = commit.Hash
	value.Commit.IKM = commit.IKM
	value.Commit.Signature = commit.Signature
	value.Commit.MAC = commit.MAC
	value.Commit.Revision = commit.Revision
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func rawBytesResponse(request *http.Request, status int, contentType string, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status, Header: http.Header{"Content-Type": {contentType}},
		Body: io.NopCloser(bytes.NewReader(body)), Request: request,
	}
}

type staticRepoKeyResolver struct {
	key atcrypto.PublicKey
}

type wrongHostRepoKeyResolver struct{ staticRepoKeyResolver }

func (r wrongHostRepoKeyResolver) ResolveRepoSource(ctx context.Context, did syntax.DID, force bool) (string, atcrypto.PublicKey, error) {
	_, key, err := r.staticRepoKeyResolver.ResolveRepoSource(ctx, did, force)
	return "https://other.example", key, err
}

type movedRepoResolver struct {
	current  atcrypto.PublicKey
	resolved bool
}

func (r *movedRepoResolver) ResolveRepoSource(_ context.Context, did syntax.DID, _ bool) (string, atcrypto.PublicKey, error) {
	if did.String() != testDID {
		return "", nil, errors.New("unexpected repo DID")
	}
	r.resolved = true
	return "https://moved.example", r.current, nil
}

func (r staticRepoKeyResolver) ResolveRepoSource(_ context.Context, did syntax.DID, _ bool) (string, atcrypto.PublicKey, error) {
	if did.String() != testDID || r.key == nil {
		return "", nil, errors.New("unexpected repo DID")
	}
	return "https://spaces.example", r.key, nil
}
