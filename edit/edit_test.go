package edit

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRemoveBattlEyeAppliesAllKnownWindowsPatches(t *testing.T) {
	tibiaBinary := newPEBinary()
	tibiaBinary = append(tibiaBinary, []byte("BattlEye--")...)
	tibiaBinary = append(tibiaBinary, []byte{0x8d, 0x4d, 0xb4, 0x75, 0x0e, 0xe8, 0xb4, 0x53}...)
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48}...)
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}...)

	patched := removeBattlEye("client.exe", tibiaBinary, false)

	if bytes.Contains(patched, []byte{0x8d, 0x4d, 0xb4, 0x75, 0x0e, 0xe8, 0xb4, 0x53}) {
		t.Fatal("expected legacy Battleye bytes to be patched")
	}
	if bytes.Contains(patched, []byte{0x75, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48}) {
		t.Fatal("expected first Battleye bytes to be patched")
	}
	if bytes.Contains(patched, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}) {
		t.Fatal("expected second Battleye bytes to be patched")
	}
	if !bytes.Contains(patched, []byte{0x8d, 0x4d, 0xb4, 0xeb, 0x0e, 0xe8, 0xb4, 0x53}) {
		t.Fatal("expected legacy patched Battleye bytes")
	}
	if !bytes.Contains(patched, []byte{0xeb, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48}) {
		t.Fatal("expected first patched Battleye bytes")
	}
	if !bytes.Contains(patched, []byte{0xeb, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}) {
		t.Fatal("expected second patched Battleye bytes")
	}
}

func TestRemoveBattlEyeSkipsNonWindowsExecutable(t *testing.T) {
	tibiaBinary := []byte("ELF--BattlEye--")
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}...)
	original := append([]byte(nil), tibiaBinary...)

	patched := removeBattlEye("client.exe", tibiaBinary, false)

	if !bytes.Equal(patched, original) {
		t.Fatal("expected non-Windows executable to be unchanged")
	}
}

func TestRemoveBattlEyeSkipsMZWithoutPESignature(t *testing.T) {
	tibiaBinary := []byte("MZ--BattlEye--")
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}...)
	original := append([]byte(nil), tibiaBinary...)

	patched := removeBattlEye("client.exe", tibiaBinary, false)

	if !bytes.Equal(patched, original) {
		t.Fatal("expected MZ-only executable to be unchanged")
	}
}

func TestBytePatternFindAllSupportsWildcards(t *testing.T) {
	pattern := newBytePattern("test", 0x75, wildcardByte, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte)
	offsets := pattern.findAll([]byte{0x90, 0x75, 0x04, 0xe8, 0x01, 0x02, 0x03, 0x04, 0x90})

	if len(offsets) != 1 || offsets[0] != 1 {
		t.Fatalf("expected wildcard pattern at offset 1, got %v", offsets)
	}
}

func TestClientCheckStrongUnsupportedEvidenceRequiresUnknownCodeContext(t *testing.T) {
	tibiaBinary, peData, referenceOffset := newClientCheckReferenceFixture("clientcheck_disconnected")

	findings := scanClientCheckFindings(tibiaBinary, peData, nil)
	diagnosis := diagnosisReport{clientCheckFindings: findings}

	if diagnosis.strongUnsupportedEvidenceCount() != 1 {
		t.Fatalf("expected one strong unsupported client-check evidence, got %d", diagnosis.strongUnsupportedEvidenceCount())
	}

	patchStatuses := []battleyePatchStatus{
		{patch: battleyePatches[0], originalOffset: []int{referenceOffset + 8}},
	}
	findings = scanClientCheckFindings(tibiaBinary, peData, patchStatuses)
	diagnosis = diagnosisReport{clientCheckFindings: findings}

	if diagnosis.strongUnsupportedEvidenceCount() != 0 {
		t.Fatalf("expected known nearby patch signature to suppress unsupported evidence, got %d", diagnosis.strongUnsupportedEvidenceCount())
	}
}

func TestBEClientReferenceIsWeakIndicator(t *testing.T) {
	tibiaBinary, peData, _ := newClientCheckReferenceFixture("BEClient")

	findings := scanClientCheckFindings(tibiaBinary, peData, nil)
	diagnosis := diagnosisReport{clientCheckFindings: findings}

	if diagnosis.strongUnsupportedEvidenceCount() != 0 {
		t.Fatalf("expected BEClient to remain weak, got %d strong evidence item(s)", diagnosis.strongUnsupportedEvidenceCount())
	}
}

func TestSuspiciousActiveEvidenceRequiresPatchedSignatureForWarningVerdict(t *testing.T) {
	tibiaBinary, peData, _ := newClientCheckReferenceFixtureWithoutRecognizedPattern("clientcheck_disconnected")

	findings := scanClientCheckFindings(tibiaBinary, peData, nil)
	diagnosis := diagnosisReport{
		patchStatuses:       []battleyePatchStatus{{patch: battleyePatches[1], originalOffset: []int{0x180}}},
		clientCheckFindings: findings,
	}

	if diagnosis.strongUnsupportedEvidenceCount() != 0 {
		t.Fatalf("expected no strong unsupported evidence, got %d", diagnosis.strongUnsupportedEvidenceCount())
	}
	if diagnosis.suspiciousActiveEvidenceCount() != 1 {
		t.Fatalf("expected one suspicious active evidence item, got %d", diagnosis.suspiciousActiveEvidenceCount())
	}
	if diagnosis.clientCheckVerdict() != "PARTIAL: only some known patchable signatures are covered" {
		t.Fatalf("expected unpatched known signature to remain PARTIAL, got %q", diagnosis.clientCheckVerdict())
	}

	diagnosis.patchStatuses = []battleyePatchStatus{{patch: battleyePatches[1], patchedOffset: []int{0x180}}}
	if diagnosis.clientCheckVerdict() != "WARNING: known client-check patch applied but suspicious branch/call evidence remains" {
		t.Fatalf("expected patched known signature plus suspicious evidence to become WARNING, got %q", diagnosis.clientCheckVerdict())
	}
}

func TestHighRiskDiagnosticSignatureChangesPatchedVerdict(t *testing.T) {
	diagnosis := diagnosisReport{
		patchStatuses: []battleyePatchStatus{
			{patch: battleyePatches[1], patchedOffset: []int{0x2DE804}},
			{patch: battleyePatch{name: "test high-risk", diagnosticOnly: true, highRiskClientCheck: true}, originalOffset: []int{0x1A8E3D}},
		},
	}

	if diagnosis.clientCheckVerdict() != "WARNING: high risk of client-check remaining after known patch" {
		t.Fatalf("expected high-risk diagnostic signature to change verdict, got %q", diagnosis.clientCheckVerdict())
	}
}

func TestUpdateConfigINIContentSyncsWithEmbeddedClientConfig(t *testing.T) {
	embeddedConfig := mustParseEmbeddedConfigINI(t, []byte("[URLS]\r\nloginWebService=http://127.0.0.1/login.php\r\nclientWebService=http://127.0.0.1/client.php\r\n[SOUND]\r\nfailInitialization=false\r\n"))
	configData := []byte("; keep this comment\r\nunknownKey=keep\r\nloginWebService = old\r\n")

	updated, changedCount, addedCount, removedCount, changed := updateConfigINIContent(configData, embeddedConfig)

	expected := "; keep this comment\r\nunknownKey=keep\r\nloginWebService = old\r\n\r\n[URLS]\r\nloginWebService=http://127.0.0.1/login.php\r\nclientWebService=http://127.0.0.1/client.php\r\n\r\n[SOUND]\r\nfailInitialization=false\r\n"
	if !changed {
		t.Fatal("expected config.ini content to change")
	}
	if changedCount != 0 {
		t.Fatalf("expected no managed section key updates, got %d", changedCount)
	}
	if addedCount != 3 {
		t.Fatalf("expected three missing embedded keys to be appended, got %d", addedCount)
	}
	if removedCount != 0 {
		t.Fatalf("expected no obsolete managed keys to be removed, got %d", removedCount)
	}
	if string(updated) != expected {
		t.Fatalf("unexpected config.ini content:\n%s", string(updated))
	}
}

func TestUpdateConfigINIContentKeepsUpToDateContentUnchanged(t *testing.T) {
	embeddedConfig := mustParseEmbeddedConfigINI(t, []byte("[URLS]\nloginWebService=http://127.0.0.1/login.php\n"))
	configData := []byte("[URLS]\nloginWebService=http://127.0.0.1/login.php\n[LOCAL]\nunknownKey=keep\n")

	updated, changedCount, addedCount, removedCount, changed := updateConfigINIContent(configData, embeddedConfig)

	if changed {
		t.Fatal("expected up-to-date config.ini content to stay unchanged")
	}
	if changedCount != 0 || addedCount != 0 || removedCount != 0 {
		t.Fatalf("expected zero changes, got changed=%d added=%d removed=%d", changedCount, addedCount, removedCount)
	}
	if !bytes.Equal(updated, configData) {
		t.Fatal("expected original config.ini bytes to be preserved")
	}
}

func TestUpdateConfigINIContentUpdatesAndRemovesManagedSectionKeys(t *testing.T) {
	embeddedConfig := mustParseEmbeddedConfigINI(t, []byte("[URLS]\nloginWebService=http://127.0.0.1/login.php\nclientWebService=http://127.0.0.1/client.php\n"))
	configData := []byte("[URLS]\nloginWebService=old\ncreateTournamentCharacterUrl=obsolete\n")

	updated, changedCount, addedCount, removedCount, changed := updateConfigINIContent(configData, embeddedConfig)

	expected := "[URLS]\nloginWebService=http://127.0.0.1/login.php\nclientWebService=http://127.0.0.1/client.php\n"
	if !changed {
		t.Fatal("expected managed config.ini section to be updated")
	}
	if changedCount != 1 {
		t.Fatalf("expected one outdated value, got %d", changedCount)
	}
	if addedCount != 1 {
		t.Fatalf("expected one new key, got %d", addedCount)
	}
	if removedCount != 1 {
		t.Fatalf("expected one obsolete key to be removed, got %d", removedCount)
	}
	if string(updated) != expected {
		t.Fatalf("unexpected config.ini content:\n%s", string(updated))
	}
}

func TestUpdateConfigINIContentCreatesOrderedSectionsFromEmbeddedConfig(t *testing.T) {
	embeddedConfig := mustParseEmbeddedConfigINI(t, []byte("[URLS]\nloginWebService=http://127.0.0.1/login.php\nclientWebService=http://127.0.0.1/client.php\n[SOUND]\nfailInitialization=false\n"))

	updated, changedCount, addedCount, removedCount, changed := updateConfigINIContent(nil, embeddedConfig)

	expected := "[URLS]\nloginWebService=http://127.0.0.1/login.php\nclientWebService=http://127.0.0.1/client.php\n\n[SOUND]\nfailInitialization=false\n"
	if !changed {
		t.Fatal("expected empty config.ini content to be created")
	}
	if changedCount != 0 {
		t.Fatalf("expected no outdated values, got %d", changedCount)
	}
	if addedCount != 3 {
		t.Fatalf("expected three new keys, got %d", addedCount)
	}
	if removedCount != 0 {
		t.Fatalf("expected no obsolete keys, got %d", removedCount)
	}
	if string(updated) != expected {
		t.Fatalf("unexpected config.ini content:\n%s", string(updated))
	}
}

func mustParseEmbeddedConfigINI(t *testing.T, configData []byte) embeddedConfigINI {
	t.Helper()

	embeddedConfig, ok := parseEmbeddedConfigINI(configData)
	if !ok {
		t.Fatal("expected embedded config.ini block to parse")
	}
	return embeddedConfig
}

func newPEBinary() []byte {
	binary := make([]byte, 0x84)
	binary[0] = 'M'
	binary[1] = 'Z'
	binary[0x3c] = 0x80
	binary[0x80] = 'P'
	binary[0x81] = 'E'
	return binary
}

func newClientCheckReferenceFixture(indicator string) ([]byte, peInfo, int) {
	tibiaBinary := make([]byte, 0x420)
	copy(tibiaBinary[0x300:], []byte(indicator))

	peData := peInfo{
		valid: true,
		sections: []peSectionInfo{
			{name: ".text", rawStart: 0x100, rawEnd: 0x200, rvaStart: 0x1000, rvaEnd: 0x1100, isCode: true},
			{name: ".rdata", rawStart: 0x300, rawEnd: 0x420, rvaStart: 0x2000, rvaEnd: 0x2120},
		},
	}

	referenceOffset := 0x120
	referenceRVA := 0x1000 + referenceOffset - 0x100
	stringRVA := 0x2000
	displacement := int32(stringRVA - (referenceRVA + 7))

	tibiaBinary[referenceOffset] = 0x48
	tibiaBinary[referenceOffset+1] = 0x8d
	tibiaBinary[referenceOffset+2] = 0x0d
	binary.LittleEndian.PutUint32(tibiaBinary[referenceOffset+3:referenceOffset+7], uint32(displacement))
	tibiaBinary[referenceOffset+8] = 0x75
	tibiaBinary[referenceOffset+9] = 0x05
	tibiaBinary[referenceOffset+10] = 0xe8
	tibiaBinary[referenceOffset+11] = 0x01
	tibiaBinary[referenceOffset+12] = 0x02
	tibiaBinary[referenceOffset+13] = 0x03
	tibiaBinary[referenceOffset+14] = 0x04

	return tibiaBinary, peData, referenceOffset
}

func newClientCheckReferenceFixtureWithoutRecognizedPattern(indicator string) ([]byte, peInfo, int) {
	tibiaBinary, peData, referenceOffset := newClientCheckReferenceFixture(indicator)
	for index := referenceOffset + 8; index <= referenceOffset+14; index++ {
		tibiaBinary[index] = 0x90
	}

	tibiaBinary[referenceOffset+0x20] = 0x75
	tibiaBinary[referenceOffset+0x21] = 0x05
	tibiaBinary[referenceOffset+0x40] = 0xe8
	tibiaBinary[referenceOffset+0x41] = 0x01
	tibiaBinary[referenceOffset+0x42] = 0x02
	tibiaBinary[referenceOffset+0x43] = 0x03
	tibiaBinary[referenceOffset+0x44] = 0x04

	return tibiaBinary, peData, referenceOffset
}
