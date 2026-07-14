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
	if !bytes.Contains(patched, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}) {
		t.Fatal("expected ambiguous branch bytes to remain unchanged")
	}
	if !bytes.Contains(patched, []byte{0x8d, 0x4d, 0xb4, 0xeb, 0x0e, 0xe8, 0xb4, 0x53}) {
		t.Fatal("expected legacy patched Battleye bytes")
	}
	if !bytes.Contains(patched, []byte{0xeb, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48}) {
		t.Fatal("expected first patched Battleye bytes")
	}
	if bytes.Contains(patched, []byte{0xeb, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}) {
		t.Fatal("expected ambiguous branch not to be rewritten")
	}
}

func TestStructuralClientCheckPairPatchesOnlyVerifiedCallSites(t *testing.T) {
	tibiaBinary, peData, fixture := newStructuralClientCheckFixture(t)
	patches := structuralTestPatches(t)
	plan := buildStructuralPatchPlan(tibiaBinary, peData, patches)
	if !plan.verifiedGroups[structuralClientCheckGroup] {
		t.Fatal("expected the complete structural client-check pair to verify")
	}

	original := append([]byte(nil), tibiaBinary...)
	for patchIndex, patch := range patches {
		match := plan.matches[patchIndex]
		if !match.unique || len(match.originalOffsets) != 1 || len(match.patchedOffsets) != 0 {
			t.Fatalf("expected one original structural match for %q, got %+v", patch.name, match)
		}
		tibiaBinary = applyBattleyePatch(tibiaBinary, patch, match.originalOffsets)
	}

	expectedChanges := make(map[int]bool)
	for offset := fixture.clientCheckOffset + 93; offset <= fixture.clientCheckOffset+97; offset++ {
		expectedChanges[offset] = true
	}
	for offset := fixture.enableClientCheckOffset + 18; offset <= fixture.enableClientCheckOffset+23; offset++ {
		expectedChanges[offset] = true
	}
	for offset := range tibiaBinary {
		changed := tibiaBinary[offset] != original[offset]
		if changed != expectedChanges[offset] {
			t.Fatalf("unexpected structural patch diff at 0x%X: before=%02X after=%02X expectedChange=%t", offset, original[offset], tibiaBinary[offset], expectedChanges[offset])
		}
	}

	patchedPlan := buildStructuralPatchPlan(tibiaBinary, peData, patches)
	if !patchedPlan.verifiedGroups[structuralClientCheckGroup] {
		t.Fatal("expected the patched structural pair to remain verifiable")
	}
	for patchIndex, patch := range patches {
		match := patchedPlan.matches[patchIndex]
		if !match.unique || len(match.originalOffsets) != 0 || len(match.patchedOffsets) != 1 {
			t.Fatalf("expected one patched structural match for %q, got %+v", patch.name, match)
		}
	}
}

func TestStructuralClientCheckPairRejectsWrongAnchorDuplicateAndFunctionBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte, *peInfo, structuralClientCheckFixture)
	}{
		{
			name: "wrong semantic anchor",
			mutate: func(tibiaBinary []byte, _ *peInfo, fixture structuralClientCheckFixture) {
				tibiaBinary[fixture.clientCheckStringOffset] = 'X'
			},
		},
		{
			name: "duplicate clientcheck candidate",
			mutate: func(tibiaBinary []byte, peData *peInfo, fixture structuralClientCheckFixture) {
				const duplicateOffset = 0x400
				populateClientCheckPattern(t, tibiaBinary, *peData, duplicateOffset, fixture)
				duplicateRVA, _ := peData.rvaForOffset(duplicateOffset)
				peData.runtimeFunctions = append(peData.runtimeFunctions, peRuntimeFunction{beginRVA: duplicateRVA - 0x20, endRVA: duplicateRVA + 0x80})
			},
		},
		{
			name: "enable wrapper is not an exact runtime function",
			mutate: func(_ []byte, peData *peInfo, fixture structuralClientCheckFixture) {
				enableRVA, _ := peData.rvaForOffset(fixture.enableClientCheckOffset)
				for index := range peData.runtimeFunctions {
					if peData.runtimeFunctions[index].beginRVA == enableRVA {
						peData.runtimeFunctions[index].endRVA++
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tibiaBinary, peData, fixture := newStructuralClientCheckFixture(t)
			test.mutate(tibiaBinary, &peData, fixture)
			plan := buildStructuralPatchPlan(tibiaBinary, peData, structuralTestPatches(t))
			if plan.verifiedGroups[structuralClientCheckGroup] {
				t.Fatal("expected unsafe or ambiguous structural evidence to reject the entire patch group")
			}
		})
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
		patchStatuses:       []battleyePatchStatus{{patch: battleyePatches[0], originalOffset: []int{0x180}}},
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

	diagnosis.patchStatuses = []battleyePatchStatus{{patch: battleyePatches[0], patchedOffset: []int{0x180}}}
	if diagnosis.clientCheckVerdict() != "WARNING: known client-check patch applied but suspicious branch/call evidence remains" {
		t.Fatalf("expected patched known signature plus suspicious evidence to become WARNING, got %q", diagnosis.clientCheckVerdict())
	}
}

func TestHighRiskDiagnosticSignatureChangesPatchedVerdict(t *testing.T) {
	diagnosis := diagnosisReport{
		patchStatuses: []battleyePatchStatus{
			{patch: battleyePatches[0], patchedOffset: []int{0x2DE804}},
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

type structuralClientCheckFixture struct {
	clientCheckOffset             int
	enableClientCheckOffset       int
	clientCheckStringOffset       int
	errorStringOffset             int
	enableClientCheckStringOffset int
	qtIATOffset                   int
	constructorIATOffset          int
	destructorIATOffset           int
	objectOffset                  int
	destructorThunkOffset         int
}

func newStructuralClientCheckFixture(t *testing.T) ([]byte, peInfo, structuralClientCheckFixture) {
	t.Helper()
	fixture := structuralClientCheckFixture{
		clientCheckOffset:             0x180,
		enableClientCheckOffset:       0x300,
		clientCheckStringOffset:       0x720,
		errorStringOffset:             0x750,
		enableClientCheckStringOffset: 0x780,
		qtIATOffset:                   0x7c0,
		constructorIATOffset:          0x7c8,
		destructorIATOffset:           0x7d0,
		objectOffset:                  0x900,
		destructorThunkOffset:         0x500,
	}
	peData := peInfo{
		valid: true,
		sections: []peSectionInfo{
			{name: ".text", rawStart: 0x100, rawEnd: 0x700, rvaStart: 0x1000, rvaEnd: 0x1600, isCode: true},
			{name: ".rdata", rawStart: 0x700, rawEnd: 0x880, rvaStart: 0x2000, rvaEnd: 0x2180},
			{name: ".data", rawStart: 0x900, rawEnd: 0xa00, rvaStart: 0x3000, rvaEnd: 0x3100, isWritable: true},
		},
	}
	tibiaBinary := make([]byte, 0xa00)
	copy(tibiaBinary[fixture.clientCheckStringOffset:], []byte("clientcheck_disconnected\x00"))
	copy(tibiaBinary[fixture.errorStringOffset:], []byte("error\x00"))
	copy(tibiaBinary[fixture.enableClientCheckStringOffset:], []byte("enableClientCheck\x00"))

	populateClientCheckPattern(t, tibiaBinary, peData, fixture.clientCheckOffset, fixture)
	populateEnableClientCheckPattern(t, tibiaBinary, peData, fixture)

	clientCheckRVA, _ := peData.rvaForOffset(fixture.clientCheckOffset)
	enableClientCheckRVA, _ := peData.rvaForOffset(fixture.enableClientCheckOffset)
	peData.runtimeFunctions = []peRuntimeFunction{
		{beginRVA: clientCheckRVA - 0x20, endRVA: clientCheckRVA + 0x80},
		{beginRVA: enableClientCheckRVA, endRVA: enableClientCheckRVA + 40},
	}
	return tibiaBinary, peData, fixture
}

func populateClientCheckPattern(t *testing.T, tibiaBinary []byte, peData peInfo, offset int, fixture structuralClientCheckFixture) {
	t.Helper()
	copy(tibiaBinary[offset:], structuralClientCheckDisconnectedPattern.data)
	binary.LittleEndian.PutUint32(tibiaBinary[offset+26:offset+30], 0xa20)
	writeRelativeTarget(t, tibiaBinary, peData, offset+18, 5, 1, mustRVAForOffset(t, peData, 0x600))
	writeRelativeTarget(t, tibiaBinary, peData, offset+36, 7, 3, mustRVAForOffset(t, peData, fixture.clientCheckStringOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+47, 6, 2, mustRVAForOffset(t, peData, fixture.qtIATOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+62, 7, 3, mustRVAForOffset(t, peData, fixture.errorStringOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+73, 6, 2, mustRVAForOffset(t, peData, fixture.qtIATOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+93, 5, 1, mustRVAForOffset(t, peData, 0x550))
}

func populateEnableClientCheckPattern(t *testing.T, tibiaBinary []byte, peData peInfo, fixture structuralClientCheckFixture) {
	t.Helper()
	offset := fixture.enableClientCheckOffset
	copy(tibiaBinary[offset:], structuralEnableClientCheckPattern.data)
	writeRelativeTarget(t, tibiaBinary, peData, offset+4, 7, 3, mustRVAForOffset(t, peData, fixture.enableClientCheckStringOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+11, 7, 3, mustRVAForOffset(t, peData, fixture.objectOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+18, 6, 2, mustRVAForOffset(t, peData, fixture.constructorIATOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+24, 7, 3, mustRVAForOffset(t, peData, fixture.destructorThunkOffset))
	writeRelativeTarget(t, tibiaBinary, peData, offset+35, 5, 1, mustRVAForOffset(t, peData, 0x580))

	thunkOffset := fixture.destructorThunkOffset
	copy(tibiaBinary[thunkOffset:], []byte{0x48, 0x8d, 0x0d, 0, 0, 0, 0, 0x48, 0xff, 0x25, 0, 0, 0, 0})
	writeRelativeTarget(t, tibiaBinary, peData, thunkOffset, 7, 3, mustRVAForOffset(t, peData, fixture.objectOffset))
	writeRelativeTarget(t, tibiaBinary, peData, thunkOffset+7, 7, 3, mustRVAForOffset(t, peData, fixture.destructorIATOffset))
}

func structuralTestPatches(t *testing.T) []battleyePatch {
	t.Helper()
	patches := make([]battleyePatch, 0, 2)
	for _, patch := range battleyePatches {
		if patch.structuralGuard != nil && patch.structuralGuard.group == structuralClientCheckGroup {
			patches = append(patches, patch)
		}
	}
	if len(patches) != 2 {
		t.Fatalf("expected two structural client-check patches, got %d", len(patches))
	}
	return patches
}

func writeRelativeTarget(t *testing.T, tibiaBinary []byte, peData peInfo, instructionOffset int, instructionLength int, displacementOffset int, targetRVA int) {
	t.Helper()
	instructionRVA, ok := peData.rvaForOffset(instructionOffset)
	if !ok {
		t.Fatalf("fixture instruction offset 0x%X has no RVA", instructionOffset)
	}
	displacement := targetRVA - (instructionRVA + instructionLength)
	binary.LittleEndian.PutUint32(tibiaBinary[instructionOffset+displacementOffset:instructionOffset+displacementOffset+4], uint32(int32(displacement)))
}

func mustRVAForOffset(t *testing.T, peData peInfo, offset int) int {
	t.Helper()
	rva, ok := peData.rvaForOffset(offset)
	if !ok {
		t.Fatalf("fixture offset 0x%X has no RVA", offset)
	}
	return rva
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
