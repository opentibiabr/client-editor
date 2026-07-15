package edit

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var (
	properties = []string{
		"loginWebService",
		"clientWebService",
		"tibiaPageUrl",
		"tibiaStoreGetCoinsUrl",
		"getPremiumUrl",
		"createAccountUrl",
		"accessAccountUrl",
		"lostAccountUrl",
		"manualUrl",
		"faqUrl",
		"premiumFeaturesUrl",
		"crashReportUrl",
		"fpsHistoryRecipient",
		"cipSoftUrl",
	}
)

var paddingByte = []byte{0x20}

const (
	wildcardByte            = -1
	codeContextRadius       = 200
	contextBytesRadius      = 48
	knownPatchContextRadius = 512
	patchContextRadius      = 32
	configINIFileName       = "config.ini"
	configINIDirName        = "conf"
	configINIStartMarker    = "[URLS]"
)

type battleyePatch struct {
	name                  string
	original              bytePattern
	patched               bytePattern
	replacement           []int
	diagnosticOnly        bool
	aggressiveReplacement []int
	highRiskClientCheck   bool
	legacyEvidenceOnly    bool
	structuralGuard       *structuralPatchGuard
	expectedOffsets       []knownPatchOffset
	falsePositiveCheck    string
}

type bytePattern struct {
	name string
	data []byte
	mask []bool
}

type knownPatchOffset struct {
	sha256 string
	offset int
	note   string
}

type structuralPatchKind string

const (
	structuralClientCheckGroup                            = "qt-client-check"
	structuralClientCheckDisconnected structuralPatchKind = "clientcheck_disconnected"
	structuralEnableClientCheck       structuralPatchKind = "enableClientCheck"
)

type structuralPatchGuard struct {
	group string
	kind  structuralPatchKind
}

type structuralPatchMatch struct {
	originalOffsets []int
	patchedOffsets  []int
	unique          bool
}

type structuralPatchPlan struct {
	matches        map[int]structuralPatchMatch
	verifiedGroups map[string]bool
}

type clientCheckIndicator struct {
	name  string
	value []byte
}

type battleyePatchStatus struct {
	patch                battleyePatch
	originalOffset       []int
	patchedOffset        []int
	expectedOffsetHits   []knownPatchOffset
	expectedOffsetMisses []knownPatchOffset
}

type peSectionInfo struct {
	name       string
	rawStart   int
	rawEnd     int
	rvaStart   int
	rvaEnd     int
	isCode     bool
	isWritable bool
}

type peRuntimeFunction struct {
	beginRVA int
	endRVA   int
}

type peInfo struct {
	valid            bool
	errorText        string
	imageBase        uint64
	sections         []peSectionInfo
	runtimeFunctions []peRuntimeFunction
	imports          []string
}

type clientCheckReference struct {
	offset            int
	section           string
	instruction       string
	branchOffsets     []int
	callOffsets       []int
	contextStart      int
	patternMatches    []patternMatch
	contextBytes      []byte
	knownPatchNearby  bool
	strongUnsupported bool
	suspiciousActive  bool
}

type patternMatch struct {
	name   string
	offset int
}

type clientCheckFinding struct {
	name       string
	encoding   string
	offsets    []int
	references []clientCheckReference
}

type diagnosisReport struct {
	path                string
	size                int
	sha256              string
	isWindowsExe        bool
	pe                  peInfo
	patchStatuses       []battleyePatchStatus
	clientCheckFindings []clientCheckFinding
	qtIndicators        []string
}

var structuralClientCheckDisconnectedPattern = newBytePattern(
	"structural clientcheck_disconnected dispatch path",
	0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97,
	0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8b, 0xbf, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x41, 0xb8, 0xff, 0xff, 0xff, 0xff,
	0x48, 0x8d, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8d, 0x4d, 0x37,
	0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff,
	0x48, 0x8d, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8d, 0x4d, 0x1f,
	0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf,
	0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90,
)

var structuralClientCheckDisconnectedReplacement = neutralizeBranchJumpPattern(
	structuralClientCheckDisconnectedPattern,
	map[int]int{93: 0x90, 94: 0x90, 95: 0x90, 96: 0x90, 97: 0x90},
)

var structuralEnableClientCheckPattern = newBytePattern(
	"structural enableClientCheck wrapper",
	0x48, 0x83, 0xec, 0x28,
	0x48, 0x8d, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8d, 0x0d, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x8d, 0x0d, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0x48, 0x83, 0xc4, 0x28,
	0xe9, wildcardByte, wildcardByte, wildcardByte, wildcardByte,
	0xcc, 0xcc, 0xcc, 0xcc,
)

var structuralEnableClientCheckReplacement = neutralizeBranchJumpPattern(
	structuralEnableClientCheckPattern,
	map[int]int{18: 0x90, 19: 0x90, 20: 0x90, 21: 0x90, 22: 0x90, 23: 0x90},
)

var battleyePatches = []battleyePatch{
	{
		name:        "legacy launch check",
		original:    newBytePattern("legacy launch check original", 0x8d, 0x4d, 0xb4, 0x75, 0x0e, 0xe8, 0xb4, 0x53),
		patched:     newBytePattern("legacy launch check patched", 0x8d, 0x4d, 0xb4, 0xeb, 0x0e, 0xe8, 0xb4, 0x53),
		replacement: newPatchReplacement(0x8d, 0x4d, 0xb4, 0xeb, 0x0e, 0xe8, 0xb4, 0x53),
	},
	{
		name:           "ambiguous client check branch",
		original:       newBytePattern("client check branch original", 0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48),
		patched:        newBytePattern("client check branch patched", 0xeb, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48),
		replacement:    newPatchReplacement(0xeb, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48),
		diagnosticOnly: true,
		expectedOffsets: []knownPatchOffset{
			{
				sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f",
				offset: 0x2DE804,
				note:   "reported new client; this is the only currently observed matching legacy patch point",
			},
		},
		falsePositiveCheck: "diagnostic-only because this short branch signature also occurs in unrelated container code; it must not authorize a rewrite without a validated call relationship to the client-check function",
	},
	{
		name:        "legacy client check branch",
		original:    newBytePattern("legacy client check branch original", 0x75, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48),
		patched:     newBytePattern("legacy client check branch patched", 0xeb, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48),
		replacement: newPatchReplacement(0xeb, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48),
	},
	{
		name:           "candidate client check conditional branch with variable call",
		original:       newBytePattern("candidate client check conditional branch original", 0x75, 0x0f, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48),
		patched:        newBytePattern("candidate client check conditional branch patched", 0xeb, 0x0f, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48),
		replacement:    newPatchReplacement(0xeb, 0x0f, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48),
		diagnosticOnly: true,
		expectedOffsets: []knownPatchOffset{
			{
				sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f",
				offset: 0x2DE804,
				note:   "wildcard diagnostic around the reported new-client match; not auto-applied without surrounding-code review",
			},
		},
		falsePositiveCheck: "diagnostic-only because the CALL rel32 bytes are wildcarded; require unique match, nearby client-check xref, and manual code-context review before making this patchable",
	},
	{
		name:           "candidate clientcheck_disconnected Qt xref dispatch",
		original:       newBytePattern("candidate clientcheck_disconnected Qt xref dispatch", 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x18, 0x39, 0x80, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
		diagnosticOnly: true,
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0x1A8E5B, note: "reported new-client clientcheck_disconnected xref context"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0x1A8E5B, note: "observed local clientcheck_disconnected xref context"},
		},
		falsePositiveCheck: "diagnostic-only xref context observed around reported ref 0x1A8E61; exact displacement bytes keep this version-specific until the RIP target and branch/call flow are manually reviewed",
	},
	{
		name:           "candidate BEClient Qt xref dispatch",
		original:       newBytePattern("candidate BEClient Qt xref dispatch", 0x48, 0x8b, 0x01, 0x48, 0x8b, 0x58, 0x28, 0x48, 0x8d, 0x15, 0x45, 0x1a, 0x7f, 0x01, 0x48, 0x8d, 0x4c, 0x24, 0x28, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
		diagnosticOnly: true,
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0x1BB425, note: "reported new-client BEClient xref context"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0x1BB425, note: "observed local BEClient xref context"},
		},
		falsePositiveCheck: "diagnostic-only xref context observed around reported ref 0x1BB42C; BEClient remains weak by itself because Qt metadata/dialog text can reference it without proving active client-check flow",
	},
	{
		name:                "structural clientcheck_disconnected dispatch path",
		original:            structuralClientCheckDisconnectedPattern,
		patched:             newBytePattern("structural clientcheck_disconnected dispatch path patched", structuralClientCheckDisconnectedReplacement...),
		replacement:         structuralClientCheckDisconnectedReplacement,
		highRiskClientCheck: true,
		structuralGuard: &structuralPatchGuard{
			group: structuralClientCheckGroup,
			kind:  structuralClientCheckDisconnected,
		},
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0x1A8E3D, note: "reported 15.13-era clientcheck_disconnected dispatch path"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0x1A8E3D, note: "Tibia 15.13 clientcheck_disconnected dispatch path"},
			{sha256: "2768a9b9c1338b7664b37982e7c7982cb35a969052d799b25156be916820780a", offset: 0x1CAE4D, note: "Tibia 15.20 clientcheck_disconnected dispatch path"},
			{sha256: "feccded03664e123ac32fa15876cccd22287a65aa5c450a80a11e2da94095ee0", offset: 0x1CB1CD, note: "Tibia 15.20 clientcheck_disconnected dispatch path"},
			{sha256: "dbe590d978bc5f3c427879639ffac19556e0c0bb68f9d0dd72e8a4c52492ee9e", offset: 0x1CDBDD, note: "Tibia 15.23 clientcheck_disconnected dispatch path"},
			{sha256: "fc57822ac6174fb8025cdf36bba55046b5901feae89b20eab4547b2172f16298", offset: 0x1CEBDD, note: "Tibia 15.24 clientcheck_disconnected dispatch path"},
			{sha256: "a0c57211a9841e827e5f738ed9f5c2084fb5246a33fa035f135ece8f30bffbe8", offset: 0x1D30ED, note: "Tibia 15.25 clientcheck_disconnected dispatch path"},
			{sha256: "d8e893689cf7b70016889add309af827f43d07f95acf7b7d4106cde885fd6627", offset: 0x1D9B9D, note: "Tibia 15.30 clientcheck_disconnected dispatch path"},
		},
		falsePositiveCheck: "auto-patched only when the normalized function skeleton, exact clientcheck_disconnected and error xrefs, shared Qt IAT target, executable call targets, PE runtime-function boundary, unique match, and paired enableClientCheck wrapper all validate",
	},
	{
		name:                "high-risk clientcheck_disconnected dispatch path",
		original:            newBytePattern("high-risk clientcheck_disconnected dispatch path", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x30, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x18, 0x39, 0x80, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xbe, 0x4a, 0x7d, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk clientcheck_disconnected dispatch path [aggressive source]", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x30, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x18, 0x39, 0x80, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xbe, 0x4a, 0x7d, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
			map[int]int{93: 0x90, 94: 0x90, 95: 0x90, 96: 0x90, 97: 0x90},
		),
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0x1A8E3D, note: "high-risk clientcheck_disconnected dispatch path seen after the known 0x2DE804 patch"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0x1A8E3D, note: "observed local clientcheck_disconnected dispatch path seen after the known 0x2DE804 patch"},
		},
		falsePositiveCheck: "diagnostic-only high-risk path; CALL bytes are wildcarded, but fixed surrounding xref/field-access bytes tie it to the reported clientcheck_disconnected dispatch context; aggressive mode nops the final signal dispatch call",
	},
	{
		name:                "high-risk clientcheck_disconnected dispatch path local 2026-07",
		original:            newBytePattern("high-risk clientcheck_disconnected dispatch path local 2026-07", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x20, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x78, 0x2c, 0xa4, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xe6, 0x86, 0x98, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk clientcheck_disconnected dispatch path local 2026-07 [aggressive source]", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x20, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x78, 0x2c, 0xa4, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xe6, 0x86, 0x98, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
			map[int]int{93: 0x90, 94: 0x90, 95: 0x90, 96: 0x90, 97: 0x90},
		),
		falsePositiveCheck: "version-scoped local 2026-07 high-risk path; aggressive mode nops the final clientcheck_disconnected signal dispatch call",
	},
	{
		name:                "high-risk clientcheck_disconnected dispatch path Tibia 15.30 d8e89368",
		original:            newBytePattern("high-risk clientcheck_disconnected dispatch path Tibia 15.30 d8e89368", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x60, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xb0, 0x6c, 0xac, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x2e, 0x87, 0xa0, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk clientcheck_disconnected dispatch path Tibia 15.30 d8e89368 [aggressive source]", 0x48, 0x83, 0x45, 0x9f, 0x48, 0xeb, 0x10, 0x4c, 0x8d, 0x45, 0xb7, 0x48, 0x8b, 0xd3, 0x48, 0x8d, 0x4d, 0x97, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xbf, 0x60, 0x0a, 0x00, 0x00, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0xb0, 0x6c, 0xac, 0x01, 0x48, 0x8d, 0x4d, 0x37, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8b, 0xd8, 0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x15, 0x2e, 0x87, 0xa0, 0x01, 0x48, 0x8d, 0x4d, 0x1f, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90, 0x4c, 0x8d, 0x4d, 0x97, 0x4c, 0x8b, 0xc3, 0x48, 0x8b, 0xd0, 0x48, 0x8b, 0xcf, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x90),
			map[int]int{93: 0x90, 94: 0x90, 95: 0x90, 96: 0x90, 97: 0x90},
		),
		expectedOffsets: []knownPatchOffset{
			{sha256: "d8e893689cf7b70016889add309af827f43d07f95acf7b7d4106cde885fd6627", offset: 0x1D9B9D, note: "Tibia 15.30 clientcheck_disconnected dispatch path"},
		},
		falsePositiveCheck: "hash-scoped Tibia 15.30 path; aggressive mode nops the final clientcheck_disconnected signal dispatch call",
	},
	{
		name:           "candidate enableClientCheck Qt xref dispatch",
		original:       newBytePattern("candidate enableClientCheck Qt xref dispatch", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x65, 0xc5, 0x99, 0x01, 0x48, 0x8d, 0x0d, 0x36, 0x04, 0xcf, 0x01, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x11, 0xd0, 0xf7, 0x00),
		diagnosticOnly: true,
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0xE8C0, note: "reported new-client enableClientCheck xref context"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0xE8C0, note: "observed local enableClientCheck xref context"},
		},
		falsePositiveCheck: "diagnostic-only xref context observed around reported ref 0xE8C4; exact displacement bytes keep this version-specific until the RIP target and branch/call flow are manually reviewed",
	},
	{
		name:                "structural enableClientCheck wrapper",
		original:            structuralEnableClientCheckPattern,
		patched:             newBytePattern("structural enableClientCheck wrapper patched", structuralEnableClientCheckReplacement...),
		replacement:         structuralEnableClientCheckReplacement,
		highRiskClientCheck: true,
		structuralGuard: &structuralPatchGuard{
			group: structuralClientCheckGroup,
			kind:  structuralEnableClientCheck,
		},
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0xE8C0, note: "reported 15.13-era enableClientCheck wrapper"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0xE8C0, note: "Tibia 15.13 enableClientCheck wrapper"},
			{sha256: "2768a9b9c1338b7664b37982e7c7982cb35a969052d799b25156be916820780a", offset: 0xE9B0, note: "Tibia 15.20 enableClientCheck wrapper"},
			{sha256: "feccded03664e123ac32fa15876cccd22287a65aa5c450a80a11e2da94095ee0", offset: 0xE9B0, note: "Tibia 15.20 enableClientCheck wrapper"},
			{sha256: "dbe590d978bc5f3c427879639ffac19556e0c0bb68f9d0dd72e8a4c52492ee9e", offset: 0xE9E0, note: "Tibia 15.23 enableClientCheck wrapper"},
			{sha256: "fc57822ac6174fb8025cdf36bba55046b5901feae89b20eab4547b2172f16298", offset: 0xE9E0, note: "Tibia 15.24 enableClientCheck wrapper"},
			{sha256: "a0c57211a9841e827e5f738ed9f5c2084fb5246a33fa035f135ece8f30bffbe8", offset: 0xEB50, note: "Tibia 15.25 enableClientCheck wrapper"},
			{sha256: "d8e893689cf7b70016889add309af827f43d07f95acf7b7d4106cde885fd6627", offset: 0xEB50, note: "Tibia 15.30 enableClientCheck wrapper"},
		},
		falsePositiveCheck: "auto-patched only when the exact enableClientCheck xref, writable Qt object, executable destructor thunk and tail target, PE runtime-function boundary, unique match, and paired clientcheck_disconnected dispatch all validate",
	},
	{
		name:                "high-risk enableClientCheck dispatch path",
		original:            newBytePattern("high-risk enableClientCheck dispatch path", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x65, 0xc5, 0x99, 0x01, 0x48, 0x8d, 0x0d, 0x36, 0x04, 0xcf, 0x01, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x11, 0xd0, 0xf7, 0x00, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk enableClientCheck dispatch path [aggressive source]", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x65, 0xc5, 0x99, 0x01, 0x48, 0x8d, 0x0d, 0x36, 0x04, 0xcf, 0x01, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x11, 0xd0, 0xf7, 0x00, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
			map[int]int{18: 0x90, 19: 0x90, 20: 0x90, 21: 0x90, 22: 0x90, 23: 0x90},
		),
		expectedOffsets: []knownPatchOffset{
			{sha256: "c930bd29b76cec5d88d35e24dbee0ed0edaeba68bd7961c68856912c40d8728f", offset: 0xE8C0, note: "high-risk enableClientCheck dispatch path seen after the known 0x2DE804 patch"},
			{sha256: "985fb4e114b3156a5488b7b35ed5d8615d58fff140a04d8e73c18ac0b4d871e5", offset: 0xE8C0, note: "observed local enableClientCheck dispatch path seen after the known 0x2DE804 patch"},
		},
		falsePositiveCheck: "diagnostic-only high-risk path; CALL/JMP bytes are wildcarded, but fixed enableClientCheck xref and thunk shape keep the match scoped to the reported dispatch context; aggressive mode nops only the Qt metadata call and preserves the original tail jump",
	},
	{
		name:                "high-risk enableClientCheck dispatch path local 2026-07",
		original:            newBytePattern("high-risk enableClientCheck dispatch path local 2026-07", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x45, 0x59, 0xc0, 0x01, 0x48, 0x8d, 0x0d, 0x96, 0x9a, 0x35, 0x02, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x01, 0xa6, 0x15, 0x01, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk enableClientCheck dispatch path local 2026-07 [aggressive source]", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x45, 0x59, 0xc0, 0x01, 0x48, 0x8d, 0x0d, 0x96, 0x9a, 0x35, 0x02, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x01, 0xa6, 0x15, 0x01, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
			map[int]int{18: 0x90, 19: 0x90, 20: 0x90, 21: 0x90, 22: 0x90, 23: 0x90},
		),
		falsePositiveCheck: "version-scoped local 2026-07 high-risk path; aggressive mode nops the enableClientCheck Qt metadata call and preserves the tail jump",
	},
	{
		name:                "high-risk enableClientCheck dispatch path Tibia 15.30 d8e89368",
		original:            newBytePattern("high-risk enableClientCheck dispatch path Tibia 15.30 d8e89368", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x8d, 0x03, 0xc9, 0x01, 0x48, 0x8d, 0x0d, 0x86, 0x0a, 0x43, 0x02, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x01, 0x39, 0x1b, 0x01, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
		diagnosticOnly:      true,
		highRiskClientCheck: true,
		legacyEvidenceOnly:  true,
		aggressiveReplacement: neutralizeBranchJumpPattern(
			newBytePattern("high-risk enableClientCheck dispatch path Tibia 15.30 d8e89368 [aggressive source]", 0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x15, 0x8d, 0x03, 0xc9, 0x01, 0x48, 0x8d, 0x0d, 0x86, 0x0a, 0x43, 0x02, 0xff, 0x15, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0x48, 0x8d, 0x0d, 0x01, 0x39, 0x1b, 0x01, 0x48, 0x83, 0xc4, 0x28, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
			map[int]int{18: 0x90, 19: 0x90, 20: 0x90, 21: 0x90, 22: 0x90, 23: 0x90},
		),
		expectedOffsets: []knownPatchOffset{
			{sha256: "d8e893689cf7b70016889add309af827f43d07f95acf7b7d4106cde885fd6627", offset: 0xEB50, note: "Tibia 15.30 enableClientCheck dispatch path"},
		},
		falsePositiveCheck: "hash-scoped Tibia 15.30 path; aggressive mode nops the enableClientCheck Qt metadata call and preserves the tail jump",
	},
}

var clientCheckIndicators = []clientCheckIndicator{
	{name: "BEClient", value: []byte("BEClient")},
	{name: "clientcheck_disconnected", value: []byte("clientcheck_disconnected")},
	{name: "requestCloseDueToClientCheck", value: []byte("requestCloseDueToClientCheck")},
	{name: "onCloseDueToClientCheckRequested", value: []byte("onCloseDueToClientCheckRequested")},
	{name: "onClientCheckDialogButtonClicked", value: []byte("onClientCheckDialogButtonClicked")},
	{name: "enableClientCheck", value: []byte("enableClientCheck")},
}

var clientCheckCodePatterns = []bytePattern{
	newBytePattern("short JNE followed by CALL", 0x75, wildcardByte, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
	newBytePattern("short JE followed by CALL", 0x74, wildcardByte, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
	newBytePattern("near JNE followed by CALL", 0x0f, 0x85, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
	newBytePattern("near JE followed by CALL", 0x0f, 0x84, wildcardByte, wildcardByte, wildcardByte, wildcardByte, 0xe8, wildcardByte, wildcardByte, wildcardByte, wildcardByte),
}

var qtContextIndicators = []string{
	"Qt5Core",
	"Qt6Core",
	"QMetaObject",
	"QObject",
	"qt_metacall",
	"qt_static_metacall",
	"QMessageBox",
}

func Edit(tibiaExe string, sourceTibiaExe string, strictClientCheck bool, aggressiveClientCheck bool) {
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("[ERROR] Failed to read config file: %s\n", err.Error())
		os.Exit(1)
	}
	// Check if all properties are present in the config file
	missingProperties := make([]string, 0)
	for _, prop := range properties {
		if !viper.IsSet(prop) {
			missingProperties = append(missingProperties, prop)
		}
	}

	// Error out if any properties are missing
	if len(missingProperties) > 0 {
		fmt.Printf("[ERROR] Missing properties in the config file: %v\n", missingProperties)
		os.Exit(1)
	}

	configValues := make(map[string]string)
	for _, prop := range properties {
		value := viper.GetString(prop)
		configValues[prop] = value
	}

	tibiaPath := tibiaExe
	sourcePath := resolveSourceExecutable(tibiaPath, sourceTibiaExe)
	_, sourceBinary := readFile(sourcePath)
	tibiaBinary := append([]byte(nil), sourceBinary...)
	originalBinarySize := len(sourceBinary)
	originalTibiaBinary := append([]byte(nil), tibiaBinary...)

	if sourcePath != tibiaExe {
		fmt.Printf("[INFO] Using source client executable for patch input: %s\n", filepath.Base(sourcePath))
		fmt.Printf("[INFO] Writing patched client to target executable: %s\n", filepath.Base(tibiaExe))
	}

	tibiaBinary = replaceTibiaRSAKey(tibiaBinary)
	tibiaBinary = removeBattlEye(tibiaPath, tibiaBinary, aggressiveClientCheck)
	diagnosis := analyzeTibiaBinary(tibiaPath, tibiaBinary)
	logClientCheckSupportSummary(diagnosis)
	enforceEditClientCheckPolicy(diagnosis, strictClientCheck)

	for prop, value := range configValues {
		ok := setPropertyByName(tibiaBinary, prop, value)
		if !ok {
			fmt.Printf("[ERROR] Unable to replace %s\n", prop)
		}
	}

	backupBinary := originalTibiaBinary
	if sourcePath != tibiaExe {
		targetBinary, err := os.ReadFile(tibiaPath)
		if err == nil {
			backupBinary = targetBinary
		} else if !os.IsNotExist(err) {
			fmt.Printf("[ERROR] Unable to read target executable for backup: %s\n", err.Error())
			os.Exit(1)
		}
	}

	backupTibiaExecutable(tibiaPath, backupBinary, aggressiveClientCheck)
	exportModifiedFile(tibiaPath, tibiaBinary, originalBinarySize)
	syncConfigINI(tibiaPath, originalTibiaBinary, configValues)
	logEditSuccess(diagnosis, strictClientCheck)
}

func Diagnose(tibiaExe string, compareWith string, strictClientCheck bool) {
	tibiaPath, tibiaBinary := readFile(tibiaExe)
	diagnosis := analyzeTibiaBinary(tibiaPath, tibiaBinary)

	printDiagnosisReport(diagnosis, "target")

	if compareWith != "" {
		comparePath, compareBinary := readFile(compareWith)
		compareDiagnosis := analyzeTibiaBinary(comparePath, compareBinary)
		printDiagnosisReport(compareDiagnosis, "baseline")
		printDiagnosisComparison(compareDiagnosis, diagnosis)
	}

	failIfStrictClientCheck(diagnosis, strictClientCheck)
}

func backupTibiaExecutable(tibiaPath string, tibiaBinary []byte, aggressive bool) {
	tibiaExeFileName := filepath.Base(tibiaPath)
	tibiaExeBackupPath := filepath.Join(filepath.Dir(tibiaPath), fmt.Sprintf("BKP%d-%s", time.Now().Unix(), tibiaExeFileName))
	tibiaExeBackupFileName := filepath.Base(tibiaExeBackupPath)

	if aggressive {
		fmt.Printf("[WARN] ============================================================\n")
		fmt.Printf("[WARN] AGGRESSIVE MODE IS ENABLED\n")
		fmt.Printf("[WARN] High-risk signatures are being rewritten automatically.\n")
		fmt.Printf("[WARN] This mode can break runtime behavior and can crash or fail to start some clients.\n")
		fmt.Printf("[WARN] Create/keep a known-good backup before using it.\n")
		fmt.Printf("[WARN] This may alter client behavior and should only be used with full manual validation.\n")
		fmt.Printf("[WARN] ============================================================\n")
	}

	fmt.Printf("[INFO] Backing up %s to %s\n", tibiaExeFileName, tibiaExeBackupFileName)

	err := os.WriteFile(tibiaExeBackupPath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}
}

func replaceTibiaRSAKey(tibiaBinary []byte) []byte {
	tibiaRsaPath := "tibia_rsa.key"
	otservRsaPath := "otserv_rsa.key"

	_, tibiaRsa := readFile(tibiaRsaPath)
	_, otservRsa := readFile(otservRsaPath)

	fmt.Printf("[INFO] Searching for Tibia RSA... \n")

	if bytes.Contains(tibiaBinary, tibiaRsa) {
		fmt.Printf("[INFO] Tibia RSA found!\n")
		tibiaBinary = bytes.Replace(tibiaBinary, tibiaRsa, otservRsa, 1)
		fmt.Printf("[PATCH] Tibia RSA replaced with OTServ RSA!\n")
	} else if bytes.Contains(tibiaBinary, otservRsa) {
		fmt.Printf("[WARN] OTServ RSA already patched!\n")
	} else {
		fmt.Printf("[ERROR] Unable to find Tibia RSA\n")
		os.Exit(1)
	}

	return tibiaBinary
}

func removeBattlEye(tibiaPath string, tibiaBinary []byte, aggressive bool) []byte {
	if !isWindowsExecutable(tibiaPath, tibiaBinary) {
		fmt.Printf("[WARN] Battleye patch skipped because the client is not a Windows executable\n")
		return tibiaBinary
	}

	fmt.Printf("[INFO] Searching for BattlEye byte patch signatures...\n")
	if aggressive {
		fmt.Printf("[WARN] Aggressive mode enabled: high-risk signatures are eligible for patching.\n")
	}

	activeBattleyePatches := make([]battleyePatch, len(battleyePatches))
	for patchIndex, patch := range battleyePatches {
		activeBattleyePatches[patchIndex] = patch.withAggressiveMode(aggressive)
	}
	peData := inspectPE(tibiaBinary)
	structuralPlan := buildStructuralPatchPlan(tibiaBinary, peData, activeBattleyePatches)
	var beforeBattleyePatches []byte
	if structuralPlan.verifiedGroups[structuralClientCheckGroup] {
		fmt.Printf("[INFO] BattlEye structural client-check pair verified uniquely before patching\n")
		beforeBattleyePatches = append([]byte(nil), tibiaBinary...)
	}

	patchesApplied := 0
	signaturesApplied := 0
	alreadyApplied := 0
	patchableSignatures := 0
	for patchIndex, patch := range activeBattleyePatches {
		originalOffsets := patch.original.findAll(tibiaBinary)
		patchedOffsets := patch.effectivePatchedPattern().findAll(tibiaBinary)
		if patch.structuralGuard != nil {
			match := structuralPlan.matches[patchIndex]
			if !structuralPlan.verifiedGroups[patch.structuralGuard.group] {
				if len(originalOffsets) > 0 || len(patchedOffsets) > 0 {
					fmt.Printf("[WARN] BattlEye structural signature %q matched byte shape original=%s patched=%s but failed unique paired structural verification; not patched\n", patch.name, formatOffsetsLimited(originalOffsets, 6), formatOffsetsLimited(patchedOffsets, 6))
				} else {
					fmt.Printf("[INFO] BattlEye structural signature %q not found\n", patch.name)
				}
				continue
			}
			originalOffsets = match.originalOffsets
			patchedOffsets = match.patchedOffsets
		}
		legacyHighRiskEvidence := patch.legacyEvidenceOnly
		eligiblePatch := !patch.diagnosticOnly || (aggressive && !legacyHighRiskEvidence && len(patch.aggressiveReplacement) > 0)
		if eligiblePatch && (len(originalOffsets) > 0 || len(patchedOffsets) > 0) {
			patchableSignatures++
		}

		if patch.diagnosticOnly {
			if !legacyHighRiskEvidence && len(originalOffsets) > 0 && aggressive && len(patch.aggressiveReplacement) > 0 {
				aggressivePatch := patch
				aggressivePatch.diagnosticOnly = false
				aggressivePatch.replacement = append([]int(nil), patch.aggressiveReplacement...)
				aggressivePatch.patched = newBytePattern(patch.name+" [aggressive]", patch.aggressiveReplacement...)

				tibiaBinary = applyBattleyePatch(tibiaBinary, aggressivePatch, originalOffsets)
				count := len(originalOffsets)
				patchesApplied += count
				signaturesApplied++
				fmt.Printf("[PATCH] BattlEye high-risk signature %q patched aggressively (%d occurrence(s))\n", patch.name, count)
				continue
			}

			if len(originalOffsets) > 0 || len(patchedOffsets) > 0 {
				fmt.Printf("[INFO] BattlEye diagnostic signature %q found original=%s patched=%s; not applied automatically\n", patch.name, formatOffsetsLimited(originalOffsets, 6), formatOffsetsLimited(patchedOffsets, 6))
			}
			continue
		}

		if len(originalOffsets) > 0 {
			tibiaBinary = applyBattleyePatch(tibiaBinary, patch, originalOffsets)
			count := len(originalOffsets)
			patchesApplied += count
			signaturesApplied++
			fmt.Printf("[PATCH] BattlEye signature %q patched (%d occurrence(s))\n", patch.name, count)
			continue
		}

		patchedCount := len(patchedOffsets)
		if patchedCount > 0 {
			alreadyApplied += patchedCount
			fmt.Printf("[INFO] BattlEye signature %q already patched (%d occurrence(s))\n", patch.name, patchedCount)
			continue
		}

		fmt.Printf("[INFO] BattlEye signature %q not found\n", patch.name)
	}

	if beforeBattleyePatches != nil {
		postPatchPE := inspectPE(tibiaBinary)
		postPatchPlan := buildStructuralPatchPlan(tibiaBinary, postPatchPE, activeBattleyePatches)
		if !postPatchPlan.groupFullyPatched(activeBattleyePatches, structuralClientCheckGroup) {
			fmt.Printf("[ERROR] BattlEye structural post-patch verification failed; rolling back all BattlEye byte changes\n")
			return beforeBattleyePatches
		}
		fmt.Printf("[INFO] BattlEye structural client-check pair verified after patching\n")
	}

	if patchesApplied > 0 {
		fmt.Printf("[PATCH] BattlEye byte patch summary: applied %d occurrence(s) across %d/%d patchable signature(s)\n", patchesApplied, signaturesApplied, patchableSignatures)
		if signaturesApplied < patchableSignatures {
			fmt.Printf("[WARN] BattlEye byte patch is partial for this binary; missing signatures can mean this client version uses different code paths\n")
		}
		if hasClientCheckStringIndicators(tibiaBinary) {
			if structuralPlan.verifiedGroups[structuralClientCheckGroup] {
				fmt.Printf("[INFO] Client-check strings remain as Qt metadata; the structurally verified dispatch pair was neutralized\n")
			} else {
				fmt.Printf("[WARN] Client-check strings remain after BattlEye patching; this edit should be treated as PARTIAL unless code-reference diagnostics prove the paths inactive\n")
			}
		}
		return tibiaBinary
	}

	if alreadyApplied > 0 {
		fmt.Printf("[WARN] BattlEye byte patches were already present (%d occurrence(s)); no new byte patch was applied\n", alreadyApplied)
		if hasClientCheckStringIndicators(tibiaBinary) {
			if structuralPlan.verifiedGroups[structuralClientCheckGroup] {
				fmt.Printf("[INFO] Client-check strings remain as Qt metadata; the structurally verified dispatch pair is already neutralized\n")
			} else {
				fmt.Printf("[WARN] Client-check strings remain in an already patched binary; this should be treated as PARTIAL unless code-reference diagnostics prove the paths inactive\n")
			}
		}
		return tibiaBinary
	}

	fmt.Printf("[WARN] BattlEye byte patch signatures not found\n")
	if hasClientCheckStringIndicators(tibiaBinary) {
		fmt.Printf("[WARN] Client-check strings remain and no patchable BattlEye signature matched; this binary is likely unsupported by the current patch set\n")
	}
	return tibiaBinary
}

func logBattlEyeSignatureReport(patchStatuses []battleyePatchStatus) {
	fmt.Printf("[INFO] Known BattlEye byte patch signature report:\n")
	for _, status := range patchStatuses {
		signatureKind := "patchable"
		if status.patch.diagnosticOnly {
			signatureKind = "diagnostic-only"
		}

		switch {
		case len(status.originalOffset) > 0:
			fmt.Printf("[WARN] %q (%s) original signature present at %s\n", status.patch.name, signatureKind, formatOffsets(status.originalOffset))
		case len(status.patchedOffset) > 0:
			fmt.Printf("[INFO] %q (%s) patched signature present at %s\n", status.patch.name, signatureKind, formatOffsets(status.patchedOffset))
		default:
			fmt.Printf("[INFO] %q (%s) signature not found\n", status.patch.name, signatureKind)
		}

		for _, expected := range status.expectedOffsetHits {
			fmt.Printf("[INFO]   expected offset hit 0x%X for SHA256 %s: %s\n", expected.offset, expected.sha256, expected.note)
		}
		for _, expected := range status.expectedOffsetMisses {
			fmt.Printf("[WARN]   expected offset miss 0x%X for SHA256 %s: %s\n", expected.offset, expected.sha256, expected.note)
		}
		if status.patch.diagnosticOnly && status.patch.falsePositiveCheck != "" {
			fmt.Printf("[INFO]   aob mask: %s\n", status.patch.original.formatAOB())
			fmt.Printf("[INFO]   false-positive guard: %s\n", status.patch.falsePositiveCheck)
		}
	}
}

func isWindowsExecutable(_ string, tibiaBinary []byte) bool {
	if len(tibiaBinary) < 0x40 || tibiaBinary[0] != 'M' || tibiaBinary[1] != 'Z' {
		return false
	}

	peOffset := int(binary.LittleEndian.Uint32(tibiaBinary[0x3c:0x40]))
	if peOffset < 0 || peOffset+4 > len(tibiaBinary) {
		return false
	}

	return tibiaBinary[peOffset] == 'P' &&
		tibiaBinary[peOffset+1] == 'E' &&
		tibiaBinary[peOffset+2] == 0x00 &&
		tibiaBinary[peOffset+3] == 0x00
}

func analyzeTibiaBinary(tibiaPath string, tibiaBinary []byte) diagnosisReport {
	sum := sha256.Sum256(tibiaBinary)
	sha256Text := fmt.Sprintf("%x", sum[:])
	diagnosis := diagnosisReport{
		path:         tibiaPath,
		size:         len(tibiaBinary),
		sha256:       sha256Text,
		isWindowsExe: isWindowsExecutable(tibiaPath, tibiaBinary),
	}

	if diagnosis.isWindowsExe {
		diagnosis.pe = inspectPE(tibiaBinary)
	}

	diagnosis.patchStatuses = scanBattlEyePatchStatus(tibiaBinary, sha256Text, diagnosis.pe)
	diagnosis.clientCheckFindings = scanClientCheckFindings(tibiaBinary, diagnosis.pe, diagnosis.patchStatuses)
	diagnosis.qtIndicators = scanQtContextIndicators(tibiaBinary, diagnosis.pe)
	return diagnosis
}

func scanBattlEyePatchStatus(tibiaBinary []byte, sha256Text string, peData peInfo) []battleyePatchStatus {
	statuses := make([]battleyePatchStatus, 0, len(battleyePatches))
	structuralPlan := buildStructuralPatchPlan(tibiaBinary, peData, battleyePatches)
	for patchIndex, patch := range battleyePatches {
		originalOffsets := patch.original.findAll(tibiaBinary)
		patchedOffsets := patch.effectivePatchedPattern().findAll(tibiaBinary)
		if patch.structuralGuard != nil {
			if structuralPlan.verifiedGroups[patch.structuralGuard.group] {
				match := structuralPlan.matches[patchIndex]
				originalOffsets = match.originalOffsets
				patchedOffsets = match.patchedOffsets
			} else {
				originalOffsets = nil
				patchedOffsets = nil
			}
		}
		statuses = append(statuses, battleyePatchStatus{
			patch:                patch,
			originalOffset:       originalOffsets,
			patchedOffset:        patchedOffsets,
			expectedOffsetHits:   patch.expectedOffsetHits(tibiaBinary, sha256Text),
			expectedOffsetMisses: patch.expectedOffsetMisses(tibiaBinary, sha256Text),
		})
	}
	return statuses
}

func inspectPE(tibiaBinary []byte) peInfo {
	peFile, err := pe.NewFile(bytes.NewReader(tibiaBinary))
	if err != nil {
		return peInfo{errorText: err.Error()}
	}
	defer peFile.Close()

	info := peInfo{valid: true}
	switch optionalHeader := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.imageBase = uint64(optionalHeader.ImageBase)
	case *pe.OptionalHeader64:
		info.imageBase = optionalHeader.ImageBase
	}

	for _, section := range peFile.Sections {
		rawStart := int(section.Offset)
		rawEnd := rawStart + int(section.Size)
		if rawStart < 0 || rawEnd < 0 || rawStart > len(tibiaBinary) {
			continue
		}
		if rawEnd > len(tibiaBinary) {
			rawEnd = len(tibiaBinary)
		}
		if rawEnd <= rawStart {
			continue
		}

		virtualSize := int(section.VirtualSize)
		if virtualSize < int(section.Size) {
			virtualSize = int(section.Size)
		}

		info.sections = append(info.sections, peSectionInfo{
			name:       strings.TrimRight(section.Name, "\x00"),
			rawStart:   rawStart,
			rawEnd:     rawEnd,
			rvaStart:   int(section.VirtualAddress),
			rvaEnd:     int(section.VirtualAddress) + virtualSize,
			isCode:     section.Characteristics&0x00000020 != 0 || section.Characteristics&0x20000000 != 0,
			isWritable: section.Characteristics&0x80000000 != 0,
		})
	}

	if peFile.FileHeader.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		for _, section := range info.sections {
			if section.name != ".pdata" {
				continue
			}

			for offset := section.rawStart; offset+12 <= section.rawEnd; offset += 12 {
				beginRVA := int(binary.LittleEndian.Uint32(tibiaBinary[offset : offset+4]))
				endRVA := int(binary.LittleEndian.Uint32(tibiaBinary[offset+4 : offset+8]))
				if beginRVA == 0 || endRVA <= beginRVA {
					continue
				}
				beginSection, beginOK := info.sectionForRVA(beginRVA)
				endSection, endOK := info.sectionForRVA(endRVA - 1)
				if !beginOK || !endOK || !beginSection.isCode || beginSection.name != endSection.name {
					continue
				}
				info.runtimeFunctions = append(info.runtimeFunctions, peRuntimeFunction{beginRVA: beginRVA, endRVA: endRVA})
			}
			break
		}
		sort.Slice(info.runtimeFunctions, func(left, right int) bool {
			return info.runtimeFunctions[left].beginRVA < info.runtimeFunctions[right].beginRVA
		})
	}

	if libraries, err := peFile.ImportedLibraries(); err == nil {
		info.imports = append(info.imports, libraries...)
	}
	if symbols, err := peFile.ImportedSymbols(); err == nil {
		info.imports = append(info.imports, symbols...)
	}
	sort.Strings(info.imports)

	return info
}

func buildStructuralPatchPlan(tibiaBinary []byte, peData peInfo, patches []battleyePatch) structuralPatchPlan {
	plan := structuralPatchPlan{
		matches:        make(map[int]structuralPatchMatch),
		verifiedGroups: make(map[string]bool),
	}
	groupMembers := make(map[string]int)
	groupUniqueMatches := make(map[string]int)

	for patchIndex, patch := range patches {
		if patch.structuralGuard == nil {
			continue
		}

		group := patch.structuralGuard.group
		groupMembers[group]++
		match := structuralPatchMatch{
			originalOffsets: patch.structurallyValidOffsets(tibiaBinary, peData, patch.original.findAll(tibiaBinary), false),
			patchedOffsets:  patch.structurallyValidOffsets(tibiaBinary, peData, patch.effectivePatchedPattern().findAll(tibiaBinary), true),
		}
		match.unique = len(match.originalOffsets)+len(match.patchedOffsets) == 1
		if match.unique {
			groupUniqueMatches[group]++
		}
		plan.matches[patchIndex] = match
	}

	for group, memberCount := range groupMembers {
		plan.verifiedGroups[group] = memberCount > 0 && groupUniqueMatches[group] == memberCount
	}
	return plan
}

func (plan structuralPatchPlan) groupFullyPatched(patches []battleyePatch, group string) bool {
	members := 0
	for patchIndex, patch := range patches {
		if patch.structuralGuard == nil || patch.structuralGuard.group != group {
			continue
		}
		members++
		match := plan.matches[patchIndex]
		if !match.unique || len(match.originalOffsets) != 0 || len(match.patchedOffsets) != 1 {
			return false
		}
	}
	return members > 0 && plan.verifiedGroups[group]
}

func (patch battleyePatch) structurallyValidOffsets(tibiaBinary []byte, peData peInfo, offsets []int, patched bool) []int {
	validOffsets := make([]int, 0, len(offsets))
	for _, offset := range offsets {
		if patch.isStructurallyValidAt(tibiaBinary, peData, offset, patched) {
			validOffsets = append(validOffsets, offset)
		}
	}
	return validOffsets
}

func (patch battleyePatch) isStructurallyValidAt(tibiaBinary []byte, peData peInfo, offset int, patched bool) bool {
	if patch.structuralGuard == nil || !peData.valid {
		return false
	}

	switch patch.structuralGuard.kind {
	case structuralClientCheckDisconnected:
		return validateClientCheckDisconnectedStructure(tibiaBinary, peData, offset, patched)
	case structuralEnableClientCheck:
		return validateEnableClientCheckStructure(tibiaBinary, peData, offset, patched)
	default:
		return false
	}
}

func validateClientCheckDisconnectedStructure(tibiaBinary []byte, peData peInfo, offset int, patched bool) bool {
	const bodyLength = 99
	if !peData.codeRangeWithinRuntimeFunction(offset, bodyLength, false) {
		return false
	}

	memberOffset := offset + 26
	if memberOffset < 0 || memberOffset+4 > len(tibiaBinary) {
		return false
	}
	memberDisplacement := int(int32(binary.LittleEndian.Uint32(tibiaBinary[memberOffset : memberOffset+4])))
	if memberDisplacement < 0x100 || memberDisplacement > 0x4000 || memberDisplacement%8 != 0 {
		return false
	}

	if !matchesRIPCString(tibiaBinary, peData, offset+36, "clientcheck_disconnected") ||
		!matchesRIPCString(tibiaBinary, peData, offset+62, "error") {
		return false
	}

	firstQtIATRVA, firstQtOK := relativeTargetRVA(tibiaBinary, peData, offset+47, 6, 2)
	secondQtIATRVA, secondQtOK := relativeTargetRVA(tibiaBinary, peData, offset+73, 6, 2)
	if !firstQtOK || !secondQtOK || firstQtIATRVA != secondQtIATRVA || !peData.rvaIsNonCode(firstQtIATRVA) {
		return false
	}

	if !relativeTargetIsCode(tibiaBinary, peData, offset+18, 5, 1) {
		return false
	}
	if !patched && !relativeTargetIsCode(tibiaBinary, peData, offset+93, 5, 1) {
		return false
	}

	return true
}

func validateEnableClientCheckStructure(tibiaBinary []byte, peData peInfo, offset int, patched bool) bool {
	const functionBodyLength = 40
	if !peData.codeRangeWithinRuntimeFunction(offset, functionBodyLength, true) {
		return false
	}
	section, ok := peData.sectionForOffset(offset)
	if !ok || !section.isCode || offset+44 > section.rawEnd || offset+44 > len(tibiaBinary) {
		return false
	}

	if !matchesRIPCString(tibiaBinary, peData, offset+4, "enableClientCheck") {
		return false
	}

	objectRVA, objectOK := relativeTargetRVA(tibiaBinary, peData, offset+11, 7, 3)
	objectSection, objectSectionOK := peData.sectionForRVA(objectRVA)
	if !objectOK || !objectSectionOK || !objectSection.isWritable || objectSection.isCode {
		return false
	}

	destructorThunkRVA, thunkOK := relativeTargetRVA(tibiaBinary, peData, offset+24, 7, 3)
	destructorThunkOffset, thunkOffsetOK := peData.offsetForRVA(destructorThunkRVA)
	if !thunkOK || !thunkOffsetOK || !peData.rvaIsCode(destructorThunkRVA) || destructorThunkOffset+14 > len(tibiaBinary) {
		return false
	}
	if !bytes.Equal(tibiaBinary[destructorThunkOffset:destructorThunkOffset+3], []byte{0x48, 0x8d, 0x0d}) ||
		!bytes.Equal(tibiaBinary[destructorThunkOffset+7:destructorThunkOffset+10], []byte{0x48, 0xff, 0x25}) {
		return false
	}

	thunkObjectRVA, thunkObjectOK := relativeTargetRVA(tibiaBinary, peData, destructorThunkOffset, 7, 3)
	destructorIATRVA, destructorIATOK := relativeTargetRVA(tibiaBinary, peData, destructorThunkOffset+7, 7, 3)
	if !thunkObjectOK || thunkObjectRVA != objectRVA || !destructorIATOK || !peData.rvaIsNonCode(destructorIATRVA) {
		return false
	}

	if !patched {
		constructorIATRVA, constructorOK := relativeTargetRVA(tibiaBinary, peData, offset+18, 6, 2)
		if !constructorOK || !peData.rvaIsNonCode(constructorIATRVA) {
			return false
		}
	}

	return relativeTargetIsCode(tibiaBinary, peData, offset+35, 5, 1)
}

func matchesRIPCString(tibiaBinary []byte, peData peInfo, instructionOffset int, value string) bool {
	targetRVA, ok := relativeTargetRVA(tibiaBinary, peData, instructionOffset, 7, 3)
	if !ok || !peData.rvaIsNonCode(targetRVA) {
		return false
	}
	targetOffset, ok := peData.offsetForRVA(targetRVA)
	if !ok || targetOffset < 0 || targetOffset+len(value) >= len(tibiaBinary) {
		return false
	}
	return bytes.Equal(tibiaBinary[targetOffset:targetOffset+len(value)], []byte(value)) && tibiaBinary[targetOffset+len(value)] == 0
}

func relativeTargetRVA(tibiaBinary []byte, peData peInfo, instructionOffset int, instructionLength int, displacementOffset int) (int, bool) {
	if instructionOffset < 0 || instructionOffset+displacementOffset+4 > len(tibiaBinary) {
		return 0, false
	}
	instructionRVA, ok := peData.rvaForOffset(instructionOffset)
	if !ok {
		return 0, false
	}
	displacement := int(int32(binary.LittleEndian.Uint32(tibiaBinary[instructionOffset+displacementOffset : instructionOffset+displacementOffset+4])))
	return instructionRVA + instructionLength + displacement, true
}

func relativeTargetIsCode(tibiaBinary []byte, peData peInfo, instructionOffset int, instructionLength int, displacementOffset int) bool {
	targetRVA, ok := relativeTargetRVA(tibiaBinary, peData, instructionOffset, instructionLength, displacementOffset)
	return ok && peData.rvaIsCode(targetRVA)
}

func scanClientCheckFindings(tibiaBinary []byte, peData peInfo, patchStatuses []battleyePatchStatus) []clientCheckFinding {
	findings := make([]clientCheckFinding, 0)
	for _, indicator := range clientCheckIndicators {
		findings = appendClientCheckFinding(findings, tibiaBinary, peData, patchStatuses, indicator.name, "ascii", indicator.value)

		utf16Value := utf16LEBytes(string(indicator.value))
		if len(utf16Value) > 0 {
			findings = appendClientCheckFinding(findings, tibiaBinary, peData, patchStatuses, indicator.name, "utf16-le", utf16Value)
		}
	}
	return findings
}

func appendClientCheckFinding(findings []clientCheckFinding, tibiaBinary []byte, peData peInfo, patchStatuses []battleyePatchStatus, name string, encoding string, needle []byte) []clientCheckFinding {
	offsets := findAllOffsets(tibiaBinary, needle)
	if len(offsets) == 0 {
		return findings
	}

	finding := clientCheckFinding{
		name:     name,
		encoding: encoding,
		offsets:  offsets,
	}

	if peData.valid {
		for _, offset := range offsets {
			finding.references = append(finding.references, findStringCodeReferences(tibiaBinary, peData, patchStatuses, name, offset)...)
		}
	}

	return append(findings, finding)
}

func findStringCodeReferences(tibiaBinary []byte, peData peInfo, patchStatuses []battleyePatchStatus, indicatorName string, stringOffset int) []clientCheckReference {
	stringRVA, ok := peData.rvaForOffset(stringOffset)
	if !ok {
		return nil
	}

	references := make([]clientCheckReference, 0)
	for _, section := range peData.sections {
		if !section.isCode {
			continue
		}

		for offset := section.rawStart; offset < section.rawEnd; offset++ {
			instructionLength, instructionName, displacementOffset, ok := ripRelativeInstructionAt(tibiaBinary, section.rawEnd, offset)
			if !ok {
				continue
			}

			instructionRVA, ok := peData.rvaForOffset(offset)
			if !ok {
				continue
			}

			displacement := int(int32(binary.LittleEndian.Uint32(tibiaBinary[displacementOffset : displacementOffset+4])))
			targetRVA := instructionRVA + instructionLength + displacement
			if targetRVA != stringRVA {
				continue
			}

			reference := clientCheckReference{
				offset:      offset,
				section:     section.name,
				instruction: instructionName,
			}
			reference = enrichCodeReferenceContext(tibiaBinary, section, reference, patchStatuses, indicatorName)
			references = append(references, reference)
		}
	}

	return dedupeAdjacentRexReferences(references)
}

func dedupeAdjacentRexReferences(references []clientCheckReference) []clientCheckReference {
	deduped := make([]clientCheckReference, 0, len(references))
	for _, reference := range references {
		if len(deduped) > 0 {
			previous := deduped[len(deduped)-1]
			if reference.offset == previous.offset+1 &&
				strings.Contains(previous.instruction, "REX:") &&
				(reference.instruction == "LEA" || reference.instruction == "MOV") {
				continue
			}
		}
		deduped = append(deduped, reference)
	}
	return deduped
}

func ripRelativeInstructionAt(tibiaBinary []byte, sectionEnd int, offset int) (int, string, int, bool) {
	if offset >= sectionEnd {
		return 0, "", 0, false
	}

	opcodeOffset := offset
	rexPrefix := byte(0)
	if tibiaBinary[opcodeOffset]&0xf0 == 0x40 {
		rexPrefix = tibiaBinary[opcodeOffset]
		opcodeOffset++
	}

	if opcodeOffset+6 > sectionEnd || opcodeOffset+6 > len(tibiaBinary) {
		return 0, "", 0, false
	}

	opcode := tibiaBinary[opcodeOffset]
	if opcode != 0x8d && opcode != 0x8b {
		return 0, "", 0, false
	}

	modRM := tibiaBinary[opcodeOffset+1]
	if modRM&0xc7 != 0x05 {
		return 0, "", 0, false
	}

	instructionLength := opcodeOffset - offset + 6
	instructionName := "rip-relative"
	if opcode == 0x8d {
		instructionName = "LEA"
	} else if opcode == 0x8b {
		instructionName = "MOV"
	}
	if rexPrefix != 0 {
		instructionName = fmt.Sprintf("%s REX:%02X", instructionName, rexPrefix)
	}

	return instructionLength, instructionName, opcodeOffset + 2, true
}

func enrichCodeReferenceContext(tibiaBinary []byte, section peSectionInfo, reference clientCheckReference, patchStatuses []battleyePatchStatus, indicatorName string) clientCheckReference {
	windowStart := reference.offset - codeContextRadius
	if windowStart < section.rawStart {
		windowStart = section.rawStart
	}
	windowEnd := reference.offset + codeContextRadius
	if windowEnd > section.rawEnd {
		windowEnd = section.rawEnd
	}

	reference.branchOffsets = findConditionalBranches(tibiaBinary, windowStart, windowEnd)
	reference.callOffsets = findCalls(tibiaBinary, windowStart, windowEnd)
	reference.patternMatches = findCodePatternMatches(tibiaBinary, windowStart, windowEnd)
	reference.knownPatchNearby = hasKnownPatchNearby(patchStatuses, reference.contextOffsets(), knownPatchContextRadius)
	reference.contextStart, reference.contextBytes = bytesAround(tibiaBinary, reference.offset, contextBytesRadius)
	reference.strongUnsupported = isStrongClientCheckEvidence(indicatorName, reference)
	reference.suspiciousActive = isSuspiciousActiveClientCheckEvidence(indicatorName, reference)

	return reference
}

func findConditionalBranches(tibiaBinary []byte, start int, end int) []int {
	offsets := make([]int, 0)
	for offset := start; offset < end && offset < len(tibiaBinary); offset++ {
		if isConditionalJump(tibiaBinary, offset, end) {
			offsets = append(offsets, offset)
		}
	}
	return offsets
}

func isStrongClientCheckEvidence(indicatorName string, reference clientCheckReference) bool {
	if !isCriticalClientCheckIndicator(indicatorName) {
		return false
	}
	if reference.knownPatchNearby {
		return false
	}
	if len(reference.branchOffsets) == 0 {
		return false
	}

	// Branches near Qt meta-object string references are common. Require a
	// recognized branch/call pattern before escalating from weak to strong.
	return len(reference.patternMatches) > 0
}

func isSuspiciousActiveClientCheckEvidence(indicatorName string, reference clientCheckReference) bool {
	if reference.strongUnsupported {
		return false
	}
	if reference.knownPatchNearby {
		return false
	}
	if !isCriticalClientCheckIndicator(indicatorName) {
		return false
	}
	if len(reference.branchOffsets) == 0 || len(reference.callOffsets) == 0 {
		return false
	}
	return true
}

func isCriticalClientCheckIndicator(indicatorName string) bool {
	switch indicatorName {
	case "clientcheck_disconnected",
		"onCloseDueToClientCheckRequested",
		"onClientCheckDialogButtonClicked",
		"enableClientCheck",
		"requestCloseDueToClientCheck":
		return true
	default:
		return false
	}
}

func isConditionalJump(data []byte, offset int, end int) bool {
	if offset < 0 || offset >= end || offset >= len(data) {
		return false
	}

	opcode := data[offset]
	if opcode >= 0x70 && opcode <= 0x7f {
		return true
	}

	return offset+1 < end &&
		offset+1 < len(data) &&
		opcode == 0x0f &&
		data[offset+1] >= 0x80 &&
		data[offset+1] <= 0x8f
}

func findCalls(tibiaBinary []byte, start int, end int) []int {
	offsets := make([]int, 0)
	for offset := start; offset < end && offset < len(tibiaBinary); offset++ {
		if offset+5 <= end && tibiaBinary[offset] == 0xe8 {
			offsets = append(offsets, offset)
			continue
		}
		if offset+2 <= end && tibiaBinary[offset] == 0xff && tibiaBinary[offset+1]&0x38 == 0x10 {
			offsets = append(offsets, offset)
		}
	}
	return offsets
}

func findCodePatternMatches(tibiaBinary []byte, start int, end int) []patternMatch {
	matches := make([]patternMatch, 0)
	if start < 0 {
		start = 0
	}
	if end > len(tibiaBinary) {
		end = len(tibiaBinary)
	}
	if end <= start {
		return matches
	}

	window := tibiaBinary[start:end]
	for _, pattern := range clientCheckCodePatterns {
		for _, offset := range pattern.findAll(window) {
			matches = append(matches, patternMatch{name: pattern.name, offset: start + offset})
		}
	}
	return matches
}

func hasKnownPatchNearby(patchStatuses []battleyePatchStatus, referenceOffsets []int, radius int) bool {
	for _, status := range patchStatuses {
		for _, knownOffset := range append(append([]int{}, status.originalOffset...), status.patchedOffset...) {
			for _, referenceOffset := range referenceOffsets {
				if absDistance(referenceOffset, knownOffset) <= radius {
					return true
				}
			}
		}
	}
	return false
}

func (reference clientCheckReference) contextOffsets() []int {
	offsets := []int{reference.offset}
	offsets = append(offsets, reference.branchOffsets...)
	offsets = append(offsets, reference.callOffsets...)
	for _, match := range reference.patternMatches {
		offsets = append(offsets, match.offset)
	}
	return offsets
}

func scanQtContextIndicators(tibiaBinary []byte, peData peInfo) []string {
	seen := make(map[string]struct{})
	for _, indicator := range qtContextIndicators {
		if bytes.Contains(tibiaBinary, []byte(indicator)) {
			seen[indicator+" string"] = struct{}{}
		}
		lowerIndicator := strings.ToLower(indicator)
		for _, importedName := range peData.imports {
			if strings.Contains(strings.ToLower(importedName), lowerIndicator) {
				seen[indicator+" import"] = struct{}{}
			}
		}
	}

	indicators := make([]string, 0, len(seen))
	for indicator := range seen {
		indicators = append(indicators, indicator)
	}
	sort.Strings(indicators)
	return indicators
}

func printDiagnosisReport(diagnosis diagnosisReport, label string) {
	fmt.Printf("[INFO] Diagnosing %s: %s\n", label, diagnosis.path)
	fmt.Printf("[INFO] Size: %d bytes\n", diagnosis.size)
	fmt.Printf("[INFO] SHA256: %s\n", diagnosis.sha256)

	if !diagnosis.isWindowsExe {
		fmt.Printf("[WARN] This file is not a Windows PE executable; BattlEye byte patch signatures are informational only\n")
	}
	if diagnosis.isWindowsExe && !diagnosis.pe.valid {
		fmt.Printf("[WARN] PE section parsing failed; code-reference diagnostics are unavailable: %s\n", diagnosis.pe.errorText)
	}

	logBattlEyeSignatureReport(diagnosis.patchStatuses)
	logClientCheckSupportSummary(diagnosis)
}

func logClientCheckSupportSummary(diagnosis diagnosisReport) {
	fmt.Printf("[INFO] Client-check support verdict: %s\n", diagnosis.clientCheckVerdict())
	fmt.Printf("[INFO] Known byte-patch coverage: %d/%d signature(s), original=%d, patched=%d\n",
		diagnosis.knownPatchCoverage(),
		patchableBattleyePatchCount(),
		diagnosis.originalPatchSignatureCount(),
		diagnosis.patchedPatchSignatureCount(),
	)

	if len(diagnosis.clientCheckFindings) == 0 {
		fmt.Printf("[INFO] No known client-check string indicators remain\n")
		return
	}

	logStrongUnsupportedEvidence(diagnosis)
	logSuspiciousActiveClientCheckEvidence(diagnosis)
	logWeakClientCheckIndicators(diagnosis)

	if len(diagnosis.qtIndicators) > 0 {
		fmt.Printf("[INFO] Qt context indicators: %s\n", strings.Join(diagnosis.qtIndicators, ", "))
	}

	if diagnosis.strongUnsupportedEvidenceCount() > 0 {
		fmt.Printf("[ERROR] Strong unsupported client-check evidence remains: %d code reference(s) combine a critical client-check string, nearby conditional branch, recognized branch/call pattern, and no known patch signature nearby\n", diagnosis.strongUnsupportedEvidenceCount())
	}
	if diagnosis.hasPatchedClientCheckSignature() && diagnosis.highRiskClientCheckDiagnosticCount() > 0 {
		fmt.Printf("[WARN] High-risk diagnostic-only client-check paths remain after a known patch was applied: %d signature(s)\n", diagnosis.highRiskClientCheckDiagnosticCount())
	}
	if diagnosis.hasPatchedClientCheckSignature() && diagnosis.suspiciousActiveEvidenceCount() > 0 {
		fmt.Printf("[WARN] Suspicious active client-check branch/call evidence remains after a known patch was applied: %d code reference(s)\n", diagnosis.suspiciousActiveEvidenceCount())
	}
}

func logStrongUnsupportedEvidence(diagnosis diagnosisReport) {
	strongCount := diagnosis.strongUnsupportedEvidenceCount()
	if strongCount == 0 {
		fmt.Printf("[INFO] Strong unsupported evidence: none\n")
		return
	}

	fmt.Printf("[ERROR] Strong unsupported evidence:\n")
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if !reference.strongUnsupported {
				continue
			}
			fmt.Printf("[ERROR]   %q (%s) string=%s ref=%s at 0x%X in %s branches=%s calls=%s patterns=%s knownPatchNearby=%t context48=%s possibleInstructions=%s\n",
				finding.name,
				finding.encoding,
				formatOffsetsLimited(finding.offsets, 4),
				reference.instruction,
				reference.offset,
				reference.section,
				formatNearestOffsets(reference.offset, reference.branchOffsets, 6),
				formatNearestOffsets(reference.offset, reference.callOffsets, 6),
				formatPatternMatches(reference.patternMatches, 4),
				reference.knownPatchNearby,
				formatBytes(reference.contextBytes),
				formatPossibleInstructions(reference),
			)
		}
	}
}

func logSuspiciousActiveClientCheckEvidence(diagnosis diagnosisReport) {
	suspiciousCount := diagnosis.suspiciousActiveEvidenceCount()
	if suspiciousCount == 0 {
		fmt.Printf("[INFO] Suspicious active client-check candidates: none\n")
		return
	}

	fmt.Printf("[WARN] Suspicious active client-check candidates:\n")
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if !reference.suspiciousActive {
				continue
			}
			fmt.Printf("[WARN]   %q (%s) string=%s ref=%s at 0x%X in %s nearestBranches=%s nearestCalls=%s patterns=%s knownPatchNearby=%t reason=%s context48=%s possibleInstructions=%s\n",
				finding.name,
				finding.encoding,
				formatOffsetsLimited(finding.offsets, 4),
				reference.instruction,
				reference.offset,
				reference.section,
				formatNearestOffsets(reference.offset, reference.branchOffsets, 8),
				formatNearestOffsets(reference.offset, reference.callOffsets, 8),
				formatPatternMatches(reference.patternMatches, 4),
				reference.knownPatchNearby,
				suspiciousEvidenceReason(finding.name, reference),
				formatBytes(reference.contextBytes),
				formatPossibleInstructions(reference),
			)
		}
	}
}

func logWeakClientCheckIndicators(diagnosis diagnosisReport) {
	fmt.Printf("[WARN] Weak indicators:\n")
	for _, finding := range diagnosis.clientCheckFindings {
		if len(finding.references) == 0 {
			fmt.Printf("[WARN]   %q (%s) string=%s refs=none reason=no code xref found\n", finding.name, finding.encoding, formatOffsetsLimited(finding.offsets, 8))
			continue
		}

		for _, reference := range finding.references {
			if reference.strongUnsupported || reference.suspiciousActive {
				continue
			}
			fmt.Printf("[WARN]   %q (%s) string=%s ref=%s at 0x%X in %s nearestBranches=%s nearestCalls=%s patterns=%s knownPatchNearby=%t reason=%s context48=%s possibleInstructions=%s\n",
				finding.name,
				finding.encoding,
				formatOffsetsLimited(finding.offsets, 4),
				reference.instruction,
				reference.offset,
				reference.section,
				formatNearestOffsets(reference.offset, reference.branchOffsets, 8),
				formatNearestOffsets(reference.offset, reference.callOffsets, 8),
				formatPatternMatches(reference.patternMatches, 4),
				reference.knownPatchNearby,
				weakEvidenceReason(finding.name, reference),
				formatBytes(reference.contextBytes),
				formatPossibleInstructions(reference),
			)
		}
	}
}

func suspiciousEvidenceReason(indicatorName string, reference clientCheckReference) string {
	if !isCriticalClientCheckIndicator(indicatorName) {
		return "non-critical indicator"
	}
	if len(reference.branchOffsets) == 0 {
		return "no conditional branch in context"
	}
	if len(reference.callOffsets) == 0 {
		return "no call in context"
	}
	if reference.knownPatchNearby {
		return "critical indicator has nearby branch and call; known nearby signature lowers this from strong to warning"
	}
	if len(reference.patternMatches) == 0 {
		return "critical indicator has nearby branch and call but no recognized branch/call signature"
	}
	return "candidate remains below strong-evidence threshold"
}

func weakEvidenceReason(indicatorName string, reference clientCheckReference) string {
	switch {
	case !isCriticalClientCheckIndicator(indicatorName):
		return "non-critical indicator"
	case reference.knownPatchNearby:
		return "known patch signature nearby"
	case len(reference.branchOffsets) == 0:
		return "no conditional branch in context"
	case len(reference.callOffsets) == 0:
		return "no call in context"
	case len(reference.patternMatches) == 0:
		return "no recognized branch/call pattern in context"
	default:
		return "not escalated"
	}
}

func printDiagnosisComparison(baseline diagnosisReport, target diagnosisReport) {
	fmt.Printf("[INFO] Comparative diagnosis: baseline=%s target=%s\n", baseline.path, target.path)
	fmt.Printf("[INFO] Size delta: %+d bytes\n", target.size-baseline.size)
	if baseline.sha256 == target.sha256 {
		fmt.Printf("[INFO] SHA256: identical\n")
	} else {
		fmt.Printf("[INFO] SHA256: baseline=%s target=%s\n", baseline.sha256, target.sha256)
	}

	fmt.Printf("[INFO] Known patch coverage: baseline=%d/%d target=%d/%d\n",
		baseline.knownPatchCoverage(),
		patchableBattleyePatchCount(),
		target.knownPatchCoverage(),
		patchableBattleyePatchCount(),
	)
	for _, patch := range battleyePatches {
		fmt.Printf("[INFO] Patch %q: baseline=%s target=%s\n",
			patch.name,
			baseline.patchStateByName(patch.name),
			target.patchStateByName(patch.name),
		)
	}

	fmt.Printf("[INFO] Client-check indicators: baseline=%d target=%d\n", baseline.clientCheckIndicatorCount(), target.clientCheckIndicatorCount())
	fmt.Printf("[INFO] Client-check code refs: baseline=%d target=%d\n", baseline.clientCheckCodeReferenceCount(), target.clientCheckCodeReferenceCount())
	fmt.Printf("[INFO] Strong unsupported evidence: baseline=%d target=%d\n", baseline.strongUnsupportedEvidenceCount(), target.strongUnsupportedEvidenceCount())
	fmt.Printf("[INFO] Suspicious active candidates: baseline=%d target=%d\n", baseline.suspiciousActiveEvidenceCount(), target.suspiciousActiveEvidenceCount())

	newIndicators := differenceStrings(target.clientCheckIndicatorKeys(), baseline.clientCheckIndicatorKeys())
	if len(newIndicators) > 0 {
		fmt.Printf("[WARN] New target-only client-check indicators: %s\n", strings.Join(newIndicators, ", "))
	}

	newStrongEvidence := differenceStrings(target.strongUnsupportedEvidenceKeys(), baseline.strongUnsupportedEvidenceKeys())
	if len(newStrongEvidence) > 0 {
		fmt.Printf("[ERROR] Target-only strong unsupported evidence: %s\n", strings.Join(newStrongEvidence, "; "))
	}

	newSuspiciousEvidence := differenceStrings(target.suspiciousActiveIndicatorKeys(), baseline.suspiciousActiveIndicatorKeys())
	if len(newSuspiciousEvidence) > 0 {
		fmt.Printf("[WARN] Target-only suspicious active candidates: %s\n", strings.Join(newSuspiciousEvidence, "; "))
	}
}

func enforceEditClientCheckPolicy(diagnosis diagnosisReport, strictClientCheck bool) {
	verdict := diagnosis.clientCheckVerdict()
	if diagnosis.strongUnsupportedEvidenceCount() > 0 {
		fmt.Printf("[ERROR] UNSUPPORTED support - refusing export because strong client-check evidence remains (%d code reference(s))\n", diagnosis.strongUnsupportedEvidenceCount())
		fmt.Printf("[ERROR] Verdict: %s\n", verdict)
		fmt.Printf("[ERROR] Run diagnose and inspect the Strong unsupported evidence section before using this client\n")
		os.Exit(1)
	}

	if diagnosis.isPartialClientCheckSupport() {
		if strictClientCheck {
			fmt.Printf("[ERROR] PARTIAL support - refusing export because --strict is enabled\n")
			fmt.Printf("[ERROR] Verdict: %s\n", verdict)
			fmt.Printf("[ERROR] Re-run without --strict only if this partial support is acceptable for manual testing\n")
			os.Exit(1)
		}

		fmt.Printf("[WARN] PARTIAL support - client may work but not fully verified\n")
		fmt.Printf("[WARN] Verdict: %s\n", verdict)
		return
	}

	if diagnosis.isWarningClientCheckSupport() {
		if strictClientCheck {
			fmt.Printf("[ERROR] WARNING support - refusing export because --strict is enabled\n")
			fmt.Printf("[ERROR] Verdict: %s\n", verdict)
			fmt.Printf("[ERROR] Re-run diagnose and inspect Suspicious active client-check candidates before using this client\n")
			os.Exit(1)
		}

		fmt.Printf("[WARN] WARNING support - client-check branch/call candidates remain after the known patch\n")
		fmt.Printf("[WARN] Client-check paths may still be active. Test recommended.\n")
		fmt.Printf("[WARN] Verdict: %s\n", verdict)
		return
	}

	fmt.Printf("[INFO] Client-check edit gate: %s\n", verdict)
}

func failIfStrictClientCheck(diagnosis diagnosisReport, strictClientCheck bool) {
	if !strictClientCheck || !diagnosis.hasUnsafeClientCheckRemainder() {
		return
	}

	fmt.Printf("[ERROR] Refusing to continue because strict client-check validation is enabled and the verdict is %s\n", diagnosis.clientCheckVerdict())
	os.Exit(1)
}

func (diagnosis diagnosisReport) hasUnsafeClientCheckRemainder() bool {
	return diagnosis.isPartialClientCheckSupport() || diagnosis.isWarningClientCheckSupport() || diagnosis.strongUnsupportedEvidenceCount() > 0
}

func (diagnosis diagnosisReport) isPartialClientCheckSupport() bool {
	return strings.HasPrefix(diagnosis.clientCheckVerdict(), "PARTIAL:")
}

func (diagnosis diagnosisReport) isWarningClientCheckSupport() bool {
	return strings.HasPrefix(diagnosis.clientCheckVerdict(), "WARNING:")
}

func logEditSuccess(diagnosis diagnosisReport, strictClientCheck bool) {
	if diagnosis.isPartialClientCheckSupport() {
		fmt.Printf("[WARN] Edit completed with PARTIAL support - client may work but not fully verified (strict=%t)\n", strictClientCheck)
		return
	}
	if diagnosis.isWarningClientCheckSupport() {
		fmt.Printf("[WARN] Edit completed with WARNING support - suspicious client-check branch/call candidates remain (strict=%t)\n", strictClientCheck)
		fmt.Printf("[WARN] Client-check paths may still be active. Test recommended.\n")
		return
	}

	fmt.Printf("[INFO] Edit completed with %s\n", diagnosis.clientCheckVerdict())
}

func (diagnosis diagnosisReport) clientCheckVerdict() string {
	strongEvidenceCount := diagnosis.strongUnsupportedEvidenceCount()
	if strongEvidenceCount > 0 {
		return "UNSUPPORTED: client-check code evidence remains"
	}
	if diagnosis.hasPatchedClientCheckSignature() && diagnosis.highRiskClientCheckDiagnosticCount() > 0 {
		return "WARNING: high risk of client-check remaining after known patch"
	}
	if diagnosis.hasPatchedClientCheckSignature() && diagnosis.suspiciousActiveEvidenceCount() > 0 {
		return "WARNING: known client-check patch applied but suspicious branch/call evidence remains"
	}
	if diagnosis.structuralGroupFullyPatched(structuralClientCheckGroup) {
		return "SUPPORTED: structurally verified client-check pair is patched and no strong client-check evidence remains"
	}

	coverage := diagnosis.knownPatchCoverage()
	patchableCount := patchableBattleyePatchCount()
	if coverage < patchableCount {
		return "PARTIAL: only some known patchable signatures are covered"
	}

	return "SUPPORTED: all known patchable signatures are covered and no strong client-check evidence remains"
}

func (diagnosis diagnosisReport) knownPatchCoverage() int {
	count := 0
	for _, status := range diagnosis.patchStatuses {
		if status.patch.diagnosticOnly {
			continue
		}
		if len(status.originalOffset) > 0 || len(status.patchedOffset) > 0 {
			count++
		}
	}
	return count
}

func (diagnosis diagnosisReport) originalPatchSignatureCount() int {
	count := 0
	for _, status := range diagnosis.patchStatuses {
		if status.patch.diagnosticOnly {
			continue
		}
		if len(status.originalOffset) > 0 {
			count++
		}
	}
	return count
}

func (diagnosis diagnosisReport) patchedPatchSignatureCount() int {
	count := 0
	for _, status := range diagnosis.patchStatuses {
		if status.patch.diagnosticOnly {
			continue
		}
		if len(status.patchedOffset) > 0 {
			count++
		}
	}
	return count
}

func (diagnosis diagnosisReport) hasPatchedClientCheckSignature() bool {
	return diagnosis.patchedPatchSignatureCount() > 0
}

func (diagnosis diagnosisReport) highRiskClientCheckDiagnosticCount() int {
	count := 0
	for _, status := range diagnosis.patchStatuses {
		if !status.patch.diagnosticOnly || !status.patch.highRiskClientCheck {
			continue
		}
		if len(status.originalOffset) > 0 {
			count++
		}
	}
	return count
}

func (diagnosis diagnosisReport) structuralGroupFullyPatched(group string) bool {
	members := 0
	for _, status := range diagnosis.patchStatuses {
		if status.patch.structuralGuard == nil || status.patch.structuralGuard.group != group {
			continue
		}
		members++
		if len(status.originalOffset) != 0 || len(status.patchedOffset) != 1 {
			return false
		}
	}
	return members > 0
}

func (diagnosis diagnosisReport) strongUnsupportedEvidenceCount() int {
	count := 0
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if reference.strongUnsupported {
				count++
			}
		}
	}
	return count
}

func (diagnosis diagnosisReport) suspiciousActiveEvidenceCount() int {
	count := 0
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if reference.suspiciousActive {
				count++
			}
		}
	}
	return count
}

func (diagnosis diagnosisReport) clientCheckIndicatorCount() int {
	count := 0
	for _, finding := range diagnosis.clientCheckFindings {
		count += len(finding.offsets)
	}
	return count
}

func (diagnosis diagnosisReport) clientCheckCodeReferenceCount() int {
	count := 0
	for _, finding := range diagnosis.clientCheckFindings {
		count += len(finding.references)
	}
	return count
}

func (diagnosis diagnosisReport) clientCheckIndicatorKeys() []string {
	keys := make([]string, 0)
	for _, finding := range diagnosis.clientCheckFindings {
		keys = append(keys, fmt.Sprintf("%s/%s", finding.name, finding.encoding))
	}
	sort.Strings(keys)
	return keys
}

func (diagnosis diagnosisReport) strongUnsupportedEvidenceKeys() []string {
	keys := make([]string, 0)
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if !reference.strongUnsupported {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s/%s ref=0x%X branches=%s calls=%s",
				finding.name,
				finding.encoding,
				reference.offset,
				formatOffsetsLimited(reference.branchOffsets, 3),
				formatOffsetsLimited(reference.callOffsets, 3),
			))
		}
	}
	sort.Strings(keys)
	return keys
}

func (diagnosis diagnosisReport) suspiciousActiveEvidenceKeys() []string {
	keys := make([]string, 0)
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if !reference.suspiciousActive {
				continue
			}
			keys = append(keys, fmt.Sprintf("%s/%s ref=0x%X branches=%s calls=%s",
				finding.name,
				finding.encoding,
				reference.offset,
				formatNearestOffsets(reference.offset, reference.branchOffsets, 3),
				formatNearestOffsets(reference.offset, reference.callOffsets, 3),
			))
		}
	}
	sort.Strings(keys)
	return keys
}

func (diagnosis diagnosisReport) suspiciousActiveIndicatorKeys() []string {
	keySet := make(map[string]struct{})
	for _, finding := range diagnosis.clientCheckFindings {
		for _, reference := range finding.references {
			if !reference.suspiciousActive {
				continue
			}
			keySet[fmt.Sprintf("%s/%s", finding.name, finding.encoding)] = struct{}{}
		}
	}

	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (diagnosis diagnosisReport) patchStateByName(name string) string {
	for _, status := range diagnosis.patchStatuses {
		if status.patch.name != name {
			continue
		}

		switch {
		case len(status.originalOffset) > 0 && len(status.patchedOffset) > 0:
			return fmt.Sprintf("mixed original=%s patched=%s", formatOffsetsLimited(status.originalOffset, 4), formatOffsetsLimited(status.patchedOffset, 4))
		case len(status.originalOffset) > 0:
			return "original at " + formatOffsetsLimited(status.originalOffset, 4)
		case len(status.patchedOffset) > 0:
			return "patched at " + formatOffsetsLimited(status.patchedOffset, 4)
		default:
			return "absent"
		}
	}
	return "unknown"
}

func findAllOffsets(data []byte, needle []byte) []int {
	offsets := make([]int, 0)
	if len(needle) == 0 || len(data) < len(needle) {
		return offsets
	}

	searchOffset := 0
	for searchOffset <= len(data)-len(needle) {
		index := bytes.Index(data[searchOffset:], needle)
		if index == -1 {
			break
		}

		offset := searchOffset + index
		offsets = append(offsets, offset)
		searchOffset = offset + len(needle)
	}
	return offsets
}

func formatOffsets(offsets []int) string {
	return formatOffsetsLimited(offsets, 0)
}

func formatOffsetsLimited(offsets []int, limit int) string {
	if len(offsets) == 0 {
		return "none"
	}

	displayOffsets := offsets
	truncated := 0
	if limit > 0 && len(offsets) > limit {
		displayOffsets = offsets[:limit]
		truncated = len(offsets) - limit
	}

	formatted := make([]string, 0, len(displayOffsets))
	for _, offset := range displayOffsets {
		formatted = append(formatted, fmt.Sprintf("0x%X", offset))
	}
	if truncated > 0 {
		formatted = append(formatted, fmt.Sprintf("... +%d more", truncated))
	}
	return strings.Join(formatted, ", ")
}

func formatNearestOffsets(anchor int, offsets []int, limit int) string {
	if len(offsets) == 0 {
		return "none"
	}

	displayOffsets := append([]int(nil), offsets...)
	sort.SliceStable(displayOffsets, func(left int, right int) bool {
		leftDistance := absDistance(anchor, displayOffsets[left])
		rightDistance := absDistance(anchor, displayOffsets[right])
		if leftDistance == rightDistance {
			return displayOffsets[left] < displayOffsets[right]
		}
		return leftDistance < rightDistance
	})

	truncated := 0
	if limit > 0 && len(displayOffsets) > limit {
		truncated = len(displayOffsets) - limit
		displayOffsets = displayOffsets[:limit]
	}

	formatted := make([]string, 0, len(displayOffsets)+1)
	for _, offset := range displayOffsets {
		delta := offset - anchor
		if delta >= 0 {
			formatted = append(formatted, fmt.Sprintf("0x%X(+0x%X)", offset, delta))
			continue
		}
		formatted = append(formatted, fmt.Sprintf("0x%X(-0x%X)", offset, -delta))
	}
	if truncated > 0 {
		formatted = append(formatted, fmt.Sprintf("... +%d more", truncated))
	}
	return strings.Join(formatted, ", ")
}

func formatPatternMatches(matches []patternMatch, limit int) string {
	if len(matches) == 0 {
		return "none"
	}

	displayMatches := matches
	truncated := 0
	if limit > 0 && len(matches) > limit {
		displayMatches = matches[:limit]
		truncated = len(matches) - limit
	}

	formatted := make([]string, 0, len(displayMatches))
	for _, match := range displayMatches {
		formatted = append(formatted, fmt.Sprintf("%s@0x%X", match.name, match.offset))
	}
	if truncated > 0 {
		formatted = append(formatted, fmt.Sprintf("... +%d more", truncated))
	}
	return strings.Join(formatted, ", ")
}

func bytesAround(data []byte, center int, radius int) (int, []byte) {
	if len(data) == 0 || center < 0 || center >= len(data) {
		return 0, nil
	}

	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius
	if end > len(data) {
		end = len(data)
	}

	return start, append([]byte(nil), data[start:end]...)
}

func bytesAroundRange(data []byte, start int, length int, radius int) (int, []byte) {
	if len(data) == 0 || start < 0 || start >= len(data) || length <= 0 {
		return 0, nil
	}

	end := start + length
	if end > len(data) {
		end = len(data)
	}

	contextStart := start - radius
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + radius
	if contextEnd > len(data) {
		contextEnd = len(data)
	}

	return contextStart, append([]byte(nil), data[contextStart:contextEnd]...)
}

func formatBytes(data []byte) string {
	if len(data) == 0 {
		return "none"
	}
	return fmt.Sprintf("% X", data)
}

func formatPossibleInstructions(reference clientCheckReference) string {
	if len(reference.contextBytes) == 0 {
		return "none"
	}

	instructions := make([]string, 0)
	for index := 0; index < len(reference.contextBytes); index++ {
		offset := reference.contextStart + index
		data := reference.contextBytes[index:]

		if len(data) >= 7 && data[0] == 0x48 && data[1] == 0x8d && (data[2] == 0x15 || data[2] == 0x0d) {
			registerName := "rdx"
			if data[2] == 0x0d {
				registerName = "rcx"
			}
			displacement := int(int32(binary.LittleEndian.Uint32(data[3:7])))
			target := offset + 7 + displacement
			instructions = append(instructions, fmt.Sprintf("0x%X: lea %s,[rip%+d] -> 0x%X", offset, registerName, displacement, target))
			index += 6
			continue
		}
		if len(data) >= 4 && data[0] == 0x48 && data[1] == 0x8d && data[2] == 0x4d {
			instructions = append(instructions, fmt.Sprintf("0x%X: lea rcx,[rbp%+d]", offset, int(int8(data[3]))))
			index += 3
			continue
		}
		if len(data) >= 6 && data[0] == 0x41 && data[1] == 0xb8 {
			immediate := binary.LittleEndian.Uint32(data[2:6])
			instructions = append(instructions, fmt.Sprintf("0x%X: mov r8d,0x%X", offset, immediate))
			index += 5
			continue
		}
		if len(data) >= 5 && data[0] == 0xe8 {
			displacement := int(int32(binary.LittleEndian.Uint32(data[1:5])))
			target := offset + 5 + displacement
			instructions = append(instructions, fmt.Sprintf("0x%X: call rel32 -> 0x%X", offset, target))
			index += 4
			continue
		}
		if len(data) >= 6 && data[0] == 0xff && data[1] == 0x15 {
			displacement := int(int32(binary.LittleEndian.Uint32(data[2:6])))
			target := offset + 6 + displacement
			instructions = append(instructions, fmt.Sprintf("0x%X: call qword [rip%+d] -> 0x%X", offset, displacement, target))
			index += 5
			continue
		}
		if len(data) >= 5 && data[0] == 0xe9 {
			displacement := int(int32(binary.LittleEndian.Uint32(data[1:5])))
			target := offset + 5 + displacement
			instructions = append(instructions, fmt.Sprintf("0x%X: jmp rel32 -> 0x%X", offset, target))
			index += 4
			continue
		}
		if len(data) >= 2 && data[0] == 0xeb {
			target := offset + 2 + int(int8(data[1]))
			instructions = append(instructions, fmt.Sprintf("0x%X: jmp short -> 0x%X", offset, target))
			index += 1
			continue
		}
		if isConditionalJump(reference.contextBytes, index, len(reference.contextBytes)) {
			if data[0] >= 0x70 && data[0] <= 0x7f && len(data) >= 2 {
				target := offset + 2 + int(int8(data[1]))
				instructions = append(instructions, fmt.Sprintf("0x%X: jcc short 0x%02X -> 0x%X", offset, data[0], target))
				index += 1
				continue
			}
			if len(data) >= 6 && data[0] == 0x0f {
				displacement := int(int32(binary.LittleEndian.Uint32(data[2:6])))
				target := offset + 6 + displacement
				instructions = append(instructions, fmt.Sprintf("0x%X: jcc near 0x%02X -> 0x%X", offset, data[1], target))
				index += 5
				continue
			}
		}
		if len(data) >= 4 && data[0] == 0x48 && data[1] == 0x83 && (data[2] == 0xec || data[2] == 0xc4) {
			operation := "sub"
			if data[2] == 0xc4 {
				operation = "add"
			}
			instructions = append(instructions, fmt.Sprintf("0x%X: %s rsp,0x%X", offset, operation, data[3]))
			index += 3
			continue
		}
	}

	if len(instructions) == 0 {
		return "none"
	}
	if len(instructions) > 10 {
		return strings.Join(instructions[:10], "; ") + fmt.Sprintf("; ... +%d more", len(instructions)-10)
	}
	return strings.Join(instructions, "; ")
}

func newBytePattern(name string, values ...int) bytePattern {
	pattern := bytePattern{
		name: name,
		data: make([]byte, len(values)),
		mask: make([]bool, len(values)),
	}

	for index, value := range values {
		if value == wildcardByte {
			continue
		}
		if value < 0 || value > 0xff {
			panic(fmt.Sprintf("invalid byte pattern value %d in %s", value, name))
		}
		pattern.data[index] = byte(value)
		pattern.mask[index] = true
	}

	return pattern
}

func (pattern bytePattern) formatAOB() string {
	if len(pattern.data) == 0 {
		return "none"
	}

	parts := make([]string, 0, len(pattern.data))
	for index, value := range pattern.data {
		if !pattern.mask[index] {
			parts = append(parts, "??")
			continue
		}
		parts = append(parts, fmt.Sprintf("%02X", value))
	}
	return strings.Join(parts, " ")
}

func newPatchReplacement(values ...int) []int {
	replacement := make([]int, len(values))
	for index, value := range values {
		if value == wildcardByte {
			replacement[index] = wildcardByte
			continue
		}
		if value < 0 || value > 0xff {
			panic(fmt.Sprintf("invalid patch replacement value %d", value))
		}
		replacement[index] = value
	}
	return replacement
}

func applyBattleyePatch(tibiaBinary []byte, patch battleyePatch, offsets []int) []byte {
	if patch.diagnosticOnly {
		return tibiaBinary
	}
	if len(patch.replacement) != len(patch.original.data) {
		fmt.Printf("[ERROR] Invalid BattlEye patch %q: replacement length differs from signature length\n", patch.name)
		os.Exit(1)
	}

	for _, offset := range offsets {
		contextStart, beforeBytes := bytesAroundRange(tibiaBinary, offset, len(patch.replacement), patchContextRadius)
		for index, value := range patch.replacement {
			if value == wildcardByte {
				continue
			}
			tibiaBinary[offset+index] = byte(value)
		}
		_, afterBytes := bytesAroundRange(tibiaBinary, offset, len(patch.replacement), patchContextRadius)
		contextEnd := contextStart + len(beforeBytes)
		fmt.Printf("[INFO]   bytes before @0x%X..0x%X: %s\n", contextStart, contextEnd, formatBytes(beforeBytes))
		fmt.Printf("[INFO]   bytes after  @0x%X..0x%X: %s\n", contextStart, contextEnd, formatBytes(afterBytes))
	}
	return tibiaBinary
}

func patchableBattleyePatchCount() int {
	count := 0
	for _, patch := range battleyePatches {
		if !patch.diagnosticOnly {
			count++
		}
	}
	return count
}

func (patch battleyePatch) withAggressiveMode(aggressive bool) battleyePatch {
	if !aggressive || len(patch.aggressiveReplacement) == 0 {
		return patch
	}

	if len(patch.aggressiveReplacement) != len(patch.original.data) {
		fmt.Printf("[ERROR] Invalid aggressive replacement for signature %q: replacement length differs from signature length\n", patch.name)
		os.Exit(1)
	}

	patch.replacement = append([]int(nil), patch.aggressiveReplacement...)
	patch.patched = newBytePattern(patch.name+" [aggressive]", patch.aggressiveReplacement...)

	return patch
}

func (patch battleyePatch) effectivePatchedPattern() bytePattern {
	if len(patch.patched.data) > 0 {
		return patch.patched
	}
	if len(patch.aggressiveReplacement) > 0 {
		return newBytePattern(patch.name+" [aggressive]", patch.aggressiveReplacement...)
	}
	return bytePattern{}
}

func (pattern bytePattern) findAll(data []byte) []int {
	offsets := make([]int, 0)
	if len(pattern.data) == 0 || len(data) < len(pattern.data) {
		return offsets
	}

	for offset := 0; offset <= len(data)-len(pattern.data); offset++ {
		if pattern.matchesAt(data, offset) {
			offsets = append(offsets, offset)
		}
	}
	return offsets
}

func (pattern bytePattern) matchesAt(data []byte, offset int) bool {
	if offset < 0 || offset+len(pattern.data) > len(data) {
		return false
	}

	for index := range pattern.data {
		if pattern.mask[index] && data[offset+index] != pattern.data[index] {
			return false
		}
	}
	return true
}

func (patch battleyePatch) expectedOffsetHits(data []byte, sha256Text string) []knownPatchOffset {
	hits := make([]knownPatchOffset, 0)
	for _, expected := range patch.expectedOffsets {
		if !expected.appliesToSHA256(sha256Text) {
			continue
		}
		if patch.matchesAtExpectedOffset(data, expected.offset) {
			hits = append(hits, expected)
		}
	}
	return hits
}

func (patch battleyePatch) expectedOffsetMisses(data []byte, sha256Text string) []knownPatchOffset {
	misses := make([]knownPatchOffset, 0)
	for _, expected := range patch.expectedOffsets {
		if !expected.appliesToSHA256(sha256Text) {
			continue
		}
		if !patch.matchesAtExpectedOffset(data, expected.offset) {
			misses = append(misses, expected)
		}
	}
	return misses
}

func (patch battleyePatch) matchesAtExpectedOffset(data []byte, offset int) bool {
	return patch.original.matchesAt(data, offset) || patch.effectivePatchedPattern().matchesAt(data, offset)
}

func (expected knownPatchOffset) appliesToSHA256(sha256Text string) bool {
	return expected.sha256 == "" || strings.EqualFold(expected.sha256, sha256Text)
}

func (peData peInfo) rvaForOffset(offset int) (int, bool) {
	for _, section := range peData.sections {
		if offset >= section.rawStart && offset < section.rawEnd {
			return section.rvaStart + offset - section.rawStart, true
		}
	}
	return 0, false
}

func (peData peInfo) offsetForRVA(rva int) (int, bool) {
	section, ok := peData.sectionForRVA(rva)
	if !ok {
		return 0, false
	}
	offset := section.rawStart + rva - section.rvaStart
	if offset < section.rawStart || offset >= section.rawEnd {
		return 0, false
	}
	return offset, true
}

func (peData peInfo) sectionForOffset(offset int) (peSectionInfo, bool) {
	for _, section := range peData.sections {
		if offset >= section.rawStart && offset < section.rawEnd {
			return section, true
		}
	}
	return peSectionInfo{}, false
}

func (peData peInfo) sectionForRVA(rva int) (peSectionInfo, bool) {
	for _, section := range peData.sections {
		if rva >= section.rvaStart && rva < section.rvaEnd {
			return section, true
		}
	}
	return peSectionInfo{}, false
}

func (peData peInfo) rvaIsCode(rva int) bool {
	section, ok := peData.sectionForRVA(rva)
	return ok && section.isCode
}

func (peData peInfo) rvaIsNonCode(rva int) bool {
	section, ok := peData.sectionForRVA(rva)
	return ok && !section.isCode
}

func (peData peInfo) runtimeFunctionContainingRVA(rva int) (peRuntimeFunction, bool) {
	index := sort.Search(len(peData.runtimeFunctions), func(index int) bool {
		return peData.runtimeFunctions[index].endRVA > rva
	})
	if index >= len(peData.runtimeFunctions) {
		return peRuntimeFunction{}, false
	}
	function := peData.runtimeFunctions[index]
	if rva < function.beginRVA || rva >= function.endRVA {
		return peRuntimeFunction{}, false
	}
	return function, true
}

func (peData peInfo) codeRangeWithinRuntimeFunction(offset int, length int, requireExactFunction bool) bool {
	if length <= 0 {
		return false
	}
	startSection, startSectionOK := peData.sectionForOffset(offset)
	endSection, endSectionOK := peData.sectionForOffset(offset + length - 1)
	if !startSectionOK || !endSectionOK || !startSection.isCode || startSection.name != endSection.name {
		return false
	}
	startRVA, startRVAOK := peData.rvaForOffset(offset)
	endRVA, endRVAOK := peData.rvaForOffset(offset + length - 1)
	if !startRVAOK || !endRVAOK {
		return false
	}
	endRVA++
	function, ok := peData.runtimeFunctionContainingRVA(startRVA)
	if !ok || endRVA > function.endRVA {
		return false
	}
	if requireExactFunction && (function.beginRVA != startRVA || function.endRVA != endRVA) {
		return false
	}
	return true
}

func utf16LEBytes(value string) []byte {
	if value == "" {
		return nil
	}

	encoded := make([]byte, 0, len(value)*2)
	for _, char := range value {
		if char > 0xffff {
			continue
		}
		encoded = append(encoded, byte(char), byte(char>>8))
	}
	return encoded
}

func hasClientCheckStringIndicators(tibiaBinary []byte) bool {
	for _, indicator := range clientCheckIndicators {
		if bytes.Contains(tibiaBinary, indicator.value) || bytes.Contains(tibiaBinary, utf16LEBytes(string(indicator.value))) {
			return true
		}
	}
	return false
}

func differenceStrings(left []string, right []string) []string {
	rightSet := make(map[string]struct{}, len(right))
	for _, value := range right {
		rightSet[value] = struct{}{}
	}

	difference := make([]string, 0)
	for _, value := range left {
		if _, ok := rightSet[value]; !ok {
			difference = append(difference, value)
		}
	}
	sort.Strings(difference)
	return difference
}

func absDistance(left int, right int) int {
	distance := left - right
	if distance < 0 {
		return -distance
	}
	return distance
}

func exportModifiedFile(tibiaPath string, tibiaBinary []byte, originalBinarySize int) {
	outputFilePath := tibiaPath

	if len(tibiaBinary) != originalBinarySize {
		fmt.Printf("[ERROR] Invalid patched file size, original: %d, modified: %d\n", originalBinarySize, len(tibiaBinary))
		os.Exit(1)
	}

	err := os.WriteFile(outputFilePath, tibiaBinary, 0644)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("[INFO] Patched file exported to: %s\n", outputFilePath)
}

func readFile(filePath string) (string, []byte) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	return filePath, fileData
}

func resolveSourceExecutable(tibiaExe string, sourceTibiaExe string) string {
	if sourceTibiaExe != "" {
		return sourceTibiaExe
	}

	defaultSource := filepath.Join(filepath.Dir(tibiaExe), "client - original.exe")
	if clean(defaultSource) == clean(tibiaExe) {
		return clean(tibiaExe)
	}

	if _, err := os.Stat(defaultSource); err == nil {
		return defaultSource
	}

	return tibiaExe
}

func clean(path string) string {
	return filepath.Clean(path)
}

func neutralizeBranchJumpPattern(pattern bytePattern, patch map[int]int) []int {
	replacement := make([]int, len(pattern.data))
	for index := range replacement {
		if index >= len(pattern.mask) || !pattern.mask[index] {
			replacement[index] = wildcardByte
			continue
		}
		replacement[index] = int(pattern.data[index])
	}

	for index, value := range patch {
		if index < 0 || index >= len(replacement) {
			panic(fmt.Sprintf("invalid branch neutralization offset %d for pattern %d bytes", index, len(replacement)))
		}
		if value < 0 || value > 0xff {
			panic(fmt.Sprintf("invalid branch neutralization byte %d at position %d", value, index))
		}
		replacement[index] = value
	}
	return replacement
}

type configINIKeyValue struct {
	key   string
	value string
}

type configINISection struct {
	name      string
	keys      []configINIKeyValue
	keyValues map[string]string
}

type embeddedConfigINI struct {
	sections      []configINISection
	sectionByName map[string]configINISection
}

func syncConfigINI(tibiaPath string, tibiaBinary []byte, configValues map[string]string) {
	embeddedConfigData, ok := extractEmbeddedConfigINIBlock(tibiaBinary)
	if !ok {
		fmt.Printf("[WARN] Embedded config.ini block starting at %q was not found; %s sync skipped\n", configINIStartMarker, configINIFileName)
		return
	}

	embeddedConfig, ok := parseEmbeddedConfigINI(embeddedConfigData)
	if !ok {
		fmt.Printf("[WARN] Embedded config.ini block could not be parsed; %s sync skipped\n", configINIFileName)
		return
	}
	embeddedConfig = overrideEmbeddedConfigValues(embeddedConfig, configValues)

	configPath, configExists := resolveConfigINIPath(tibiaPath)
	configData := make([]byte, 0)
	if configExists {
		data, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Printf("[ERROR] Unable to read %s: %s\n", configPath, err.Error())
			os.Exit(1)
		}
		configData = data
	}

	updatedConfig, changedCount, addedCount, removedCount, changed := updateConfigINIContent(configData, embeddedConfig)
	if !changed {
		fmt.Printf("[INFO] %s already up to date\n", configINIFileName)
		return
	}

	if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
		fmt.Printf("[ERROR] Unable to write %s: %s\n", configPath, err.Error())
		os.Exit(1)
	}

	if configExists {
		fmt.Printf("[PATCH] %s updated from embedded client config (%d outdated value(s), %d new key(s), %d obsolete key(s) removed)\n", configINIFileName, changedCount, addedCount, removedCount)
		return
	}
	fmt.Printf("[PATCH] %s created from embedded client config (%d key(s))\n", configINIFileName, addedCount)
}

func resolveConfigINIPath(tibiaPath string) (string, bool) {
	tibiaDir := filepath.Dir(tibiaPath)
	confConfigPath := filepath.Clean(filepath.Join(tibiaDir, "..", configINIDirName, configINIFileName))
	binConfigPath := filepath.Join(tibiaDir, configINIFileName)

	for _, candidate := range []string{confConfigPath, binConfigPath} {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, true
		}
	}

	confDir := filepath.Dir(confConfigPath)
	if info, err := os.Stat(confDir); err == nil && info.IsDir() {
		return confConfigPath, false
	}

	return binConfigPath, false
}

func extractEmbeddedConfigINIBlock(tibiaBinary []byte) ([]byte, bool) {
	start := bytes.Index(tibiaBinary, []byte(configINIStartMarker))
	if start == -1 {
		return nil, false
	}

	end := start
	for end < len(tibiaBinary) {
		value := tibiaBinary[end]
		if value == 0 {
			break
		}
		if value == '\r' || value == '\n' || value == '\t' || (value >= 0x20 && value <= 0x7e) {
			end++
			continue
		}
		break
	}

	if end <= start {
		return nil, false
	}
	return tibiaBinary[start:end], true
}

func parseEmbeddedConfigINI(configData []byte) (embeddedConfigINI, bool) {
	config := embeddedConfigINI{}
	currentSectionIndex := -1
	for _, line := range splitConfigINILines(configData) {
		if sectionName, ok := parseConfigINISectionLine(line); ok {
			config.sections = append(config.sections, configINISection{
				name:      sectionName,
				keyValues: make(map[string]string),
			})
			currentSectionIndex = len(config.sections) - 1
			continue
		}

		if currentSectionIndex == -1 {
			continue
		}

		key, value, ok := splitConfigINILine(line)
		if !ok {
			continue
		}

		section := &config.sections[currentSectionIndex]
		if _, exists := section.keyValues[key]; exists {
			continue
		}
		section.keys = append(section.keys, configINIKeyValue{key: key, value: value})
		section.keyValues[key] = value
	}

	totalKeys := 0
	config.sectionByName = make(map[string]configINISection, len(config.sections))
	for _, section := range config.sections {
		config.sectionByName[section.name] = section
		totalKeys += len(section.keys)
	}

	return config, totalKeys > 0
}

func overrideEmbeddedConfigValues(embeddedConfig embeddedConfigINI, configValues map[string]string) embeddedConfigINI {
	for sectionIndex := range embeddedConfig.sections {
		section := &embeddedConfig.sections[sectionIndex]
		for keyIndex := range section.keys {
			value, ok := configValues[section.keys[keyIndex].key]
			if !ok {
				continue
			}

			section.keys[keyIndex].value = value
			section.keyValues[section.keys[keyIndex].key] = value
		}
	}

	embeddedConfig.sectionByName = make(map[string]configINISection, len(embeddedConfig.sections))
	for _, section := range embeddedConfig.sections {
		embeddedConfig.sectionByName[section.name] = section
	}
	return embeddedConfig
}

func updateConfigINIContent(configData []byte, embeddedConfig embeddedConfigINI) ([]byte, int, int, int, bool) {
	lineEnding := detectLineEnding(configData)
	if len(configData) == 0 {
		return renderEmbeddedConfigINI(embeddedConfig, lineEnding), 0, embeddedConfigKeyCount(embeddedConfig), 0, true
	}

	lines := splitConfigINILines(configData)
	output := make([]string, 0, len(lines)+embeddedConfigKeyCount(embeddedConfig))
	seenSections := make(map[string]struct{}, len(embeddedConfig.sections))
	seenKeys := make(map[string]map[string]struct{}, len(embeddedConfig.sections))
	changedCount := 0
	addedCount := 0
	removedCount := 0
	currentSection := ""
	currentManaged := false

	appendMissingKeys := func(sectionName string) {
		section, ok := embeddedConfig.sectionByName[sectionName]
		if !ok {
			return
		}
		if _, ok := seenKeys[sectionName]; !ok {
			seenKeys[sectionName] = make(map[string]struct{}, len(section.keys))
		}
		for _, item := range section.keys {
			if _, ok := seenKeys[sectionName][item.key]; ok {
				continue
			}
			output = append(output, item.key+"="+item.value)
			seenKeys[sectionName][item.key] = struct{}{}
			addedCount++
		}
	}

	for _, line := range lines {
		if sectionName, ok := parseConfigINISectionLine(line); ok {
			if currentManaged {
				appendMissingKeys(currentSection)
			}

			currentSection = sectionName
			_, currentManaged = embeddedConfig.sectionByName[currentSection]
			if currentManaged {
				seenSections[currentSection] = struct{}{}
				if _, ok := seenKeys[currentSection]; !ok {
					seenKeys[currentSection] = make(map[string]struct{})
				}
			}

			output = append(output, line)
			continue
		}

		if currentManaged {
			key, _, ok := splitConfigINILine(line)
			if ok {
				section := embeddedConfig.sectionByName[currentSection]
				value, exists := section.keyValues[key]
				if !exists {
					removedCount++
					continue
				}
				if _, duplicate := seenKeys[currentSection][key]; duplicate {
					removedCount++
					continue
				}

				seenKeys[currentSection][key] = struct{}{}
				nextLine := key + "=" + value
				if line != nextLine {
					output = append(output, nextLine)
					changedCount++
					continue
				}
			}
		}

		output = append(output, line)
	}

	if currentManaged {
		appendMissingKeys(currentSection)
	}

	for _, section := range embeddedConfig.sections {
		if _, ok := seenSections[section.name]; ok {
			continue
		}
		if len(output) > 0 && strings.TrimSpace(output[len(output)-1]) != "" {
			output = append(output, "")
		}
		output = append(output, "["+section.name+"]")
		for _, item := range section.keys {
			output = append(output, item.key+"="+item.value)
			addedCount++
		}
	}

	if changedCount == 0 && addedCount == 0 && removedCount == 0 {
		return configData, 0, 0, 0, false
	}

	return []byte(strings.Join(output, lineEnding) + lineEnding), changedCount, addedCount, removedCount, true
}

func splitConfigINILines(configData []byte) []string {
	normalized := strings.ReplaceAll(string(configData), "\r\n", "\n")
	normalized = strings.TrimRight(normalized, "\x00")
	normalized = strings.TrimSuffix(normalized, "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}

func parseConfigINISectionLine(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 3 || !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", false
	}

	sectionName := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	if sectionName == "" {
		return "", false
	}
	return sectionName, true
}

func renderEmbeddedConfigINI(embeddedConfig embeddedConfigINI, lineEnding string) []byte {
	lines := make([]string, 0, embeddedConfigKeyCount(embeddedConfig)+len(embeddedConfig.sections)*2)
	for index, section := range embeddedConfig.sections {
		if index > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "["+section.name+"]")
		for _, item := range section.keys {
			lines = append(lines, item.key+"="+item.value)
		}
	}
	return []byte(strings.Join(lines, lineEnding) + lineEnding)
}

func embeddedConfigKeyCount(embeddedConfig embeddedConfigINI) int {
	total := 0
	for _, section := range embeddedConfig.sections {
		total += len(section.keys)
	}
	return total
}

func splitConfigINILine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return "", "", false
	}

	separator := strings.Index(trimmed, "=")
	if separator <= 0 {
		return "", "", false
	}

	key := strings.TrimSpace(trimmed[:separator])
	value := strings.TrimSpace(trimmed[separator+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

func detectLineEnding(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func setPropertyByName(tibiaBinary []byte, propertyName string, customValue string) bool {
	originalBinarySize := len(tibiaBinary)
	propertyName = fmt.Sprintf("%s=", propertyName)
	propertyIndex := bytes.Index(tibiaBinary, []byte(propertyName))
	if propertyIndex != -1 {
		// Extract current property value
		startValue := propertyIndex + len(propertyName)
		endValue := startValue + bytes.IndexByte(tibiaBinary[startValue:], '\n')
		propertyValue := string(tibiaBinary[startValue:endValue])

		if len(customValue) > len(propertyValue) {
			fmt.Printf("[ERROR] Cannot replace %s to '%s' because the new value must be smaller than '%s' (%d chars).\n", propertyName, customValue, propertyValue, len(propertyValue))
			return false
		}

		fmt.Printf("[INFO] %s found! %s\n", propertyName, propertyValue)

		// Create the new value with the correct length
		customValueBytes := []byte(customValue)
		paddedCustomValue := append(customValueBytes, bytes.Repeat(paddingByte, len(propertyValue)-len(customValueBytes))...)

		// Merge everything back to the client
		remainingBinary := tibiaBinary[endValue:]

		tibiaBinary = append(tibiaBinary[:startValue], paddedCustomValue...)
		tibiaBinary = append(tibiaBinary, remainingBinary...)

		if originalBinarySize != len(tibiaBinary) {
			fmt.Printf("[ERROR] Fatal error: The new modified client (size %d) has a different byte size from the original (size %d). Make sure to use the correct versions of both the client and client-editor or report a bug.\n", len(tibiaBinary), originalBinarySize)
			os.Exit(1)
		}

		fmt.Printf("[PATCH] %s replaced to %s!\n", propertyName, customValue)
		return true
	}

	fmt.Printf("[WARNING] %s was not found!\n", propertyName)
	return false
}
