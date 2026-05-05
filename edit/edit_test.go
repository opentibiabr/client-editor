package edit

import (
	"bytes"
	"testing"
)

func TestRemoveBattlEyeAppliesAllKnownWindowsPatches(t *testing.T) {
	tibiaBinary := newPEBinary()
	tibiaBinary = append(tibiaBinary, []byte("BattlEye--")...)
	tibiaBinary = append(tibiaBinary, []byte{0x8d, 0x4d, 0xb4, 0x75, 0x0e, 0xe8, 0xb4, 0x53}...)
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0xd9, 0xd4, 0xed, 0xff, 0x48}...)
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}...)

	patched := removeBattlEye("client.exe", tibiaBinary)

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

	patched := removeBattlEye("client.exe", tibiaBinary)

	if !bytes.Equal(patched, original) {
		t.Fatal("expected non-Windows executable to be unchanged")
	}
}

func TestRemoveBattlEyeSkipsMZWithoutPESignature(t *testing.T) {
	tibiaBinary := []byte("MZ--BattlEye--")
	tibiaBinary = append(tibiaBinary, []byte{0x75, 0x0f, 0xe8, 0x35, 0xff, 0xff, 0xff, 0x48}...)
	original := append([]byte(nil), tibiaBinary...)

	patched := removeBattlEye("client.exe", tibiaBinary)

	if !bytes.Equal(patched, original) {
		t.Fatal("expected MZ-only executable to be unchanged")
	}
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
