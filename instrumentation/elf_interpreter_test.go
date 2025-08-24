package instrumentation

import "testing"

func TestELFInterpreter_GetDelayableOffsetsForPackage(t *testing.T) {
	exePath := "./testdata/greet"
	interpreter := NewELFInterpreter(exePath)
	pkgName := "main"
	symOffsets := interpreter.GetDelayableOffsetsForPackage(pkgName)

	expectedOffsets := map[string][]uint64{
		"main.Greet":                 {0xa, 0x22, 0xcb},
		"main.main":                  {0x12, 0x1d, 0xc0, 0xca, 0x1b9, 0x22f, 0x26a, 0x359, 0x37c, 0x39e, 0x3ca, 0x413, 0x4f1, 0x53b, 0x54d, 0x606, 0x613},
		"main.main.func1":            {0xf, 0x23, 0x3c, 0xf7},
		"main.main.func2":            {0xf, 0x23, 0x44, 0xd7},
		"main.main.func3":            {0xf, 0x41, 0xb2, 0xf9},
		"main.main.func3.deferwrap1": {0x6},
	}

	if len(symOffsets) != len(expectedOffsets) {
		t.Fatalf("Expected %d functions, got %d", len(expectedOffsets), len(symOffsets))
	}

	for fn, expected := range expectedOffsets {
		offsets, ok := symOffsets[fn]
		if !ok {
			t.Fatalf("Function %s not found in offsets", fn)
		}
		if len(offsets) != len(expected) {
			t.Fatalf("Function %s: expected %d offsets, got %d", fn, len(expected), len(offsets))
		}
		for i, offset := range offsets {
			if offset != expected[i] {
				t.Errorf("Function %s: expected offset 0x%x at index %d, got 0x%x", fn, expected[i], i, offset)
			}
		}
	}
}
