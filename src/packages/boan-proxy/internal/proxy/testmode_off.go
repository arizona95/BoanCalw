//go:build !testmode

// testmode_off.go — release 빌드 기본값. test-only 분기를 컴파일 단계에서 제거.

package proxy

const TestModeEnabled = false

const BuildMode = "release"
