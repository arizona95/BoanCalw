//go:build testmode

// testmode_on.go — testmode 빌드에서만 활성화되는 test-only 경로들의 플래그와
// 진입점. Go 컴파일러의 dead-code elimination 덕분에 `if TestModeEnabled {...}`
// 는 release 빌드에서 완전히 제거된다.
//
// 이 파일이 컴파일되려면 `go build -tags=testmode` 로 빌드해야 한다. 기본값
// (태그 없음) = release. 실수로 prod 에 test 코드가 섞일 여지 zero.

package proxy

const TestModeEnabled = true

// BuildMode — /api/admin/debug/build-info 응답용 라벨.
const BuildMode = "testmode"
