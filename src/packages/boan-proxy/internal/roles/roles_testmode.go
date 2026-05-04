//go:build testmode

package roles

// testmode 빌드 전용: Tester 는 정식 role 로 보존되고 admin 권한 부여.

func normalizeTester() Role { return Tester }
func testerCanEdit() bool   { return true }
