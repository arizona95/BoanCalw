//go:build !testmode

package roles

// release 빌드: Tester 는 User 로 강등, admin 권한 없음.
// 즉 실수로 role=tester 레코드가 들어와도 prod 에서는 일반 사용자로만 동작.

func normalizeTester() Role { return User }
func testerCanEdit() bool   { return false }
