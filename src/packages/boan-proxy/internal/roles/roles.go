package roles

type Role string

const (
	Owner Role = "owner"
	User  Role = "user"
	// Tester — testmode 빌드 전용 컨셉. 상수는 항상 존재하지만 CanEdit / Normalize
	// 가 testmode 일 때만 admin-권한 부여. release 에서는 User 로 강등됨.
	Tester Role = "tester"
)

var Labels = map[Role]string{
	Owner:  "소유자",
	User:   "사용자",
	Tester: "🧪 테스터",
}

func Normalize(r Role) Role {
	switch r {
	case "primary_owner", Owner:
		return Owner
	case Tester:
		// testmode 빌드에서는 Tester 유지, release 에서는 User 로 강등.
		// (roles_testmode.go / roles_release.go 참조.)
		return normalizeTester()
	default:
		return User
	}
}

func ValidString(s string) bool {
	switch Normalize(Role(s)) {
	case Owner, User, Tester:
		return true
	default:
		return false
	}
}

func CanEdit(r Role) bool {
	n := Normalize(r)
	return n == Owner || (n == Tester && testerCanEdit())
}
