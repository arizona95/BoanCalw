package roles

type Role string

const (
	Owner Role = "owner"
	User  Role = "user"
)

var Labels = map[Role]string{
	Owner: "소유자",
	User:  "사용자",
}

func Normalize(r Role) Role {
	switch r {
	case "primary_owner", Owner:
		return Owner
	default:
		return User
	}
}

func ValidString(s string) bool {
	switch Normalize(Role(s)) {
	case Owner, User:
		return true
	default:
		return false
	}
}

func CanEdit(r Role) bool {
	return Normalize(r) == Owner
}
