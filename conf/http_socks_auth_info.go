package conf

type HTTPSOCKSAuthInfo struct {
	Username string
	Password string
}

func (authInfo *HTTPSOCKSAuthInfo) IsEmpty() bool {
	return authInfo == nil || (authInfo.Username == "" && authInfo.Password == "")
}

func (authInfo *HTTPSOCKSAuthInfo) NotEqual(anotherAuthInfo *HTTPSOCKSAuthInfo) bool {
	return !(authInfo.Username == anotherAuthInfo.Username && authInfo.Password == anotherAuthInfo.Password)
}

func (authInfo *HTTPSOCKSAuthInfo) NotEqual2(username, password string) bool {
	return !(authInfo.Username == username && authInfo.Password == password)
}
