package otp

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

type entry struct {
	code    string
	expires time.Time
	email   string
}

type Store struct {
	mu      sync.Mutex
	codes   map[string]*entry
	smtp    SMTPConfig
}

type SMTPConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	From     string
}

func New(cfg SMTPConfig) *Store {
	s := &Store{
		codes: make(map[string]*entry),
		smtp:  cfg,
	}
	go s.gc()
	return s
}

func (s *Store) Generate(email string) (string, error) {
	code, err := randomCode()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.codes[strings.ToLower(email)] = &entry{
		code:    code,
		expires: time.Now().Add(10 * time.Minute),
		email:   email,
	}
	s.mu.Unlock()

	if err := s.send(email, code); err != nil {
		if s.smtp.Host == "" {
			log.Printf("[OTP] email send failed (%v) — fallback to log", err)
			log.Printf("========================================")
			log.Printf("[OTP] %s → CODE: %s  (expires in 10 min)", email, code)
			log.Printf("========================================")
		} else {
			return "", fmt.Errorf("send otp email: %w", err)
		}
	}

	return code, nil
}

func (s *Store) Verify(email, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.codes[strings.ToLower(email)]
	if !ok {
		return false
	}
	if time.Now().After(e.expires) {
		delete(s.codes, strings.ToLower(email))
		return false
	}
	if e.code != code {
		return false
	}
	delete(s.codes, strings.ToLower(email))
	return true
}

func (s *Store) send(to, code string) error {
	if s.smtp.Host == "" {
		return fmt.Errorf("no smtp host configured")
	}

	from := s.smtp.From
	if from == "" {
		from = s.smtp.User
	}

	body := fmt.Sprintf(
		"Subject: BoanClaw 로그인 코드\r\n"+
			"From: %s\r\n"+
			"To: %s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"BoanClaw 로그인 코드: %s\r\n\r\n"+
			"이 코드는 10분간 유효합니다.\r\n",
		from, to, code,
	)

	addr := s.smtp.Host + ":" + s.smtp.Port
	var auth smtp.Auth
	if s.smtp.User != "" {
		auth = smtp.PlainAuth("", s.smtp.User, s.smtp.Password, s.smtp.Host)
	}
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(body))
}

func (s *Store) gc() {
	for range time.Tick(5 * time.Minute) {
		s.mu.Lock()
		for k, e := range s.codes {
			if time.Now().After(e.expires) {
				delete(s.codes, k)
			}
		}
		s.mu.Unlock()
	}
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
