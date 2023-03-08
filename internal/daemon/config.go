package daemon

import (
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
)

type Config struct {
	Host              string        `yaml:"host"`
	Port              uint          `yaml:"port"`
	ListeningIp       string        `yaml:"listening-ip,omitempty"`
	AuditLog          Logging       `yaml:"auditLog"`
	Database          db.DbConfig   `yaml:"db-config,omitempty"`
	ExerciseService   ServiceConfig `yaml:"exercise-service"`
	Production        bool          `yaml:"prodmode,omitempty"`
	JwtSecret         string        `yaml:"jwtSecret,omitempty"`
	Rechaptcha        string        `yaml:"recaptcha-key,omitempty"`
	APICreds          APICreds      `yaml:"api-creds,omitempty"`
	StatePath         string        `yaml:"state-path,omitempty"`
	TestDelay         TestDelay     `yaml:"test-delay,omitempty"`
	LabExpiryDuration time.Duration `yaml:"lab-expiry-duration,omitempty"`
}

type Logging struct {
	Directory  string `yaml:"directory"`
	FileName   string `yaml:"fileName"`
	MaxBackups int    `yaml:"max-backups"`
	MaxSize    int    `yaml:"max-size"`
	MaxAge     int    `yaml:"max-age"`
}

type APICreds struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type ServiceConfig struct {
	Grpc       string `yaml:"grpc"`
	AuthKey    string `yaml:"auth-key"`
	SignKey    string `yaml:"sign-key"`
	TLSEnabled bool   `yaml:"tls-enabled"`
}

type TestDelay struct {
	Enabled        bool          `yaml:"enabled"`
	DelayInSeconds time.Duration `yaml:"delay-seconds"`
}
