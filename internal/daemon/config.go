package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/db"

type Config struct {
	Host            string        `yaml:"host"`
	Port            uint          `yaml:"port"`
	AuditLog        Logging       `yaml:"auditLog"`
	Database        db.DbConfig   `yaml:"db-config,omitempty"`
	ExerciseService ServiceConfig `yaml:"exercise-service"`
	Production      bool          `yaml:"prodmode,omitempty"`
	JwtSecret       string        `yaml:"jwtSecret,omitempty"`
	Rechaptcha      string        `yaml:"recaptcha-key,omitempty"`
	APICreds        APICreds      `yaml:"api-creds,omitempty"`
	StatePath       string        `yaml:"state-path,omitempty"`
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
