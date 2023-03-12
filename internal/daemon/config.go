package daemon

import (
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
)

type Config struct {
	Host               string        `yaml:"host"` // Host is is not really important at this time
	Port               uint          `yaml:"port"` // Port to be listening on
	ListeningIp        string        `yaml:"listening-ip,omitempty"` // ex. "127.0.0.1", "0.0.0.0". Default is "0.0.0.0"
	AuditLog           Logging       `yaml:"auditLog"` // Audit log, used for admin endpoints to log admin events. See Logging struct below
	Database           db.DbConfig   `yaml:"db-config,omitempty"` // Creds and host for the postgres database
	ExerciseService    ServiceConfig `yaml:"exercise-service"` // Creds and host information for the exercise service
	Production         bool          `yaml:"prodmode,omitempty"` // Currently unused
	JwtSecret          string        `yaml:"jwtSecret,omitempty"` // Secret used to sign JWT's
	Rechaptcha         string        `yaml:"recaptcha-key,omitempty"` // Recaptcha keys, currently not used
	APICreds           APICreds      `yaml:"api-creds,omitempty"` // Currently unused
	StatePath          string        `yaml:"state-path,omitempty"` // Path of the state file
	TestDelay          TestDelay     `yaml:"test-delay,omitempty"` // Can be enabled or disabled, used to delay api responses to test long response times
	LabExpiryDuration  time.Duration `yaml:"lab-expiry-duration,omitempty"` // Base duration before lab expires without extension in minutes
	LabExpiryExtension time.Duration `yaml:"lab-expiry-extension,omitempty"` // Duration to extend lab expiration time by in minutes
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
