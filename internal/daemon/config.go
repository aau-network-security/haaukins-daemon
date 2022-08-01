package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/database"

type Config struct {
	Host            string            `yaml:"host"`
	Port            uint              `yaml:"port"`
	AuditLog        Logging           `yaml:"auditLog"`
	Database        database.DbConfig `yaml:"db-config,omitempty"`
	Production      bool              `yaml:"prodmode,omitempty"`
	AdminOrg        string            `yaml:"admin-org,omitempty"`
	DefaultPolicies [][]string        `yaml:"default-policies,omitempty"`
	JwtSecret       string            `yaml:"jwtSecret,omitempty"`
	Rechaptcha      string            `yaml:"recaptcha-key,omitempty"`
	APICreds        APICreds          `yaml:"api-creds,omitempty"`
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
