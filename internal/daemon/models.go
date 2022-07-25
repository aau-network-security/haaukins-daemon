package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/database"

type Config struct {
	Host       string            `json:"host"`
	Port       uint              `yaml:"port"`
	Database   database.DbConfig `yaml:"db-config,omitempty"`
	Production bool              `yaml:"prodmode,omitempty"`
	JwtSecret  string            `yaml:"jwtSecret,omitempty"`
	Rechaptcha string            `yaml:"recaptcha-key,omitempty"`
	APICreds   APICreds          `yaml:"api-creds,omitempty"`
}

type APICreds struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type APIResponse struct {
	Status string `yaml:"status,omitempty"`
}

// VPNConnConf includes configuration
// information for gRPC client on VPN service
