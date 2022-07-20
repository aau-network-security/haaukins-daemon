package daemon

type Config struct {
	Port       uint          `yaml:"port"`
	Database   ServiceConfig `yaml:"db-config,omitempty"`
	Production bool          `yaml:"prodmode,omitempty"`
	jwtSecret  string        `yaml:"jwtSecret,omitempty"`
	Rechaptcha string        `yaml:"recaptcha-key,omitempty"`
	APICreds   APICreds      `yaml:"api-creds,omitempty"`
}

type APICreds struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// VPNConnConf includes configuration
// information for gRPC client on VPN service

type ServiceConfig struct {
	Host     string `yaml:"host"`
	Port     uint64 `yaml:"port"`
	DbName   string `yaml:"db_name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
