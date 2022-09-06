module github.com/aau-network-security/haaukins-daemon

go 1.16

replace github.com/aau-network-security/haaukins-agent => /home/mikkel/Desktop/haaukinsdev/haaukins-agent

replace github.com/aau-network-security/haaukins-exercises => /home/mikkel/Desktop/haaukinsdev/haaukins-exercises

require (
	github.com/aau-network-security/haaukins-agent v0.0.1
	github.com/aau-network-security/haaukins-exercises v1.2.2
	github.com/casbin/casbin/v2 v2.51.2
	github.com/casbin/gorm-adapter/v3 v3.8.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-contrib/cors v1.4.0
	github.com/gin-gonic/gin v1.8.1
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/google/uuid v1.3.0
	github.com/lib/pq v1.10.6
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.20.0 // indirect
	github.com/rs/zerolog v1.28.0
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	golang.org/x/net v0.0.0-20220826154423-83b083e8dc8b // indirect
	golang.org/x/sys v0.0.0-20220829200755-d48e67d00261 // indirect
	google.golang.org/genproto v0.0.0-20220829175752-36a9c930ecbf // indirect
	google.golang.org/grpc v1.49.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/postgres v1.3.8
	gorm.io/gorm v1.23.8
)
