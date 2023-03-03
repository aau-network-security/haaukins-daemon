module github.com/aau-network-security/haaukins-daemon

go 1.18

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
	github.com/gorilla/websocket v1.5.0
	github.com/lib/pq v1.10.6
	github.com/microcosm-cc/bluemonday v1.0.21
	github.com/rs/zerolog v1.28.0
	github.com/yuin/goldmark v1.5.3
	golang.org/x/crypto v0.1.0
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2
	google.golang.org/grpc v1.49.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/postgres v1.3.8
	gorm.io/gorm v1.23.8
)

require (
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/denisenkom/go-mssqldb v0.12.0 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/glebarez/go-sqlite v1.16.0 // indirect
	github.com/glebarez/sqlite v1.4.3 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.10.0 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/goccy/go-json v0.9.7 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.0.0-20170517235910-f1bb20e5a188 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.12.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.11.0 // indirect
	github.com/jackc/pgx/v4 v4.16.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/onsi/gomega v1.20.0 // indirect
	github.com/pelletier/go-toml/v2 v2.0.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	golang.org/x/net v0.1.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/genproto v0.0.0-20220829175752-36a9c930ecbf // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gorm.io/driver/mysql v1.3.3 // indirect
	gorm.io/driver/sqlserver v1.3.2 // indirect
	gorm.io/plugin/dbresolver v1.1.0 // indirect
	modernc.org/libc v1.15.1 // indirect
	modernc.org/mathutil v1.4.1 // indirect
	modernc.org/memory v1.0.7 // indirect
	modernc.org/sqlite v1.16.0 // indirect
)
