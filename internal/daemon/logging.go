package daemon

import (
	"io"
	"os"
	"path"

	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

func newRollingFile(conf *Config) io.Writer {
	if err := os.MkdirAll(conf.AuditLog.Directory, 0744); err != nil {
		log.Error().Err(err).Str("path", conf.AuditLog.Directory).Msg("can't create log directory")
		return nil
	}

	return &lumberjack.Logger{
		Filename:   path.Join(conf.AuditLog.Directory, conf.AuditLog.FileName),
		MaxBackups: conf.AuditLog.MaxBackups, // files
		MaxSize:    conf.AuditLog.MaxSize,    // megabytes
		MaxAge:     conf.AuditLog.MaxAge,     // days
	}
}
