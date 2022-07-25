package main

import (
	"flag"
	"os"

	"github.com/aau-network-security/haaukins-daemon/internal/daemon"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultConfigFile = "config/config.yml"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	confFilePtr := flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()

	c, err := daemon.NewConfigFromFile(*confFilePtr)
	if err != nil {
		log.Fatal().Err(err).Msgf("unable to read configuration file: %s", *confFilePtr)
		return
	}

	d, err := daemon.New(c)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create daemon")
		return
	}

	if err := d.Run(); err != nil {
		log.Fatal().Err(err).Msg("Error running daemon")
	}
}
