package config

import (
	"os"
)

type Config struct {
	Debug          bool
	ListenAddress  string
	Key            string
	IPV6           bool
	RequestTimeout uint
}

var DefaultConfig *Config

func init() {
	default_listen_addr := os.Getenv("MORTY_ADDRESS")
	if default_listen_addr == "" {
		default_listen_addr = "127.0.0.1:3000"
	}
	default_key := os.Getenv("MORTY_KEY")
	DefaultConfig = &Config{
		Debug:          os.Getenv("DEBUG") != "false",
		ListenAddress:  default_listen_addr,
		Key:            default_key,
		IPV6:           true,
		RequestTimeout: 5,
	}
}
