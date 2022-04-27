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
	FollowRedirect bool
	UrlParameter   string
	HashParameter  string
}

var DefaultConfig *Config

func init() {
	default_listen_addr := os.Getenv("MORTY_ADDRESS")
	if default_listen_addr == "" {
		default_listen_addr = "127.0.0.1:3000"
	}
	default_url_parameter := os.Getenv("MORTY_URL_PARAM")
	if default_url_parameter == "" {
		default_url_parameter = "mortyurl"
	}
	default_hash_parameter := os.Getenv("MORTY_HASH_PARAM")
	if default_hash_parameter == "" {
		default_hash_parameter = "mortyhash"
	}
	default_key := os.Getenv("MORTY_KEY")
	DefaultConfig = &Config{
		Debug:          os.Getenv("DEBUG") != "false",
		ListenAddress:  default_listen_addr,
		Key:            default_key,
		IPV6:           true,
		RequestTimeout: 5,
		FollowRedirect: false,
		UrlParameter:   default_url_parameter,
		HashParameter:  default_hash_parameter,
	}
}
