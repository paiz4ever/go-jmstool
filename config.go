package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Access struct {
		KeyID  string `mapstructure:"key_id"` // API KEY ID
		Secret string `mapstructure:"secret"` // API KEY SECRET
	} `mapstructure:"access"`
	SSH struct {
		Host string `mapstructure:"host"`
	} `mapstructure:"ssh"`
}

var config Config

func InitConfig() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exePath)
	viper.AddConfigPath(exeDir)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	err = viper.ReadInConfig()
	if err != nil {
		return err
	}
	err = viper.Unmarshal(&config)
	if err != nil {
		return err
	}
	return nil
}
