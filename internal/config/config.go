package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Pattern     string `yaml:"pattern"`
}

type Config struct {
	Rules []Rule `yaml:"rules"`
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire le fichier de configuration : %v", err)
	}
	conf := Config{}
	err = yaml.Unmarshal(file, &conf)
	if err != nil {
		return nil, fmt.Errorf("impossible de parser le YAML : %v", err)
	}
	return &conf, nil

}
