package config

import (
	"os"
)

// Config ...
type Config struct {
	DBUser          string
	DBPassword      string
	DBName          string
	AccessTokenKey  string
	RefreshTokenKey string
	Port            string
}

// New Config struct
func New() *Config {
	return &Config{
		DBUser:          getEnv("MONGODB_USER", ""),
		DBPassword:      getEnv("MONGODB_PASSWORD", ""),
		DBName:          getEnv("MONGODB_NAME", ""),
		AccessTokenKey:  getEnv("JWT_ACCESS_TOKEN_KEY", ""),
		RefreshTokenKey: getEnv("JWT_REFRESH_TOKEN_KEY", ""),
		Port:            getEnv("PORT", "5000"),
	}
}

// Function to read an environment variable or return a default value
func getEnv(key string, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
