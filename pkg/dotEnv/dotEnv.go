package dotEnv

import (
	"os"
	"regexp"

	"github.com/joho/godotenv"
)

func LoadDotEnv() error {
	projectName, err := regexp.Compile("^(.*ProgressTracking)")
	if err != nil {
		return err
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	root := projectName.Find([]byte(wd))

	err = godotenv.Load(string(root) + "/.env")
	if err != nil {
		return err
	}
	return nil
}
