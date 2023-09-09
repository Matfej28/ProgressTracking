package dotEnv

import (
	"log"
	"os"
	"regexp"

	"github.com/joho/godotenv"
)

func LoadDotEnv() {
	projectName, err := regexp.Compile("^(.*ProgressTracking)")
	if err != nil {
		log.Fatal(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	root := projectName.Find([]byte(wd))

	err = godotenv.Load(string(root) + "/.env")
	if err != nil {
		log.Fatal(err)
	}
}
