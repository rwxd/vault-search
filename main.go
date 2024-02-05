package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

var (
	flagVerbose    = flag.Bool("v", false, "Verbose mode")
	flagMountpoint = flag.String("m", "secret", "Mountpoint to search for secrets")
)

func main() {
	flag.Parse()
	search := flag.Arg(0)

	logLevel := slog.LevelWarn
	if *flagVerbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	if vaultToken == "" {
		tokenFromFile, err := readTokenFromFile()
		if err != nil {
			fmt.Println("Error reading Vault token:", err)
			os.Exit(1)
		}

		if vaultToken == "" {
			vaultToken = tokenFromFile
		}

		if vaultAddr == "" {
			fmt.Println("Error: Vault address is not provided.")
			os.Exit(1)
		}
	}

	// Create a new Vault client
	client, err := vault.NewClient(&vault.Config{Address: vaultAddr})
	if err != nil {
		fmt.Println("Error creating Vault client:", err)
		os.Exit(1)
	}

	client.SetToken(vaultToken)

	// Start recursive search
	searchSecrets(client, *flagMountpoint+"/", search)
}

// Try reading from the ~/.vault-token file if not provided as environment variables
func readTokenFromFile() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	tokenFilePath := homeDir + "/.vault-token"
	file, err := os.Open(tokenFilePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	tokenBytes := make([]byte, 64) // Assuming the token length won't exceed 64 characters
	n, err := file.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	return string(tokenBytes[:n]), nil
}

func searchSecrets(client *vault.Client, mount string, search string) {
	secrets, err := listSecretsRecursively(client, mount, "")
	if err != nil {
		fmt.Println("Error listing secrets:", err)
		return
	}

	fmt.Println("Found the following secrets:")
	for _, secret := range secrets {
		name := secret.Data["path"].(string)
		if search == "" || strings.Contains(strings.ToLower(name), strings.ToLower(search)) {
			fmt.Println(mount + name)
		}
	}
}

func listSecretsRecursively(client *vault.Client, mount string, path string) ([]*vault.Secret, error) {
	found := []*vault.Secret{}

	slog.Debug("Listing secrets", "path", mount+path)
	keys, err := client.Logical().List(mount + "metadata/" + path)
	if err != nil {
		return found, err
	}

	if keys == nil {
		slog.Debug("No secrets found", "path", mount+path)
		return found, nil
	}

	for _, item := range keys.Data["keys"].([]interface{}) {
		itemPath := path + item.(string)
		if isVaultDir(itemPath) {
			slog.Debug("Found a directory", "item", item)
			secrets, err := listSecretsRecursively(client, mount, itemPath)
			if err != nil {
				return found, err
			}
			found = append(found, secrets...)
		} else {
			slog.Debug("Found a secret", "item", item)
			found = append(found, &vault.Secret{Data: map[string]interface{}{"path": path + item.(string)}})
		}
	}

	slog.Debug("Found secrets", "number", len(found), "path", mount+path)
	return found, nil
}

func isVaultSecret(path string) bool {
	return !isVaultDir(path)
}

func isVaultDir(path string) bool {
	return strings.HasSuffix(path, "/")
}
