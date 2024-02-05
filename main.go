package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

func main() {
	flag.Parse()
	mountPath := flag.Arg(0)

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
	searchSecrets(client, mountPath)
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

func searchSecrets(client *vault.Client, mount string) {
	secrets, err := listSecretsRecursively(client, mount, "")
	if err != nil {
		fmt.Println("Error listing secrets:", err)
		return
	}

	fmt.Println("Found the following secrets:")
	for _, secret := range secrets {
		fmt.Println(secret)
	}
}

func listSecretsRecursively(client *vault.Client, mount string, path string) ([]*vault.Secret, error) {
	found := []*vault.Secret{}

	fmt.Println("Listing secrets at", mount+path)
	keys, err := client.Logical().List(mount + "metadata/" + path)
	if err != nil {
		return found, err
	}

	if keys == nil {
		fmt.Println("No secrets found at", mount+path)
		return found, nil
	}

	for _, item := range keys.Data["keys"].([]interface{}) {
		if isVaultDir(path + item.(string)) {
			fmt.Println("Found a directory:", item)
			secrets, err := listSecretsRecursively(client, mount, path+item.(string))
			if err != nil {
				return found, err
			}

			for _, secret := range secrets {
				if isVaultSecret(secret.Data["path"].(string)) {
					found = append(found, secret)
				} else {
					newFound, err := listSecretsRecursively(client, mount, secret.Data["path"].(string))
					if err != nil {
						return found, err
					}

					found = append(found, newFound...)
				}
			}
		} else {
			fmt.Println("Found a secret:", item)
			found = append(found, &vault.Secret{Data: map[string]interface{}{"path": path + item.(string)}})
		}
	}

	fmt.Println("Found", len(found), "secrets at", mount+path)
	return found, nil
}

func isVaultSecret(path string) bool {
	return !isVaultDir(path)
}

func isVaultDir(path string) bool {
	return strings.HasSuffix(path, "/")
}
