package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/tidwall/gjson"
)

func parsePublicKey() *rsa.PublicKey {
	const publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtVuAtSvE93tgSBze6BLLKKHTvJmYitUDe2ybivkf+IgdPY3hcUSve84H6iM2wWLwxqFXMcSj7f0inTPYr23D1i3Ys6FV3HgiFNVwafzrGV2+4rwMUxN4D5KPsr2u1FfNlCEF7zsM9uDgHPa/Si0g98jPL18vxkfoGyc22+TEI6wIDAQAB"
	der, _ := base64.StdEncoding.DecodeString(publicKey)
	pub, _ := x509.ParsePKIXPublicKey(der)
	rsaPub := pub.(*rsa.PublicKey)
	return rsaPub
}

func fixJSONKeys(jsonStr string) string {
	re := regexp.MustCompile(`([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)(\s*:)`)
	return re.ReplaceAllString(jsonStr, `$1"$2"$3`)
}

func changePassword(username, oldPassword, newPassword string) error {
	pub := parsePublicKey()
	encOldBytes, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(oldPassword))
	encNewBytes, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(newPassword))

	encOldPassword := base64.StdEncoding.EncodeToString(encOldBytes)
	encNewPassword := base64.StdEncoding.EncodeToString(encNewBytes)

	const URL = "http://self.ssmc.jh:9011/uassselfActionAjaxno.action?_fw_service_id=updateTabStaticPwdByUserName"
	res, err := http.PostForm(URL, map[string][]string{
		"username": {username},
		"oldpwd":   {encOldPassword},
		"newpwd":   {encNewPassword},
		"authType": {"11"},
		"authCode": {""},
	})
	if err != nil {
		return err
	}

	buf := make([]byte, 1024)
	n, _ := res.Body.Read(buf)
	strJSON := fixJSONKeys(string(buf[:n]))
	defer res.Body.Close()

	msg := gjson.Get(strJSON, "message").String()
	hasError := gjson.Get(strJSON, "error")
	if hasError.Exists() && hasError.String() == "true" {
		return fmt.Errorf("%s", msg)
	} else if msg == "口令修改成功" {
		fmt.Printf("Changed password from '%s' to '%s'.\n", oldPassword, newPassword)
		return nil
	} else {
		return fmt.Errorf("unknown error. raw response: %s", strJSON)
	}
}

func multiPasswd(username, oldPassword, newPassword string) error {
	lastPassword := oldPassword
	for i := 0; i < 10; i++ {
		nextPassword := fmt.Sprintf("TmpPasswd_%d", i)
		err := changePassword(username, lastPassword, nextPassword)
		if err != nil {
			return fmt.Errorf("failed. last error: %s", err.Error())
		}
		lastPassword = nextPassword
		for j := 20; j > 0; j-- {
			fmt.Printf("\r(%d/10) Waiting %d seconds before next change...", i+1, j)
			time.Sleep(1 * time.Second)
		}
		fmt.Print("\r                             \r")
	}
	err := changePassword(username, lastPassword, newPassword)
	if err != nil {
		return err
	}
	return nil
}

func interactiveInput() (string, string, string) {
	var username, oldPassword, newPassword, repeatPassword string
	fmt.Print("Username: ")
	fmt.Scanln(&username)
	fmt.Print("Old password: ")
	fmt.Scanln(&oldPassword)
	for {
		fmt.Print("New password (press Enter to keep the same): ")
		fmt.Scanln(&newPassword)
		if newPassword == "" {
			return username, oldPassword, oldPassword
		}
		fmt.Print("Repeat new password: ")
		fmt.Scanln(&repeatPassword)
		if newPassword == repeatPassword {
			return username, oldPassword, newPassword
		}
		fmt.Println("Error: new passwords do not match.")
	}
}

func welcomeMessage() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("---------- UASS Passwd ----------")
}

func exit(code int) {
	fmt.Print("Press Enter to exit...")
	fmt.Scanln()
	os.Exit(code)
}

func main() {
	welcomeMessage()
	var username, oldPassword, newPassword string
	if len(os.Args) == 1 {
		username, oldPassword, newPassword = interactiveInput()
		welcomeMessage()
	} else if len(os.Args) == 4 {
		username, oldPassword, newPassword = os.Args[1], os.Args[2], os.Args[3]
	} else {
		fmt.Println("Usage: uass-passwd <username> <old_password> <new_password>")
		return
	}

	// 在一个方框中展示username, oldPassword, newPassword
	fmt.Println("+--------------------------------+")
	fmt.Printf("| Username: %-20s |\n", username)
	fmt.Printf("| Old Password: %-16s |\n", oldPassword)
	fmt.Printf("| New Password: %-16s |\n", newPassword)
	fmt.Println("+--------------------------------+")

	err := changePassword(username, oldPassword, newPassword)
	if err != nil {
		if err.Error() == "Your password cannot be the same to the former 10 passwords." {
			fmt.Println("Attempting multi-step password change to bypass history restriction...")
			err = multiPasswd(username, oldPassword, newPassword)
			if err != nil {
				fmt.Println("Error:", err)
				exit(1)
			}
		} else {
			fmt.Println("Error:", err)
			exit(1)
		}
	}
	fmt.Println("Password changed successfully.")
	exit(0)
}
