package utils

import (
	"os/exec"
)

func RunPing(ipAddress string) {
	// Command Injection [CWE-78]
	cmd := "ping -c 4 " + ipAddress
	exec.Command("sh", "-c", cmd).Run()
}
