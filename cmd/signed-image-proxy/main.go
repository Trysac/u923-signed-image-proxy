// Command signed-image-proxy runs the signed image proxy server or signs URLs.
package main

import (
	"os"

	"github.com/Trysac/u923-signed-image-proxy"
)

func main() {
	os.Exit(signedimageproxy.Run(os.Args[1:], os.Stdout, os.Stderr))
}
