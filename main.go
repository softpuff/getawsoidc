package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
)

var issuerURL string
var verbose bool
var mdfive bool

type Thumbrint struct {
	Thumbprint string `json:"thumbprint"`
}

type partialOIDCConfig struct {
	JwksURI string `json:"jwks_uri"`
}

func GetOIDCConfigURL(issuerURL string) (string, error) {
	parsedURL, err := url.Parse(issuerURL)
	if err != nil {
		return "", err
	}
	parsedURL.Path = path.Join(parsedURL.Path, ".well-known", "openid-configuration")
	openidConfigURL := parsedURL.String()
	return openidConfigURL, nil

}

func getJwksURL(openidConfigURL string) (string, error) {
	resp, err := http.Get(openidConfigURL)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var partialOIDCConfig partialOIDCConfig
	if err := json.Unmarshal(body, &partialOIDCConfig); err != nil {
		return "", err
	}

	return partialOIDCConfig.JwksURI, nil

}

func sha1Hash(data []byte) string {
	hasher := sha1.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	return hex.EncodeToString(hashed)
}

func mdpFingerprint(data []byte) string {
	fingerprint := md5.Sum(data)
	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}

func getThumbprint(jwksURL string) (string, error) {
	parsedURL, err := url.Parse(jwksURL)
	if err != nil {
		return "", err
	}
	hostname := parsedURL.Host
	if parsedURL.Port() == "" {
		hostname = net.JoinHostPort(hostname, "443")
	}
	if verbose {
		fmt.Println("Hostname")
		fmt.Println(hostname)
	}

	tlsConfig := tls.Config{ServerName: parsedURL.Host}
	conn, err := tls.Dial("tcp", hostname, &tlsConfig)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	peerCerts := state.PeerCertificates
	numCerts := len(peerCerts)
	if numCerts == 0 {
		return "", err
	}

	// root CA certificate is the last one in the list
	root := peerCerts[numCerts-1]
	if verbose {
		fmt.Println("root cert")
		fmt.Println(root)
	}

	if mdfive {
		md5F := mdpFingerprint(root.Raw)
		fmt.Println(md5F)
	}
	return sha1Hash(root.Raw), nil
}

func GetOIDCThumb(issuerURL string) (*Thumbrint, error) {

	openidConfigURL, err := GetOIDCConfigURL(issuerURL)
	if err != nil {
		return nil, err
	}
	if verbose {
		fmt.Println("openidConfigURL")
		fmt.Println(openidConfigURL)
	}

	jwksURL, err := getJwksURL(openidConfigURL)
	if err != nil {
		return nil, err
	}
	if verbose {
		fmt.Println("jwksURL")
		fmt.Println(jwksURL)
	}

	thumb, err := getThumbprint(jwksURL)
	if err != nil {
		return nil, err
	}

	if verbose {

		fmt.Printf("Retrieved OIDC Issuer (%s) CA Thumbprint: %s\n", issuerURL, thumb)
	}

	return &Thumbrint{Thumbprint: thumb}, nil

}

func main() {
	flag.StringVar(&issuerURL, "issuerURL", "", "issuer URL to get thumbrint from")
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.BoolVar(&mdfive, "mdfive", false, "md5 thumbprint")

	flag.Parse()

	thumb, err := GetOIDCThumb(issuerURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	data, err := json.Marshal(thumb)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(data))

}
