package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	jose "github.com/square/go-jose"
)

const (
	staging    = directory("https://acme-staging.api.letsencrypt.org/directory")
	production = directory("https://acme-v01.api.letsencrypt.org/directory")
)

var (
	ErrNoNonce = errors.New("acme server did not respond with a proper nonce header")
	ErrPending = errors.New("authz still pending")
)

var (
	flagStage = flag.Bool("staging", false, "use acme staging server")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("acmecancel: ")

	flag.Parse()
	url := flag.Arg(0)

	acmeDirectory := production
	if *flagStage {
		acmeDirectory = staging
	}

	key, ok := os.LookupEnv("LE_KEY")
	if !ok {
		log.Fatal("specify Let's Encrypt registration key with LE_KEY environment variable")
	}

	c, err := newClient(key, acmeDirectory)
	if err != nil {
		log.Fatalf("could not parse Let's Encrypt registration key: %v", err)
	}

	if err := c.disableAuthz(url); err != nil {
		log.Fatalf("could not disable authz: %v", err)
	}
}

type client struct {
	directoryURL string
	signer       jose.Signer
}

func newClient(ks string, ns jose.NonceSource) (*client, error) {
	var reg struct {
		X, Y, D *big.Int
	}
	if err := json.Unmarshal([]byte(ks), &reg); err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{
		D: reg.D,
		PublicKey: ecdsa.PublicKey{
			X:     reg.X,
			Y:     reg.Y,
			Curve: elliptic.P256(),
		},
	}

	signer, err := jose.NewSigner(jose.ES256, priv)
	if err != nil {
		return nil, err
	}
	signer.SetNonceSource(ns)

	return &client{signer: signer}, nil
}

func (c *client) disableAuthz(url string) error {
	b, err := json.Marshal(struct {
		Resource string `json:"resource"`
		Status   string `jsom:"status"`
	}{
		Resource: "authz",
		Status:   "deactivated",
	})
	if err != nil {
		return err
	}

	signed, err := c.signer.Sign(b)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer([]byte(signed.FullSerialize()))
	resp, err := http.Post(url, "application/jose+json", buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		var message struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
			return err
		}
		return errors.New(message.Detail)
	}

	var v struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return err
	}
	if v.Status == "pending" {
		return ErrPending
	}
	return nil
}

type directory string

func (d directory) Nonce() (string, error) {
	c := &http.Client{Timeout: 1 * time.Second}
	resp, err := c.Get(string(d))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", ErrNoNonce
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", ErrNoNonce
	}
	return nonce, nil
}
