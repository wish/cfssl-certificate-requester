package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type ApiCertificateRequest struct {
	Hosts              []string `json:"hosts"`
	CertificateRequest string   `json:"certificate_request"`
	Expiry             string   `json:"expiry"`
	Profile            string   `json:"profile"`
	Bundle             bool     `json:"bundle"`
}

func main() {
	log.SetOutput(os.Stderr)

	cfsslServer, csr, csrExpiry, cfsslProfileName, verboseModeEnabled, err := parseArguments()
	if err != nil {
		log.Fatalf("arg parsing: %v", err)
	}

	log.SetLevel(log.InfoLevel)
	if verboseModeEnabled {
		log.SetLevel(log.DebugLevel)
	}

	// send the API call
	responseBody, err := requestCertificate(cfsslServer, csr, csrExpiry, cfsslProfileName)
	if err != nil {
		log.Fatalf("request certificate: %v", err)
	}

	// output the results, intended to be parsed by cfssljson
	fmt.Print(string(responseBody))

	os.Exit(0)
}

func parseArguments() (cfsslServerAddress string, csr string, csrExpiry string, cfsslProfileName string, verboseModeEnabled bool, e error) {
	cfsslServerAddressFlag := flag.String("cfssl-server", "", "Hostname and port of the cfssl server to request a certificate from")
	csrPathFlag := flag.String("csr-file", "", "Path to PEM-encoded CSR file to request a signature for.")
	csrExpiryFlag := flag.String("expiry", "", "Expiration time of the certificate. This should contain a time duration in the form understood by Go's time package[1].")
	cfsslProfileNameFlag := flag.String("cfssl-profile", "", "Name of the cfssl profile the CA server should use when signing the certificate")
	verboseModeEnabledFlag := flag.Bool("verbose", false, "Enable verbose output?")

	// print program description if no arguments are given
	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr,
			"cfssl-certificate-requester: A tool for getting certificates and their corresponding bundles from a cfssl server.\n"+
				"Intended to have its output piped into `cfssljson`, which will parse it and turn it into files.\n\n"+
				"For usage instructions, run `%s --help`\n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	csrBytes, err := ioutil.ReadFile(*csrPathFlag)
	if err != nil {
		err = errors.Wrap(err, "reading csr file")
	}

	return *cfsslServerAddressFlag, string(csrBytes), *csrExpiryFlag, *cfsslProfileNameFlag, *verboseModeEnabledFlag, err
}

// requestCertificate attempts to make an HTTP API call to the cfssl server and
// returns the body of the response.
func requestCertificate(cfsslServer string, csr string, csrExpiry string, cfsslProfileName string) ([]byte, error) {
	request := ApiCertificateRequest{
		Hosts:              nil,
		CertificateRequest: csr,
		Expiry:             csrExpiry,
		Profile:            cfsslProfileName,
		Bundle:             true,
	}
	reExpiry := regexp.MustCompile(`^([1-9]{1}[0-9]*)h$`)

	if csrExpiry != "" {
		statusRe := reExpiry.MatchString(csrExpiry)
		if !statusRe {
			err := fmt.Errorf("Expiry has the wrong format - It should contain a time duration in the form understood by Go's time package")
			return nil, errors.Wrap(err, "expiry format")
		}
	}

	encodedJsonRequest, err := json.Marshal(request)
	if err != nil {
		return nil, errors.Wrap(err, "request json marhal")
	}
	log.WithFields(log.Fields{
		"encodedJsonRequest": string(encodedJsonRequest),
	}).Debug("The JSON request that we're about to send")

	requestUrl := fmt.Sprintf("%s/api/v1/cfssl/sign", cfsslServer)
	response, err := http.Post(requestUrl, "application/json", bytes.NewBuffer(encodedJsonRequest))
	if err != nil {
		return nil, errors.Wrap(err, "http post")
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading body")
	}
	log.WithFields(log.Fields{
		"statusCode":      response.StatusCode,
		"rawResponseBody": string(body),
	}).Debug("Response info")

	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("http status: got %v, want %v", response.StatusCode, http.StatusOK)
	}
	return body, nil
}

