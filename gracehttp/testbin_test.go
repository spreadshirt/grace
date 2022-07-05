package gracehttp_test

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/facebookgo/grace/gracehttp"
)

const preStartProcessEnv = "GRACEHTTP_PRE_START_PROCESS"

func TestMain(m *testing.M) {
	const (
		testbinKey   = "GRACEHTTP_TEST_BIN"
		testbinValue = "1"
	)
	if os.Getenv(testbinKey) == testbinValue {
		testbinMain()
		return
	}
	if err := os.Setenv(testbinKey, testbinValue); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type response struct {
	Sleep time.Duration
	Pid   int
	Error string `json:",omitempty"`
}

// Wait for 10 consecutive responses from our own pid.
//
// This prevents flaky tests that arise from the fact that we have the
// perfectly acceptable (read: not a bug) condition where both the new and the
// old servers are accepting requests. In fact the amount of time both are
// accepting at the same time and the number of requests that flip flop between
// them is unbounded and in the hands of the various kernels our code tends to
// run on.
//
// In order to combat this, we wait for 10 successful responses from our own
// pid. This is a somewhat reliable way to ensure the old server isn't
// serving anymore.
func wait(wg *sync.WaitGroup, url string) {
	var success int
	defer wg.Done()
	for {
		res, err := http.Get(url)
		if err == nil {
			// ensure it isn't a response from a previous instance
			defer res.Body.Close()
			var r response
			if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
				log.Fatalf("Error decoding json: %s", err)
			}
			if r.Pid == os.Getpid() {
				success++
				if success == 10 {
					return
				}
				continue
			}
		} else {
			success = 0
			// we expect connection refused
			if !strings.HasSuffix(err.Error(), "connection refused") {
				e2 := json.NewEncoder(os.Stderr).Encode(&response{
					Error: err.Error(),
					Pid:   os.Getpid(),
				})
				if e2 != nil {
					log.Fatalf("Error writing error json: %s", e2)
				}
			}
		}
	}
}

func httpsServer(addr string) *http.Server {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		log.Fatalf("error loading cert: %v", err)
	}
	return &http.Server{
		Addr:    addr,
		Handler: newHandler(),
		TLSConfig: &tls.Config{
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{cert},
		},
	}
}

func testbinMain() {
	var httpAddr, httpsAddr string
	var testOption int
	flag.StringVar(&httpAddr, "http", ":48560", "http address to bind to")
	flag.StringVar(&httpsAddr, "https", ":48561", "https address to bind to")
	flag.IntVar(&testOption, "testOption", -1, "which option to test on ServeWithOptions")
	flag.Parse()

	// we have self signed certs
	http.DefaultTransport = &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// print json to stderr once we can successfully connect to all three
	// addresses. the ensures we only print the line once we're ready to serve.
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go wait(&wg, fmt.Sprintf("http://%s/sleep/?duration=1ms", httpAddr))
		go wait(&wg, fmt.Sprintf("https://%s/sleep/?duration=1ms", httpsAddr))
		wg.Wait()

		err := json.NewEncoder(os.Stderr).Encode(&response{Pid: os.Getpid()})
		if err != nil {
			log.Fatalf("Error writing startup json: %s", err)
		}
	}()

	servers := []*http.Server{
		&http.Server{Addr: httpAddr, Handler: newHandler()},
		httpsServer(httpsAddr),
	}

	if testOption == -1 {
		err := gracehttp.Serve(servers...)
		if err != nil {
			log.Fatalf("Error in gracehttp.Serve: %s", err)
		}
	} else {
		if testOption == testPreStartProcess {
			switch os.Getenv(preStartProcessEnv) {
			case "":
				err := os.Setenv(preStartProcessEnv, "READY")
				if err != nil {
					log.Fatalf("testbin (first incarnation) could not set %v to 'ready': %v", preStartProcessEnv, err)
				}
			case "FIRED":
				// all good, reset for next round
				err := os.Setenv(preStartProcessEnv, "READY")
				if err != nil {
					log.Fatalf("testbin (second incarnation) could not reset %v to 'ready': %v", preStartProcessEnv, err)
				}
			case "READY":
				log.Fatalf("failure to update startup hook before new process started")
			default:
				log.Fatalf("something strange happened with %v: it ended up as %v, which is not '', 'FIRED', or 'READY'", preStartProcessEnv, os.Getenv(preStartProcessEnv))
			}

			err := gracehttp.ServeWithOptions(
				servers,
				gracehttp.PreStartProcess(func() error {
					err := os.Setenv(preStartProcessEnv, "FIRED")
					if err != nil {
						log.Fatalf("startup hook could not set %v to 'fired': %v", preStartProcessEnv, err)
					}
					return nil
				}),
			)
			if err != nil {
				log.Fatalf("Error in gracehttp.Serve: %s", err)
			}
		}
	}
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sleep/", func(w http.ResponseWriter, r *http.Request) {
		duration, err := time.ParseDuration(r.FormValue("duration"))
		if err != nil {
			http.Error(w, err.Error(), 400)
		}
		time.Sleep(duration)
		err = json.NewEncoder(w).Encode(&response{
			Sleep: duration,
			Pid:   os.Getpid(),
		})
		if err != nil {
			log.Fatalf("Error encoding json: %s", err)
		}
	})
	return mux
}

// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
// generated from src/pkg/crypto/tls:
// go run generate_cert.go  --rsa-bits 512 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDOjCCAiKgAwIBAgIRAJ+QatTa6+MVw1IUj6xQofIwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAPBICQG9WVdfLaGamXK4gnzrWkeQRjZl4ZHuDo8JWJ6KJsIMCXri
p8FscN5DvGaYHZX2EsrQAGtkgZogiSuhDl8ryzDA8nmiiHeL0fWEqaNjz1D1jcml
hvIT1BQDWSx+WWHdDj/8irIUci40hYPVaeqoZhnVxZ2fwoV/XA/JgVvbivYb+8R2
tFWChu3G8HSNArGIFNHRGGxgYVfSmpxZUZrtyLZLSMYhLIxN7+c5u5ki1NucHFT6
G9gbSXP2k65kHqshnJDAegtZFeyoOLbpE+DbN5LhCPHFJ7hDun+2MWTCeRQOlXD6
voyPqgIefqYLl0S9Dj+ij6gLgyDR8MCH7MkCAwEAAaOBiDCBhTAOBgNVHQ8BAf8E
BAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUb+Te14JJDsWuLz+/tajT/hyZ7qQwLgYDVR0RBCcwJYILZXhhbXBsZS5j
b22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBACLd
jbr/LH4JyzHZFskfljFjIcP+C44cDe/EaWU53hRdbT+ORmm+tZ7fMM/U0CbJ/C9G
AET62SSR0R9uA62K0tnW/28w5E1Ve8s7CtramVFycaM40Z041jS48eCddRGUvyKJ
2aqeKOibfALKsJ7B70t8VXx4JWBtuFaIAkgmh1L51Rt6rIsXghTuGFOhfMBPhFle
Ln0cImigJbry9OxDfvQBHGpjYQlp+r5TJ6GdXazV7wHm3YiqWw7YVkn4Jw6VHQcx
O6GW6ZQjCKDWcygbQ/lqgbqSBlhCfWYo8ccSSva0SNCGe+8d1m66XVu0+O7vJX2X
KFUdwHfJbqRh0dA5CCU=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDwSAkBvVlXXy2h
mplyuIJ861pHkEY2ZeGR7g6PCVieiibCDAl64qfBbHDeQ7xmmB2V9hLK0ABrZIGa
IIkroQ5fK8swwPJ5ooh3i9H1hKmjY89Q9Y3JpYbyE9QUA1ksfllh3Q4//IqyFHIu
NIWD1WnqqGYZ1cWdn8KFf1wPyYFb24r2G/vEdrRVgobtxvB0jQKxiBTR0RhsYGFX
0pqcWVGa7ci2S0jGISyMTe/nObuZItTbnBxU+hvYG0lz9pOuZB6rIZyQwHoLWRXs
qDi26RPg2zeS4QjxxSe4Q7p/tjFkwnkUDpVw+r6Mj6oCHn6mC5dEvQ4/oo+oC4Mg
0fDAh+zJAgMBAAECggEARxCXEVumK9Arl8s4rRRjC300M0w5Z+dUAqwMxEM4YZNs
iSG0QBL/GJbw/tu7wgAlZ+/iePdx2FFef242A6BbtswmCWJXlJ/8ipbg3yOAZKGl
dEVbzRLWyYwRwmWHH0CzQN13VHdlseuYJZBFGMuqystJf0SZcNgKWR9k5Apt5vOB
6yY+C/vIUBRf9Qxmy0UUfOZI4DmIC39lDW4IR8c71UdfrmC6+vdpzXa0ZDa7HA4y
5maNL1kERscLo1+CsPbPDs5oVvPzL0376DKMYdmj/8AfSihGK/d6tWgtI1Kz7Br6
pweQhhZy1K69dOorhP3mEkBfBiw2RtAuUp9Tnw/nHQKBgQD/+zoRbfexqjS6qZ6e
/RPsZnkqT7faK1p7koXzubqxS3r+I0QuV2ZbH6Bq1zn0vXr1B3rqebbMQou0Vg3x
XlJ7tQMa0+JBcU8cXUDArIR1WGTT8pSwDxZbsGWPlcJNrC6Mzo60TT7c2oPYf3Hr
XdN9ozcH6B6EzLjT0XPL/JbASwKBgQDwTIP+nxzqLzKXD6BxKz3DLdHp7v0YM/R+
/h3jXVmESmMgt3LOJnrUvcBr6qWXkKIklCWVyQ92oM8ygSXFPX4b65mSZps7KRzw
HUyLYl4Yxqr+cLDuSPPjszJHV8m3BC22s7MalVhCR6OwZAZJrMMOC8jqt8giU3cR
zPLlWe6iuwKBgEMCfRz68JBtwgfrRz7PeVu1J5rP640NNE6M+Mvontqyq6vDh6Gp
9317Nf9CAEX1JC7ommCvJA8sjG3U6Sl6S5VeuUVYmi4Pf2opbz4A61vcm+hv5ESC
bpPqBWwlBAxZOoZZvDmuzvn5qfIOyr+WfDqzc0B6nyKchPXOKsYHhV8pAoGAaIcg
M7ZLAaOeQg/OHuxMZYac9UG8Xrba+BLaNXj5443oKOcjzYD3lWslNMxRU+jaX0cC
QnG/hD7XYoTDRVVGcia+Guz/QXDU4a4dCdS0Udq5rwyeKkkZrkbY7CfH2xC6QetR
UZL9XXeEQMqB4bKA9q8xqshfCm98MAYS8ql4INkCgYEA+tt8NXkY458rwFXGWCF9
bnL+FxvizMcPyT/A/iL4MfDs6JYE8PU7nO87+gYzYRWH++P6nmAhqISQPv9gqRIq
RGFgSwIRm7azh675pXFYd1D2d6fwdtTdJolN7ALmGqMsVekwGourAcfLGNgceoRL
yEDkQhP0shB7aDVt9ZKB/cY=
-----END PRIVATE KEY-----
`)
