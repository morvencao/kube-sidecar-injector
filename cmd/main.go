package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	infoLogger    *log.Logger
	warningLogger *log.Logger
	errorLogger   *log.Logger
)

var (
	port                                   int
	sidecarConfigFile                      string
	sidecarTemplateFile, sidecarValuesFile string
	webhookNamespace, webhookServiceName   string
)

const (
	apiKeyEnvName string = "WALLARM_API_KEY"
	apiKeyDefault string = "dummyApiKey"
)

func init() {
	// init loggers
	infoLogger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	warningLogger = log.New(os.Stderr, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	// webhook server running namespace
	webhookNamespace = os.Getenv("POD_NAMESPACE")
}

func main() {
	// init command flags
	flag.IntVar(&port, "port", 8443, "Webhook server port.")
	flag.StringVar(&webhookServiceName, "service-name", "sidecar-injector", "Webhook service name.")
	flag.StringVar(&sidecarTemplateFile, "sidecar-template-file", "/etc/webhook/config/sidecar-template.yaml.tmpl", "Sidecar injector GO template file")
	flag.StringVar(&sidecarValuesFile, "sidecar-values-file", "/etc/webhook/config/sidecar-values.json", "Sidecar injector values file")
	// flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "x509 Certificate file.")
	// flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "x509 private key file.")
	flag.Parse()

	dnsNames := []string{
		webhookServiceName,
		webhookServiceName + "." + webhookNamespace,
		webhookServiceName + "." + webhookNamespace + ".svc",
	}
	commonName := webhookServiceName + "." + webhookNamespace + ".svc"

	org := "morven.me"
	caPEM, certPEM, certKeyPEM, err := generateCert([]string{org}, dnsNames, commonName)
	if err != nil {
		errorLogger.Fatalf("Failed to generate ca and certificate key pair: %v", err)
	}

	pair, err := tls.X509KeyPair(certPEM.Bytes(), certKeyPEM.Bytes())
	if err != nil {
		errorLogger.Fatalf("Failed to load certificate key pair: %v", err)
	}

	sidecarDefaults, err := loadSidecarDefaults(sidecarValuesFile)
	if err != nil {
		errorLogger.Fatalf("Failed to load sidecar values file: %v", err)
	}

	sidecarTemplate, err := loadSidecarTemplate(sidecarTemplateFile)
	if err != nil {
		errorLogger.Fatalf("Failed to load sidecar template file: %v", err)
	}

	sidecarSecrets := loadSidecarSecrets()

	// create or update the mutatingwebhookconfiguration
	err = createOrUpdateMutatingWebhookConfiguration(caPEM, webhookServiceName, webhookNamespace)
	if err != nil {
		errorLogger.Fatalf("Failed to create or update the mutating webhook configuration: %v", err)
	}

	whsvr := &WebhookServer{
		sidecarTemplate: sidecarTemplate,
		sidecarDefaults: sidecarDefaults,
		sidecarSecrets:  sidecarSecrets,
		server: &http.Server{
			Addr:      fmt.Sprintf(":%v", port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc(webhookInjectPath, whsvr.serve)
	whsvr.server.Handler = mux

	// start webhook server in new rountine
	go func() {
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
			errorLogger.Fatalf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	infoLogger.Printf("Got OS shutdown signal, shutting down webhook server gracefully...")
	whsvr.server.Shutdown(context.Background())
}
