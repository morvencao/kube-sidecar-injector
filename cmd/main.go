package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
)

func main() {
	var port int
	var webhookNamespace, webhookServiceName, sidecarCfgFile string
	// get command line parameters
	flag.IntVar(&port, "port", 8443, "Webhook server port.")
	flag.StringVar(&webhookServiceName, "service-name", "sidecar-injector-webhook", "Webhook service name.")
	// flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	// flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&sidecarCfgFile, "sidecarCfgFile", "/etc/webhook/config/sidecarconfig.yaml", "File containing the mutation configuration.")
	flag.Parse()

	webhookNamespace = os.Getenv("POD_NAMESPACE")
	sidecarConfig, err := loadConfig(sidecarCfgFile)
	if err != nil {
		glog.Errorf("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	dnsNames := []string{
		webhookServiceName,
		webhookServiceName + "." + webhookNamespace,
		webhookServiceName + "." + webhookNamespace + ".svc",
	}
	commonName := webhookServiceName + "." + webhookNamespace + ".svc"

	ca, caKey, caPEM, err := generateCA([]string{"morven.me"})
	if err != nil {
		glog.Errorf("Failed to generate CA: %v", err)
		os.Exit(1)
	}

	certPEM, keyPEM, err := signCertificate(ca, caKey, dnsNames, commonName)
	if err != nil {
		glog.Errorf("Failed to sign certificate & key pair: %v", err)
		os.Exit(1)
	}

	pair, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		glog.Errorf("Failed to load key pair: %v", err)
		os.Exit(1)
	}

	err = createMutatingWebhookConfiguration(caPEM, webhookServiceName, webhookNamespace)
	if err != nil {
		glog.Errorf("Failed to create mutating webhook configuration: %v", err)
		os.Exit(1)
	}

	whsvr := &WebhookServer{
		sidecarConfig: sidecarConfig,
		server: &http.Server{
			Addr:      fmt.Sprintf(":%v", port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", whsvr.serve)
	whsvr.server.Handler = mux

	// start webhook server in new rountine
	go func() {
		if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
			glog.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	glog.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	whsvr.server.Shutdown(context.Background())
}
