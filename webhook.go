package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

var ignoredNamespaces = []string {
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const admissionWebhookAnnotationMutateKey = "sidecar-injector-webhook.morven.me/inject"

type WebhookServer struct {
	sidecarConfig    *Config
	server           *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port int                 // webhook server port
	certFile string          // path to the x509 certificate for https
	keyFile string           // path to the x509 private key matching `CertFile`
	sidecarCfgFile string    // path to sidecar injector configuration file
}

type Config struct {
	containers    []corev1.Container
	volumes       []corev1.Volume
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))
	//glog.Infof("Containers: |\n  %v", strings.Replace(string(yaml.Marshal(cfg.containers)), "\n", "\n  ", -1))
	//glog.Infof("Volumes: |\n  %v", strings.Replace(string(yaml.Marshal(cfg.volumes)), "\n", "\n  ", -1))
	
	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, pod *corev1.Pod) bool {
	metadata := pod.ObjectMeta

	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it' in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	
	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	switch strings.ToLower(annotations[admissionWebhookAnnotationMutateKey]) {
	default:
		required = false
	case "y", "yes", "true", "on":
		required = true
	}

	glog.Infof("Mutation policy for %v/%v: required:%v", metadata.Namespace, metadata.Name, required)
	
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, sidecarConfig *Config) ([]byte, error) {
	var patch []patchOperation
	
	patch = append(patch, addContainer(pod.Spec.Containers, sidecarConfig.containers, "/spec/containers")...)
	patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.volumes, "/spec/volumes")...)
	
	return json.Marshal(patch)
}

// sidecar injection process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)
	glog.Infof("Object: %v", string(req.Object.Raw))
	glog.Infof("OldObject: %v", string(req.OldObject.Raw))
	
	// determine whether to perform mutation
	if (mutationRequired(ignoredNamespaces, &pod)) {
		glog.Infof("Skipping mutating %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse {
			Allowed: true, 
		}
	}
	
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig)
	if err != nil {
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}
	
	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	
	reviewResponse := v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
	
	return &reviewResponse
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	glog.Info("New request is comming...")

	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if (contentType != "application/json") {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		reviewResponse = &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	} else {
		// main mutation process
		reviewResponse = whsvr.mutate(&ar)
	}
	
	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		if ar.Request != nil {
			response.Response.UID = ar.Request.UID
		}
	}
	
	res, err := json.Marshal(response);
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("can't encode response: %v", err), http.StatusInternalServerError)
	}
	if _, err := w.Write(res); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("can't write response: %v", err), http.StatusInternalServerError)
	}
}
