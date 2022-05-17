package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"sigs.k8s.io/yaml"
	"strings"
	"text/template"
)

type SidecarConfig struct {
	InitContainers []corev1.Container `yaml:"initContainers"`
	Containers     []corev1.Container `yaml:"containers"`
	Volumes        []corev1.Volume    `yaml:"volumes"`
}

type SidecarTemplateValues struct {
	Values     *TemplateDefaultValues
	ObjectMeta *metav1.ObjectMeta
	Secrets    SidecarSecrets
}

type SidecarSecrets struct {
	ApiKey string
}

type TemplateDefaultValues struct {
	Proxy  ProxyContainerDefaultValues `json:"proxy"`
	Init   InitContainerDefaultValues  `json:"init"`
	Global GlobalDefaultValues         `json:"global"`
}

type GlobalDefaultValues struct {
	Image         string `json:"image"`
	Tag           string `json:"tag"`
	ApiHost       string `json:"apiHost"`
	ApiPort       string `json:"apiPort"`
	TarantoolHost string `json:"tarantoolHost"`
}

type InitContainerDefaultValues struct {
	Image     string    `json:"image"`
	Tag       string    `json:"tag"`
	Resources Resources `json:"resources"`
}

type ProxyContainerDefaultValues struct {
	Image     string    `json:"image"`
	Tag       string    `json:"tag"`
	Port      string    `json:"port"`
	Resources Resources `json:"resources"`
}

type Resources struct {
	Limits   CpuMemory `json:"limits"`
	Requests CpuMemory `json:"requests"`
}

type CpuMemory struct {
	Cpu    string `json:"cpu"`
	Memory string `json:"memory"`
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getAnnotation(meta metav1.ObjectMeta, property string, defaultValue interface{}) string {
	value, ok := meta.Annotations[property]
	if !ok {
		value = fmt.Sprint(defaultValue)
	}
	return value
}

func isSet(m map[string]string, key string) bool {
	_, ok := m[key]
	return ok
}

func createTemplateExtraFuncs() template.FuncMap {
	return template.FuncMap{
		"getAnnotation": getAnnotation,
		"isSet":         isSet,
	}
}

func loadSidecarDefaults(filePath string) (*TemplateDefaultValues, error) {
	defaultValuesFile, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully load values from file: " + filePath)

	var defaultValues TemplateDefaultValues
	err = json.Unmarshal(defaultValuesFile, &defaultValues)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully parsed JSON values from file: " + filePath)
	return &defaultValues, nil
}

func loadSidecarSecrets() SidecarSecrets {
	secrets := SidecarSecrets{ApiKey: getEnv(apiKeyEnvName, apiKeyDefault)}
	return secrets
}

func loadSidecarTemplate(filePath string) (*template.Template, error) {
	buf, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully loaded template from file: %v", filePath)

	tmplExtraFuncs := createTemplateExtraFuncs()
	tmpl, err := template.New("").Funcs(tmplExtraFuncs).Parse(string(buf))
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully parsed template from file: %v", filePath)
	return tmpl, nil
}

func parseSidecarConfig(configFile []byte) (*SidecarConfig, error) {
	var cfg SidecarConfig
	err := yaml.Unmarshal(configFile, &cfg)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully parsed sidecar config")
	return &cfg, nil
}

func renderSidecarTemplate(sidecarTemplate *template.Template, sidecarValues SidecarTemplateValues) (*SidecarConfig, error) {
	var buf strings.Builder
	err := sidecarTemplate.Execute(&buf, sidecarValues)
	if err != nil {
		return nil, err
	}
	infoLogger.Printf("Successfully rendered template")

	sidecarConfig, err := parseSidecarConfig([]byte(buf.String()))
	if err != nil {
		return nil, err
	}
	return sidecarConfig, nil
}
