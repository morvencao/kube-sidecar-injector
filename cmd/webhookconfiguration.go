package main

import (
	"bytes"
	"context"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func createMutatingWebhookConfiguration(caCert *bytes.Buffer, webhookService, webhookNamespace string) error {
	config, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	path := "/mutate"
	fail := admissionregistrationv1.Fail
	sideEffect := admissionregistrationv1.SideEffectClassNone
	mutatingWebhookConfig := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sidecar-injector-webhook",
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name:                    "sidecar-injector.morven.me",
			AdmissionReviewVersions: []string{"v1", "v1beta1"},
			SideEffects:             &sideEffect,
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				CABundle: caCert.Bytes(), // self-generated CA for the webhook
				Service: &admissionregistrationv1.ServiceReference{
					Name:      webhookService,
					Namespace: webhookNamespace,
					Path:      &path,
				},
			},
			Rules: []admissionregistrationv1.RuleWithOperations{
				{
					Operations: []admissionregistrationv1.OperationType{
						admissionregistrationv1.Create,
						admissionregistrationv1.Update,
					},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"pods"},
					},
				},
			},
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"sidecar-injection": "enabled",
				},
			},
			FailurePolicy: &fail,
		}},
	}

	_, err = clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.TODO(), mutatingWebhookConfig, metav1.CreateOptions{})
	return err
}
