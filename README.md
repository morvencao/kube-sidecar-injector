# kube-sidecar-injector

This repo is used for tutoral to create a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a nginx sidecar container into pod prior to persistence of the object.

## Prerequisites

- [git](https://git-scm.com/downloads)
- [go](https://golang.org/dl/) version v1.17+
- [docker](https://docs.docker.com/install/) version 19.03+
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) version v1.19+
- Access to a Kubernetes v1.19+ cluster with the `admissionregistration.k8s.io/v1` API enabled. Verify that by the following command:

```
kubectl api-versions | grep admissionregistration.k8s.io
```
The result should be:
```
admissionregistration.k8s.io/v1
admissionregistration.k8s.io/v1beta1
```

> Note: In addition, the `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook` admission controllers should be added and listed in the correct order in the admission-control flag of kube-apiserver.

## Build and Deploy

1. Build and push docker image:

```bash
make docker-build docker-push IMAGE=quay.io/<your_quayio_username>/sidecar-injector:latest
```

2. Deploy the kube-sidecar-injector to kubernetes cluster:

```bash
make deploy IMAGE=quay.io/<your_quayio_username>/sidecar-injector:latest
```

3. Verify the kube-sidecar-injector is up and running:

```bash
# kubectl -n sidecar-injector get pod
# kubectl -n sidecar-injector get pod
NAME                                READY   STATUS    RESTARTS   AGE
sidecar-injector-7c8bc5f4c9-28c84   1/1     Running   0          30s
```

## How to use

1. Create a new namespace `test-ns` and label it with `sidecar-injector=enabled`:

```
# kubectl create ns test-ns
# kubectl label namespace test-ns sidecar-injection=enabled
# kubectl get namespace -L sidecar-injection
NAME                 STATUS   AGE   SIDECAR-INJECTION
default              Active   26m
test-ns              Active   13s   enabled
kube-public          Active   26m
kube-system          Active   26m
sidecar-injector     Active   17m
```

2. Deploy an app in Kubernetes cluster, take `alpine` app as an example

```bash
kubectl -n test-ns run alpine \
    --image=alpine \
    --restart=Never \
    --overrides='{"apiVersion":"v1","metadata":{"annotations":{"sidecar-injector-webhook.morven.me/inject":"yes"}}}' \
    --command -- sleep infinity
```

3. Verify sidecar container is injected:

```
# kubectl -n test-ns get pod
NAME                     READY     STATUS        RESTARTS   AGE
alpine                   2/2       Running       0          10s
# kubectl -n test-ns get pod alpine -o jsonpath="{.spec.containers[*].name}"
alpine sidecar-nginx
```

## Troubleshooting

Sometimes you may find that pod is injected with sidecar container as expected, check the following items:

1. The sidecar-injector pod is in running state and no error logs.
2. The namespace in which application pod is deployed has the correct labels(`sidecar-injector=enabled`) as configured in `mutatingwebhookconfiguration`.
3. Check if the application pod has annotation `sidecar-injector-webhook.morven.me/inject":"yes"`.
