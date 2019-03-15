# Kubernetes Mutating Admission Webhook for sidecar injection

This tutoral shows how to build and deploy a [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a nginx sidecar container into pod prior to persistence of the object.

## Prerequisites

Kubernetes 1.9.0 or above with the `admissionregistration.k8s.io/v1beta1` API enabled. Verify that by the following command:
```
kubectl api-versions | grep admissionregistration.k8s.io/v1beta1
```
The result should be:
```
admissionregistration.k8s.io/v1beta1
```

In addition, the `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook` admission controllers should be added and listed in the correct order in the admission-control flag of kube-apiserver.

## Build

1. Setup dep

   The repo uses [dep](https://github.com/golang/dep) as the dependency management tool for its Go codebase. Install `dep` by the following command:
```
go get -u github.com/golang/dep/cmd/dep
```

2. Build and push docker image
   
```
./build
```

## Deploy

1. Create a signed cert/key pair and store it in a Kubernetes `secret` that will be consumed by sidecar deployment
```
./deployment/webhook-create-signed-cert.sh \
    --service sidecar-injector-webhook-svc \
    --secret sidecar-injector-webhook-certs \
    --namespace default
```

2. Patch the `MutatingWebhookConfiguration` by set `caBundle` with correct value from Kubernetes cluster
```
cat deployment/mutatingwebhook.yaml | \
    deployment/webhook-patch-ca-bundle.sh > \
    deployment/mutatingwebhook-ca-bundle.yaml
```

3. Deploy resources
```
kubectl create -f deployment/nginxconfigmap.yaml
kubectl create -f deployment/configmap.yaml
kubectl create -f deployment/deployment.yaml
kubectl create -f deployment/service.yaml
kubectl create -f deployment/mutatingwebhook-ca-bundle.yaml
```

## Verify

1. The sidecar inject webhook should be running
```
[root@mstnode ~]# kubectl get pods
NAME                                                  READY     STATUS    RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-882dd   1/1       Running   0          5m
[root@mstnode ~]# kubectl get deployment
NAME                                  DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
sidecar-injector-webhook-deployment   1         1         1            1           5m
```

2. Label the default namespace with `sidecar-injector=enabled`
```
kubectl label namespace default sidecar-injector=enabled
[root@mstnode ~]# kubectl get namespace -L sidecar-injector
NAME          STATUS    AGE       SIDECAR-INJECTOR
default       Active    18h       enabled
kube-public   Active    18h
kube-system   Active    18h
```

3. Deploy an app in Kubernetes cluster, take `sleep` app as an example
```
[root@mstnode ~]# cat <<EOF | kubectl create -f -
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: sleep
spec:
  replicas: 1
  template:
    metadata:
      annotations:
        sidecar-injector-webhook.morven.me/inject: "yes"
      labels:
        app: sleep
    spec:
      containers:
      - name: sleep
        image: tutum/curl
        command: ["/bin/sleep","infinity"]
        imagePullPolicy: 
EOF
```

4. Verify sidecar container injected
```
[root@mstnode ~]# kubectl get pods
NAME                     READY     STATUS        RESTARTS   AGE
sleep-5c55f85f5c-tn2cs   2/2       Running       0          1m
```
