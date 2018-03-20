# Diving into Kubernetes MutatingAdmissionWebhook

[Admission controllers](https://kubernetes.io/docs/admin/admission-controllers/) are powerful tools for intercepting requests to the Kubernetes API server prior to persistence of the object. However, they are not very flexible due to the requirement that they are compiled into binary into `kube-apiserver` and configured by the cluster administrator. Starting in Kubernetes 1.7, [Initializers](https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/#initializers) and [External Admission Webhooks](https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/#external-admission-webhooks) are introduced to address this limitation. In Kubernetes 1.9, `Initializers` stays in alpha phase while `External Admission Webhooks` have been promoted to beta and split into [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) and [ValidatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#validatingadmissionwebhook-alpha-in-18-beta-in-19).

`MutatingAdmissionWebhook` together with `ValidatingAdmissionWebhook` are a special kind of `admission controllers` which process mutating and validating on requests matching the rules defined in [MutatingWebhookConfiguration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.9/#mutatingwebhookconfiguration-v1beta1-admissionregistration)(explained below).

In this article, we'll dive into the details of `MutatingAdmissionWebhook` and write a working webhook admission server step by step.

## Benefit of `Webhooks`

`Webhooks` allow Kubernetes cluster-admin to create additional mutating and validating admission plugins to the admission chain of `apiserver` without recompiling them. This provides end-developer with the freedom and flexibility to customize admission logic on multiple actions("CREATA", "UPDATE", "DELETE"...) on any resource. The possible applications are vast. Some common use cases includes:
- Mutating resources before creating them. [Istio](https://github.com/istio), a representative example, injecting [Envoy](https://github.com/envoyproxy/envoy) sidecar container to target pods to implement traffic management and policy enforcement.
- Automated provisioning of `StorageClass`. Observes creation of `PersistentVolumeClaim` objects and automatically adds storage class to them based on predefined policy. Users that do not need to care about `StorageClass` creating.
- Validating complex custom resource. Make sure custom resource can only be created after its definition and all dependencies created and available.
- Restricting namespace. On multi-tenant systems, avoid resources created in reserved namespaces.

Besides the user-cases listed above, many more aplications can be created based on the power of `webhooks`.

## `Webhooks` vs `Initializers`

Based on feedback from the community and use cases in alpha phase of both `External Admission Webhooks` and `Initializers`, the Kubernetes community decided to promote webhooks to beta and split it into `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook`. These updates make webhooks consistent with other admission controllers and enforce `mutate-before-validate`. `Initializers` can also implement dynamic admission control by modifying Kubernetes resources before they are actually created. If you're unfamiliar with `Initializers`, please refer to the acrtcle: https://medium.com/ibm-cloud/kubernetes-initializers-deep-dive-and-tutorial-3bc416e4e13e.

So what's the difference between `Webhooks` and `Initializers`?

- `Webhooks` can be applied on more actions, including 'mutate' or 'admit' on resoures 'CREATE' 'UPDATE' and 'DELETE', whereas `Initializers` can't 'admit' resources for 'DELETE' requests.
- `Webhooks` are not allowed to query resources before created, while `Initializers` are capable of watching the uninitialized resources by the query parameter `?includeUninitialized=true`, which makes resources creating progress transparent.
- Since the `Initializers` persist the 'pre-create' states to `etcd`, higher latency and increased `etcd` burden will be introduced accordingly, especially when `apiserver` upgrades or fails. `Webhooks`, however, consume less memory and computing resources.
- More robustness on failures for `Webhooks` than `Initializers`. Failure policy can be configured in `Webhooks` configuraton to avoid hanging onto resources that are created. Buggy `Initializers`, on the other hand, may block all matched resources creating.

Besides the difference listed above, `Initializer` is stuck in some open issues with long expected development time including quota replenishment bug. Promotion of `Webhooks` to beta may be a signal that more support for it in the future, but that depends. If stable behavior is preferred, suggest you choose `Webhooks`.

## How MutatingAdmissionWebhook works

`MutatingAdmissionWebhook` intercepts requests matching the rules defined in `MutatingWebhookConfiguration` before presisting into [etcd](https://github.com/coreos/etcd). `MutatingAdmissionWebhook` executes the mutation by sending admission requests to webhook server. Webhook server is just plain http server that adhere to the [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go).

The following diagram describes how `MutatingAdmissionWebhook` works in details:

![](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/mutating-admission-webhook.jpg)

The `MutatingAdmissionWebhook` needs three objects to function:

1. **MutatingWebhookConfiguration**
   
   `MutatingAdmissionWebhook` need to be registered in the `apiserver` by providing `MutatingWebhookConfiguration`. During the registration process, MutatingAdmissionWebhook states:
   - How to connect to the webhook admission server
   - How to verify the webhook admission server
   - The URL path of the webhook admission server
   - Rules defining which resource and what action it handles
   - How unrecognized errors from the webhook admission server are handled

2. **MutatingAdmissionWebhook itself**

   `MutatingAdmissionWebhook` is a plugin-style admission controller that can be configured into the `apiserver`. The `MutatingAdmissionWebhook` plugin get the list of interested admission webhooks from `MutatingWebhookConfiguration`. Then the `MutatingAdmissionWebhook` observes the requests to apiserver and intercepts requests matching the rules in admission webhooks and calls them in parallel.

3. **Webhook Admission Server**
   
   `Webhook Admission Server` is just plain http server that adhere to Kubernetes [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go). 
   For each request to the `apiserver`, the `MutatingAdmissionWebhook` sends an `admissionReview`([API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go) for reference) to the relevant webhook admission server. The webhook admission server gathers information like `object`, `oldobject`, and `userInfo` from `admissionReview`, and sends back a `admissionReview` response including `AdmissionResponse` whose `Allowed` and `Result` fields are filled with the admission decision and optional `Patch` to mutate the resoures.
   
## Tutorial for MutatingAdmissionWebhook

Write a complete Webhook Admission Server may be intimidating. To make it easier, we'll write a simple Webhook Admission Server that implements injecting nginx sidecar container and volume. The complete code can be found in [kube-mutating-webhook-tutorial](https://github.com/morvencao/kube-mutating-webhook-tutorial). The project refers to [Kunernetes webhook example](https://github.com/kubernetes/kubernetes/tree/release-1.9/test/images/webhook) and [Istio sidecar injection implementation](https://github.com/istio/istio/tree/master/pilot/pkg/kube/inject).

In the following sections, I'll show you how to write a working containerized webhook admission server and deploy it to a Kubernetes cluster.

#### Prerequisites

`MutatingAdmissionWebhook` requires a Kubernetes 1.9.0 or above with the `admissionregistration.k8s.io/v1beta1` API enabled. Verify that by the following command:
```
kubectl api-versions | grep admissionregistration.k8s.io/v1beta1
```
The result should be:
```
admissionregistration.k8s.io/v1beta1
```
In addition, the `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook` admission controllers should be added and listed in the correct order in the `admission-control` flag of `kube-apiserver`.

### Write the Webhook Server

`Webhook Admission Server` is just plain http server that adhere to Kubernetes [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go). 
I'll paste some pseudo code to describe the main logic:
```
sidecarConfig, err := loadConfig(parameters.sidecarCfgFile)
pair, err := tls.LoadX509KeyPair(parameters.certFile, parameters.keyFile)

whsvr := &WebhookServer {
    sidecarConfig:    sidecarConfig,
    server:           &http.Server {
        Addr:        fmt.Sprintf(":%v", 443),
        TLSConfig:   &tls.Config{Certificates: []tls.Certificate{pair}},
    },
}
	
// define http server and server handler
mux := http.NewServeMux()
mux.HandleFunc("/mutate", whsvr.serve)
whsvr.server.Handler = mux

// start webhook server in new rountine
go func() {
    if err := whsvr.server.ListenAndServeTLS("", ""); err != nil {
        glog.Errorf("Filed to listen and serve webhook server: %v", err)
    }
}()
```
Explanation for the above code:

- `sidecarCfgFile` contains sidecar injector template defined in `ConfigMap` below.
- `certFile` and `keyFile` key pair that will be needed for TLS communication between `apiserver` and `webhook server`.
- Line 19 starts https server listening on 443 on path '/mutate'. 

Next we'll focus on the main logic of handler function `serve`:
```
// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	var reviewResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Error(err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = mutate(ar)
	}

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		response.Response.UID = ar.Request.UID
	}
	// reset the Object and OldObject, they are not needed in a response.
	ar.Request.Object = runtime.RawExtension{}
	ar.Request.OldObject = runtime.RawExtension{}

	resp, err := json.Marshal(response)
	if err != nil {
		glog.Error(err)
	}
	if _, err := w.Write(resp); err != nil {
		glog.Error(err)
	}
}
```
The `serve` function is plain http handler with `http request` and `response writer` parameters. 
- Firstly unmarshals the request to `AdmissionReview`, which contains information like `object`, `oldobject` and `userInfo`...
- Then calls Webhook core function `mutate` to create `patch` that injects sidecar container and volume. 
- Finally, unmarshals the response with admission decision and optional patch, sends it back to `apiserver`.

For the part of `mutate` function, you get the free rein to complete it in your preferred way. Let's take my implementation as an example:
```
// main mutation process
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
	
	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse {
			Allowed: true, 
		}
	}

	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, annotations)
	
	return &v1beta1.AdmissionResponse {
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}
```
From the code above, the `mutate` function calls [mutationRequired](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/webhook.go#L98-L130) to detemine whether mutation is required or not. For those requiring mutation, the `mutate` function gets mutation 'patch' from another function [createPatch](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/webhook.go#L196-L205). Pay attention to the little trick in function `mutationRequired`, we skip the `pods` without annotation `sidecar-injector-webhook.morven.me/inject: true`. That will be mentioned latter when we deployment applications. For complete code, please refer to https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/webhook.go.

#### Create Dockerfile and Build the Container

Create the `build` script:
```
dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kube-mutating-webhook-tutorial .
docker build --no-cache -t morvencao/sidecar-injector:v1 .
rm -rf kube-mutating-webhook-tutorial

docker push morvencao/sidecar-injector:v1
```

And create `Dockerfile` as dependency of build script:
```
FROM alpine:latest

ADD kube-mutating-webhook-tutorial /kube-mutating-webhook-tutorial
ENTRYPOINT ["./kube-mutating-webhook-tutorial"]
```

Before actually building the container, you need a [Docker](https://hub.docker.com/) ID account and change the image name&tag(in `Dockerfile` and `deployment.yaml`) to yours, then execute:
```
[root@mstnode kube-mutating-webhook-tutorial]# ./build
Sending build context to Docker daemon  44.89MB
Step 1/3 : FROM alpine:latest
 ---> 3fd9065eaf02
Step 2/3 : ADD kube-mutating-webhook-tutorial /kube-mutating-webhook-tutorial
 ---> 432de60c2b3f
Step 3/3 : ENTRYPOINT ["./kube-mutating-webhook-tutorial"]
 ---> Running in da6e956d1755
Removing intermediate container da6e956d1755
 ---> 619faa936145
Successfully built 619faa936145
Successfully tagged morvencao/sidecar-injector:v1
The push refers to repository [docker.io/morvencao/sidecar-injector]
efd05fe119bb: Pushed
cd7100a72410: Layer already exists
v1: digest: sha256:7a4889928ec5a8bcfb91b610dab812e5228d8dfbd2b540cd7a341c11f24729bf size: 739
```

#### Create Sidecar Injection Configuration

Now let's create a Kubernetes `ConfigMap`, which includes `container` and `volume` information that will be injected into the target pod.
```
apiVersion: v1
kind: ConfigMap
metadata:
  name: sidecar-injector-webhook-configmap
data:
  sidecarconfig.yaml: |
    containers:
      - name: sidecar-nginx
        image: nginx:1.12.2
        imagePullPolicy: IfNotPresent
        ports:
          - containerPort: 80
        volumeMounts:
          - name: nginx-conf
            mountPath: /etc/nginx
    volumes:
      - name: nginx-conf
        configMap:
          name: nginx-configmap
```
From the above manifest, another ConfigMap including `nginx conf` is required. Here we put it in [nginxconfigmap.yaml](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/deployment/nginxconfigmap.yaml).

Then deploy the two `ConfigMap`s to cluster:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/nginxconfigmap.yaml
configmap "nginx-configmap" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/configmap.yaml
configmap "sidecar-injector-webhook-configmap" created
```

#### Create Secret Including Signed key/cert Pair

Supporting `TLS` for external webhook server is required, because admission is a high security operation. so we need to create TLS certificate signed by `Kubernetes CA` for to secure the communcation between webhook server and `apiserver`. For the complete creating and approving `CSR` process, please refer to https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/. 

For simplicity purposes, we refer to the [script](https://github.com/istio/istio/blob/master/install/kubernetes/webhook-create-signed-cert.sh) from `Istio` and write a similar script called `webhook-create-signed-cert.sh` to automatically create the cert/key pair and include it in a Kubernetes `secret`.
```
#!/bin/bash
while [[ $# -gt 0 ]]; do
    case ${1} in
        --service)
            service="$2"
            shift
            ;;
        --secret)
            secret="$2"
            shift
            ;;
        --namespace)
            namespace="$2"
            shift
            ;;
    esac
    shift
done

[ -z ${service} ] && service=sidecar-injector-webhook-svc
[ -z ${secret} ] && secret=sidecar-injector-webhook-certs
[ -z ${namespace} ] && namespace=default

csrName=${service}.${namespace}
tmpdir=$(mktemp -d)
echo "creating certs in tmpdir ${tmpdir} "

cat <<EOF >> ${tmpdir}/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.${namespace}
DNS.3 = ${service}.${namespace}.svc
EOF

openssl genrsa -out ${tmpdir}/server-key.pem 2048
openssl req -new -key ${tmpdir}/server-key.pem -subj "/CN=${service}.${namespace}.svc" -out ${tmpdir}/server.csr -config ${tmpdir}/csr.conf

# clean-up any previously created CSR for our service. Ignore errors if not present.
kubectl delete csr ${csrName} 2>/dev/null || true

# create  server cert/key CSR and  send to k8s API
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: ${csrName}
spec:
  groups:
  - system:authenticated
  request: $(cat ${tmpdir}/server.csr | base64 | tr -d '\n')
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF

# verify CSR has been created
while true; do
    kubectl get csr ${csrName}
    if [ "$?" -eq 0 ]; then
        break
    fi
done

# approve and fetch the signed certificate
kubectl certificate approve ${csrName}
# verify certificate has been signed
for x in $(seq 10); do
    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
    if [[ ${serverCert} != '' ]]; then
        break
    fi
    sleep 1
done
if [[ ${serverCert} == '' ]]; then
    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
    exit 1
fi
echo ${serverCert} | openssl base64 -d -A -out ${tmpdir}/server-cert.pem


# create the secret with CA cert and server cert/key
kubectl create secret generic ${secret} \
        --from-file=key.pem=${tmpdir}/server-key.pem \
        --from-file=cert.pem=${tmpdir}/server-cert.pem \
        --dry-run -o yaml |
    kubectl -n ${namespace} apply -f -
```

Then execute it and a Kubernetes `secret` including cert/key pair is created:
```
[root@mstnode kube-mutating-webhook-tutorial]# ./deployment/webhook-create-signed-cert.sh
creating certs in tmpdir /tmp/tmp.wXZywp0wAF
Generating RSA private key, 2048 bit long modulus
...........................................+++
..........+++
e is 65537 (0x10001)
certificatesigningrequest "sidecar-injector-webhook-svc.default" created
NAME                                   AGE       REQUESTOR                                           CONDITION
sidecar-injector-webhook-svc.default   0s        https://mycluster.icp:9443/oidc/endpoint/OP#admin   Pending
certificatesigningrequest "sidecar-injector-webhook-svc.default" approved
secret "sidecar-injector-webhook-certs" created
```

#### Create the Sidecar Injector Deployment and Service

The `deployment` brings up 1 `pod` in which the `sidecar-injector` container is running.  The container starts with special arguments:
- `sidecarCfgFile` pointing to the sidecar injector configuration file mounted from `sidecar-injector-webhook-configmap` ConfigMap created above
- `tlsCertFile` and `tlsKeyFile` are cert/key pair mounted from `sidecar-injector-webhook-certs` Secret create by script above
- `alsologtostderr` `v=4` and `2>&1` are logging arguments
```
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: sidecar-injector-webhook-deployment
  labels:
    app: sidecar-injector
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: sidecar-injector
    spec:
      containers:
        - name: sidecar-injector
          image: morvencao/sidecar-injector:v1
          imagePullPolicy: IfNotPresent
          args:
            - -sidecarCfgFile=/etc/webhook/config/sidecarconfig.yaml
            - -tlsCertFile=/etc/webhook/certs/cert.pem
            - -tlsKeyFile=/etc/webhook/certs/key.pem
            - -alsologtostderr
            - -v=4
            - 2>&1
          volumeMounts:
            - name: webhook-certs
              mountPath: /etc/webhook/certs
              readOnly: true
            - name: webhook-config
              mountPath: /etc/webhook/config
      volumes:
        - name: webhook-certs
          secret:
            secretName: sidecar-injector-webhook-certs
        - name: webhook-config
          configMap:
            name: sidecar-injector-webhook-configmap
```

The `service` exposes the `pod` defined above labeled by `app=sidecar-injector` to make it accessible in cluster. This `service` will be referred by the `MutatingWebhookConfiguration` in `clientConfig` section and by default `spec.ports.port` should be **443**(default https port).
```
apiVersion: v1
kind: Service
metadata:
  name: sidecar-injector-webhook-svc
  labels:
    app: sidecar-injector
spec:
  ports:
  - port: 443
    targetPort: 443
  selector:
    app: sidecar-injector
```

Next we deploy the above `Deployment` and `Service` to cluster and verify the `sidecar injector` webhook server is running:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/deployment.yaml
deployment "sidecar-injector-webhook-deployment" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/service.yaml
service "sidecar-injector-webhook-svc" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get deployment
NAME                                  DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
sidecar-injector-webhook-deployment   1         1         1            1           2m
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pod
NAME                                                  READY     STATUS    RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running   0          3m
```

#### Configure webhook admission controller on the fly

`MutatingWebhookConfiguration` specifies which webhook admission servers are enabled and which resources are subject to the admission server. It is recommended that you firstly deploy the webhook admission server and make sure it is working properly before creating the `MutatingWebhookConfiguration`. Otherwise, requests will be unconditionally accepted or rejected based on `failurePolicy`.

For now, we create the `MutatingWebhookConfiguration` manifest with the following content:
```
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: sidecar-injector-webhook-cfg
  labels:
    app: sidecar-injector
webhooks:
  - name: sidecar-injector.morven.me
    clientConfig:
      service:
        name: sidecar-injector-webhook-svc
        namespace: default
        path: "/mutate"
      caBundle: ${CA_BUNDLE}
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    namespaceSelector:
      matchLabels:
        sidecar-injector: enabled
```

Line 8: `name` - name for the webhook, should be fully qualified. Mutiple mutating webhooks are sorted by providing order.
Line 9: `clientConfig` - describes how to connect to the webhook admission server and the TLS certificate. In our case, we specify the `sidecar injector` service.
Line 15: `rules` - specifies what resources and what actions the webhook server handles. In our case, only intercepts request for creating of pods.
Line 20: `namespaceSelector` - `namespaceSelector` decides whether to send admission request the webhook server on an object based on whether the namespace for that object matches the selector.

Before deploying the `MutatingWebhookConfiguration`, we need to replace the `${CA_BUNDLE}` with apiserver's default `caBundle`. Let's write the script `webhook-patch-ca-bundle.sh` to automate this process:
```
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

ROOT=$(cd $(dirname $0)/../../; pwd)

export CA_BUNDLE=$(kubectl get configmap -n kube-system extension-apiserver-authentication -o=jsonpath='{.data.client-ca-file}' | base64 | tr -d '\n')

if command -v envsubst >/dev/null 2>&1; then
    envsubst
else
    sed -e "s|\${CA_BUNDLE}|${CA_BUNDLE}|g"
fi
```

Then execute:
```
[root@mstnode kube-mutating-webhook-tutorial]# cat ./deployment/mutatingwebhook.yaml |\
>   ./deployment/webhook-patch-ca-bundle.sh >\
>   ./deployment/mutatingwebhook-ca-bundle.yaml
```

Finally we can deploy `MutatingWebhookConfiguration`:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/mutatingwebhook-ca-bundle.yaml
mutatingwebhookconfiguration "sidecar-injector-webhook-cfg" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get mutatingwebhookconfiguration
NAME                           AGE
sidecar-injector-webhook-cfg   11s
```

#### Verification and Troubleshooting

Now it's time to verify sidecar injector works as expected and try to see how to troubleshoot if you encounter issues.
Typically we create and deploy a sleep application in `default` namespace to see if the sidecar can be injected.
```
[root@mstnode kube-mutating-webhook-tutorial]# cat <<EOF | kubectl create -f -
> apiVersion: extensions/v1beta1
> kind: Deployment
> metadata:
>   name: sleep
> spec:
>   replicas: 1
>   template:
>     metadata:
>       annotations:
>         sidecar-injector-webhook.morven.me/inject: "true"
>       labels:
>         app: sleep
>     spec:
>       containers:
>       - name: sleep
>         image: tutum/curl
>         command: ["/bin/sleep","infinity"]
>         imagePullPolicy: IfNotPresent
> EOF
deployment "sleep" created
```

Pay close attention to the `spec.template.metadata.annotations` as there is a new annotation added:
```
sidecar-injector-webhook.morven.me/inject: "true"
```
The sidecar injector has some logic to check the existence of the above annotation before injecting sidecar container and volume. 
You're free to delete the logic or customize it before build the sidecar injector container.

Check the `deployment` and `pod`:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get deployment
NAME                                  DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
sidecar-injector-webhook-deployment   1         1         1            1           18m
sleep                                 1         1         1            1           58s
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pod
NAME                                                  READY     STATUS    RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running   0          18m
sleep-6d79d8dc54-r66vz                                1/1       Running   0          1m
```
It's not there. What's going on?
Let's check the sidecar injector logs:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl logs -f sidecar-injector-webhook-deployment-bbb689d69-fdbgj
I0314 08:48:15.140858       1 webhook.go:88] New configuration: sha256sum 21669464280f76170b88241fd79ecbca3dcebaec5c152a4a9a3e921ff742157f

```
We can't find any logs that indicate webhook server got admission request, seems that request hadn't been sent to `sidecar injector` webhook server. 
So there is a possibility that the issue is caused by configuration in `MutatingWebhookConfiguration`. Do a double check of `MutatingWebhookConfiguration` and we find following content:
```
    namespaceSelector:
      matchLabels:
        sidecar-injector: enabled
```

#### Control sidecar injector with `namespaceSelector`

We have configured 'namespaceSelector' in `MutatingWebhookConfiguration`, which means only resources in namespace matching the selector will be sent to webhook server. So we need label the `default` namespace with `sidecar-injector=enabled`:

```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl label namespace default sidecar-injector=enabled
namespace "default" labeled
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get namespace -L sidecar-injector
NAME          STATUS    AGE       sidecar-injector
default       Active    1d        enabled
kube-public   Active    1d
kube-system   Active    1d
```

We have configured the `MutatingWebhookConfiguration` resulting in the sidecar injection occuring at pod creation time. Kill the running pod and verify a new pod is created with the injected sidecar.
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl delete pod sleep-6d79d8dc54-r66vz
pod "sleep-6d79d8dc54-r66vz" deleted
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pods
NAME                                                  READY     STATUS              RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running             0          29m
sleep-6d79d8dc54-b8ztx                                0/2       ContainerCreating   0          3s
sleep-6d79d8dc54-r66vz                                1/1       Terminating         0          11m
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pod sleep-6d79d8dc54-b8ztx -o yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: default
    sidecar-injector-webhook.morven.me/inject: "true"
    sidecar-injector-webhook.morven.me/status: injected
  labels:
    app: sleep
    pod-template-hash: "2835848710"
  name: sleep-6d79d8dc54-b8ztx
  namespace: default
spec:
  containers:
  - command:
    - /bin/sleep
    - infinity
    image: tutum/curl
    imagePullPolicy: IfNotPresent
    name: sleep
    resources: {}
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: default-token-d7t2r
      readOnly: true
  - image: nginx:1.12.2
    imagePullPolicy: IfNotPresent
    name: sidecar-nginx
    ports:
    - containerPort: 80
      protocol: TCP
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /etc/nginx
      name: nginx-conf
  volumes:
  - name: default-token-d7t2r
    secret:
      defaultMode: 420
      secretName: default-token-d7t2r
  - configMap:
      defaultMode: 420
      name: nginx-configmap
    name: nginx-conf
...
```
We can see that sidecar container and volume have been injected into sleep application successfully. Until now, we have working sidecar injector with `MutatingAdmissionWebhook`. With `namespaceSelector` we can easily control whether the pods in specified namespace will be injected or not. 

But there is a problem for this, with the above configurations, all of the pods in `default` namespace will be injected with a sidecar, this may be not expected for some cases.

#### Control sidecar injector with `annotation`

Thanks to flexibility of `MutatingAdmissionWebhook`, we can easily customized the mutating logic to filter resources with specified annotations. Remember the annotation `sidecar-injector-webhook.morven.me/inject: "true"` mentioned above? It can be used as an extra control on sidecar injector. I have written [some code](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/webhook.go#L98-L130) in webhook server to skip injecting for pod without the annotation.

Let's give it a try. In this case, we create another sleep application without `sidecar-injector-webhook.morven.me/inject: "true"` annotation in `podTemplateSpec`:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl delete deployment sleep
deployment "sleep" deleted
[root@mstnode kube-mutating-webhook-tutorial]# cat <<EOF | kubectl create -f -
apiVersion: extensions/v1beta1
> kind: Deployment
> metadata:
>   name: sleep
> spec:
>   replicas: 1
>   template:
>     metadata:
>       labels:
>         app: sleep
>     spec:
>       containers:
>       - name: sleep
>         image: tutum/curl
>         command: ["/bin/sleep","infinity"]
>         imagePullPolicy: IfNotPresent
> EOF
deployment "sleep" created
```

And then verify the sidecar injector skipped the pod:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get deployment
NAME                                  DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
sidecar-injector-webhook-deployment   1         1         1            1           45m
sleep                                 1         1         1            1           17s
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pod
NAME                                                  READY     STATUS        RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running       0          45m
sleep-776b7bcdcd-4bz58                                1/1       Running       0          21s
```

The output shows that the sleep application contains only one container, no extra container and volume injected.
Then we patch the sleep deployment to add the additional annotation and verify it will be injected after recreated:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl patch deployment sleep -p '{"spec":{"template":{"metadata":{"annotations":{"sidecar-injector-webhook.morven.me/inject": "true"}}}}}'
deployment "sleep" patched
[root@mstnode kube-mutating-webhook-tutorial]# kubectl delete pod sleep-776b7bcdcd-4bz58
pod "sleep-776b7bcdcd-4bz58" deleted
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pods
NAME                                                  READY     STATUS              RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running             0          49m
sleep-3e42ff9e6c-6f87b                                0/2       ContainerCreating   0          18s
sleep-776b7bcdcd-4bz58                                1/1       Terminating         0          3m
```
As expected, the pod has been injected with extra sidecar container.
Now, we got working sidecar injector with `mutatingAdmissionWebhook` and its coarse-grained control by `namespaceSelector` and fine-grained control by additional `annotation`.

## Conclusion

`MutatingAdmissionWebhook` is one of easiest ways of extending Kubernetes with new policy controls, resources mutation...

This feature will enable more workloads and support more ecosystem components, including [Istio](https://github.com/istio/istio) service mesh platform. Starting with Istio 0.5.0, Istio has refactored to support their auto injection code with `MutatingAdmissionWebhook` replacing `initializers`.

## Reference

- http://blog.kubernetes.io/2018/01/extensible-admission-is-beta.html
- https://docs.google.com/document/d/1c4kdkY3ha9rm0OIRbGleCeaHknZ-NR1nNtDp-i8eH8E/view
- https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/
- https://github.com/kubernetes/kubernetes/tree/release-1.9/test/images/webhook