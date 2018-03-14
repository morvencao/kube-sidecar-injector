# A dive into Kunernetes MutatingAdmissionWebhook

[Admission controllers](https://kubernetes.io/docs/admin/admission-controllers/) are powerful tools for restricting resources prior to persistence by intercepting requests to `kube-apiserver`. 
But they are not flexible enough for they need to be compiled to binary into `kube-apiserver`. From Kubernetes 1.7, [Initializers](https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/#initializers) and [External Admission Webhooks](https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/#external-admission-webhooks) are introduced to address this limitation. To Kubernetes 1.9, `Initializers` stays in alpha phase while `External Admission Webhooks` have been promoted to beta and split into [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) and [ValidatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#validatingadmissionwebhook-alpha-in-18-beta-in-19).

In this article, we'll dive into the details of `MutatingAdmissionWebhook` and write a working webhook admission server step by step.


`MutatingAdmissionWebhook` together with `ValidatingAdmissionWebhook` are special kind of `admission controllers` which process the mutating and validating on request matching the rules defined in [MutatingWebhookConfiguration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.9/#mutatingwebhookconfiguration-v1beta1-admissionregistration)(explained below).

## Why Webhooks first

According to the feedback of alpha of both `GenericAdmissionWebhook` and `Initializers`, k8s community decides to push webhook to beta abd divide it into `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook`. `MutatingAdmissionWebhook` inherits and extends features of `GenericAdmissionWebhook` to support mutation based on voices from community.

The following explanations for webhooks first are quoted form Mutating Webhooks Beta [design doc](https://docs.google.com/document/d/1c4kdkY3ha9rm0OIRbGleCeaHknZ-NR1nNtDp-i8eH8E/view#):

> 1. **Serves Most Use Cases:** We reviewed code of all current use cases, namely: Kubernetes Built-in Admission Controllers, OpenShift Admission Controllers, Istio & Service Catalog. All of those use cases are well served by mutating and non-mutating webhooks.
> 2. **Less Work:** An engineer quite experienced with both code bases estimated that it is less work to adding Mutating Webhooks and bring both kinds of webhooks to beta; than to bring non-mutating webhooks and initializers to Beta. Some open issues with Initializers with long expected development time include quota replenishment bug, and controller awareness of uninitialized objects.
> 3. **API Consistency:** Prefer completing one related pair of interfaces (both kinds of webhooks) at the same time.

Webhooks' update makes it consistent with other admission controllers and enforces `mutate-before-validate`. Each of narrowly focused webhooks can be added to admission chain without recompiling them and have semantic knowledge of what they are inspecting.

## How MutatingAdmissionWebhook works

`MutatingAdmissionWebhook` intercepts requests matching the rules in `MutatingWebhookConfiguration` before presisted into [ETCD](https://github.com/coreos/etcd). `MutatingAdmissionWebhook` executes the mutating by sending admission requests to webhook server. Webhook server is just plain http server that adhere to [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go), so the possible applications are vast.

The following diagram describes how `MutatingAdmissionWebhook` works in details:

![](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/mutating-admission-webhook.jpg)

The `MutatingAdmissionWebhook` needs three objects to function:

1. MutatingWebhookConfiguration
   `MutatingAdmissionWebhook` need to be registered in the `apiserver` by providing `MutatingWebhookConfiguration`. During the registration process, MutatingAdmissionWebhook states:
   - How to connect to the webhook admission server
   - How to verify the webhook admission server
   - The URL path of the webhook admission server
   - Rules defines what resources and what action it handles
   - How unrecognized errors from the webhook admission server are handled

2. MutatingAdmissionWebhook itself
   `MutatingAdmissionWebhook` is plugin-style admission controller that can be configured into `apiserver`. The `MutatingAdmissionWebhook` plugin get lists of intersted admission webhook from `MutatingWebhookConfiguration`. Then the `MutatingAdmissionWebhook` observes the requests to apiserver and intercepts requests matching the rules in admission webhooks and call them in parallel.

3. Webhook Admission Server
   `Webhook Admission Server` is just plain http server that adhere to k8s [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go). 
   For each request to `apiserver`, the `MutatingAdmissionWebhook` sends an `admissionReview` to the relevant webhook admission server. The webhook admission server gathers information like object, oldobject, and userInfo from `admissionReview`, and sends back a `admissionReview` response including a `AdmissionResponse` whose `Allowed` and `Result` fields are filled with the admission decision and optional `Patch` to mutate the resoures.
   
## Tutorial for MutatingAdmissionWebhook

Write a complete Webhook Admission Server may be intimidating. To make it easier, we'll write a simple Webhook Admission Server that implements injecting nginx sidecar container and volume. The complete code can be find in [kube-mutating-webhook-tutorial](https://github.com/morvencao/kube-mutating-webhook-tutorial). The code is based on [Kunernetes webhook example](https://github.com/kubernetes/kubernetes/tree/release-1.9/test/images/webhook) and [Istio sidecar injection implemention](https://github.com/istio/istio/tree/master/pilot/pkg/kube/inject).

From now on, I'll show you how to write a working webhook admission server and deploy it in Kubernetes cluster.


#### Prerequisites

`MutatingAdmissionWebhook` requires a Kubernetes 1.9.0 or above with the admissionregistration.k8s.io/v1beta1 API enabled. Verify that by the following command:
```
kubectl api-versions | grep admissionregistration.k8s.io/v1beta1
```
The result should be:
```
admissionregistration.k8s.io/v1beta1
```
In addition, the `MutatingAdmissionWebhook` and `ValidatingAdmissionWebhook` admission controllers should be added and listed in the correct order in the `admission-control` flag of `kube-apiserver`.

### Write the Webhook Server

`Webhook Admission Server` is just plain http server that adhere to k8s [API](https://github.com/kubernetes/kubernetes/blob/v1.9.0/pkg/apis/admission/types.go). 
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
Explaination for the above code:

- `sidecarCfgFile` contains sidecar injector template defined in `ConfigMap` below.
- `certFile` and `keyFile` key pair that will be needed for TLS communication between `apiserver` and `webhook server`.
- it will start a https server which listen on 443 on path '/mutate'. Next we'll focus on the handler function `serve`.

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
The `serve` function is just plain http handler. 
- It firstly unmarshal the request to `AdmissionReview` including information like `object`, `oldobject` and `userInfo`.
- Then it calls Webhook core function `mutate` to create `patch` that injects sidecar container and volume. 
- Finally, unmarshal the response with admission decision and send it back to `apiserver`.

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
The `mutate` function skip `pod` in special `namespace` and creates `patch` based on injection policy. For complete code, please refer to https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/webhook.go.

#### Create Dockerfile and Build the Container

Create `Dockerfile`:
```
FROM alpine:latest

ADD kube-mutating-webhook-tutorial /kube-mutating-webhook-tutorial
ENTRYPOINT ["./kube-mutating-webhook-tutorial"]
```

Create the `build` script:
```
dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kube-mutating-webhook-tutorial .
docker build --no-cache -t morvencao/sidecar-injector:v1 .
rm -rf kube-mutating-webhook-tutorial

docker push morvencao/sidecar-injector:v1
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

Now let's create a Kubernetes `ConfigMap`, which includes container and volume information that will be injected to the target pod.
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
From the above manifest, another ConfigMap including nginx conf is required. Here we put it in [nginxconfigmap.yaml](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/deployment/nginxconfigmap.yaml).

Then deploy the two `ConfigMaps` to cluster:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/nginxconfigmap.yaml
configmap "nginx-configmap" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/configmap.yaml
configmap "sidecar-injector-webhook-configmap" created
```

#### Create Secret Including Signed key/cert Pair

Https is enabled by sidecar injector `deployment` and `service`, so we need to create TLS certificate signed by Kubernetes CA for the sidecar injector to consume. For the complete creating and approving `CSR` process, please refer to https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/. 

Here we'll write `webhook-create-signed-cert.sh` script to automatically create the cert/key pair and include it in a Kubernetes `secret`:
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

The `deployment` brings up 1 `pod` in which `sidecar-injector` container is running. And the container starts with special arguments:
- `sidecarCfgFile` points to the sidecar injector configuration file mounted from `sidecar-injector-webhook-configmap` ConfigMap created above
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

The `service` exposes `pod` defined above labeled by `app=sidecar-injector` to make it accessible in cluster. This `service` will be referred by `MutatingWebhookConfiguration` in `clientConfig` section and by default `spec.ports.port` should be **443**(default https port).
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

Then deploy the above `Deployment` and `Service` to cluster:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/deployment.yaml
deployment "sidecar-injector-webhook-deployment" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/service.yaml
service "sidecar-injector-webhook-svc" created
```

#### Create `MutatingWebhookConfiguration`

`MutatingWebhookConfiguration` specifies which webhook admission servers are enabled and which resources are subject to the admission server. It is recommended that you first deploy the webhook admission server and make sure it is working properly before creating the `MutatingWebhookConfiguration`. Request will be unconditionally accepted or rejected based on `failurePolicy`.

Make sure the `sidecar injector` webhook server is running:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get deployment
NAME                                  DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
sidecar-injector-webhook-deployment   1         1         1            1           2m
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get pod
NAME                                                  READY     STATUS    RESTARTS   AGE
sidecar-injector-webhook-deployment-bbb689d69-fdbgj   1/1       Running   0          3m
```

For now, we just create the `MutatingWebhookConfiguration` manifest:
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
Line 9: `clientConfig` - describes how to connect to the webhook admission server and the TLS certificate.
In this case, we specify the `sidecar injector` service.
Line 15: `rules` - specifies what resources and what action the webhook server handles. In this case, only intercepts request for creating of pods.

Before deploying the `MutatingWebhookConfiguration`, we need to replace the `${CA_BUNDLE}` with apiserver's default `caBundle`.
Let's write the script `webhook-patch-ca-bundle.sh` to automate this process:
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

Finally deploy `MutatingWebhookConfiguration`:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl create -f ./deployment/mutatingwebhook-ca-bundle.yaml
mutatingwebhookconfiguration "sidecar-injector-webhook-cfg" created
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get mutatingwebhookconfiguration
NAME                           AGE
sidecar-injector-webhook-cfg   11s
```

#### Verify

Typically we create and deploy a sleep application to see if the sidecar can be injected.
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

Pay attentions to `spec.template.metadata.annotations`, new annotation is added:
```
sidecar-injector-webhook.morven.me/inject: "true"
```
For the sidecar injector has some logic to check the existance of above annotation before injecting sidecar container and volume. You're free to delete the logic or customize it before build the sidecar injector container.

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
Its not there. What's going on?
Let's check the sidecar injector logs:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl logs -f sidecar-injector-webhook-deployment-bbb689d69-fdbgj
I0314 08:48:15.140858       1 webhook.go:88] New configuration: sha256sum 21669464280f76170b88241fd79ecbca3dcebaec5c152a4a9a3e921ff742157f

```
Seems that request hadn't been sent to `sidecar injector` webhook server. Looks like it is caused the issues in `MutatingWebhookConfiguration`. After reviewing `MutatingWebhookConfiguration`, we find:

```
    namespaceSelector:
      matchLabels:
        sidecar-injector: enabled
```
NamespaceSelector decides whether to send admission request the webhook server based on whether the namespace for that object matches the selector. So we need label the `default` namespace with `sidecar-injector=enabled`:
```
[root@mstnode kube-mutating-webhook-tutorial]# kubectl label namespace default sidecar-injector=enabled
namespace "default" labeled
[root@mstnode kube-mutating-webhook-tutorial]# kubectl get namespace -L sidecar-injector
NAME          STATUS    AGE       sidecar-injector
default       Active    1d        enabled
kube-public   Active    1d
kube-system   Active    1d
```

We have configure in `MutatingWebhookConfiguration` that sidecar injection occurs at pod creation time. Kill the running pod and verify a new pod is created with the injected sidecar.
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

Until to now, we have working sidecar injector with `MutatingAdmissionWebhook`. With `namespaceSelector` we can easily control whether the pods in specified namespace will be injected or not. In addition, we get another fine-grained control on sidecar injector by `annotation`. 

In this case, we create another sleep application without `sidecar-injector-webhook.morven.me/inject: "true"` annotation:
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

And then veridy sidecar injectr skipped injecting:
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
From above output, we can see that the sleep application include only one container, and no data was injected.

## Conclusion

`MutatingAdmissionWebhook` is one of easiest ways of extending Kubernetes with new policy controls, resources mutation...

This feature will enable many more workloads and support ecosystem components, including [Istio](https://github.com/istio/istio) service mesh platform. From Istio 0.5.0, Istio have refactor the auto injection code with `MutatingAdmissionWebhook` to replace `initializers`.

## Reference

- http://blog.kubernetes.io/2018/01/extensible-admission-is-beta.html
- https://docs.google.com/document/d/1c4kdkY3ha9rm0OIRbGleCeaHknZ-NR1nNtDp-i8eH8E/view
- https://v1-8.docs.kubernetes.io/docs/admin/extensible-admission-controllers/
- https://github.com/kubernetes/kubernetes/tree/release-1.9/test/images/webhook