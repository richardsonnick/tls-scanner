FROM registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.25-openshift-4.22 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN make build

FROM registry.ci.openshift.org/ocp/4.22:base-rhel9

ARG OC_VERSION=latest
ARG TARGETARCH
ARG TESTSSL_VERSION=3.2.2

RUN dnf -y update && \
    dnf install -y --allowerasing binutils file go podman runc jq skopeo tar lsof openssl bash && \
    dnf clean all

RUN wget -O "openshift-client-linux-${OC_VERSION}.tar.gz" "https://mirror.openshift.com/pub/openshift-v4/${TARGETARCH}/clients/ocp/${OC_VERSION}/openshift-client-linux.tar.gz" && \
    tar -C /usr/local/bin -xzvf "openshift-client-linux-$OC_VERSION.tar.gz" oc && \
    rm -f "openshift-client-linux-$OC_VERSION.tar.gz"

# Install testssl.sh
RUN curl -L "https://testssl.sh/testssl.sh-${TESTSSL_VERSION}.tar.gz" -o /tmp/testssl.tar.gz && \
    mkdir -p /opt/testssl && \
    tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1 && \
    chmod +x /opt/testssl/testssl.sh && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    rm -f /tmp/testssl.tar.gz

COPY --from=builder /app/bin/tls-scanner /usr/local/bin/tls-scanner

ENTRYPOINT ["/usr/local/bin/tls-scanner"]

LABEL com.redhat.component="tls-scanner"
