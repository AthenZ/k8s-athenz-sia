.PHONY: test e2e setup clean athenz-distribution-checkout kind-create \
	kind-load-images authzproxy-configure k8s-athenz-sia-image-build \
	athenz-deploy authzproxy-deploy authzproxy-role-member athenz-client-deploy \
	force-local-sia-image athenz-client-role-member

E2E_ROOT_DIR ?= $(abspath $(CURDIR)/..)
E2E_ATHENZ_DISTRIBUTION_DIR ?= $(E2E_ROOT_DIR)/.external/athenz-distribution
E2E_ATHENZ_DISTRIBUTION_REPO ?= https://github.com/ctyano/athenz-distribution.git
E2E_ATHENZ_DISTRIBUTION_REF ?= latest
E2E_K8S_ATHENZ_SIA_IMAGE ?= athenz/k8s-athenz-sia:local
E2E_ATHENZ_NAMESPACE ?= athenz
E2E_ATHENZ_CLIENT_DIR ?= $(E2E_ROOT_DIR)/e2e/athenz-client
E2E_ATHENZ_CLIENT_KUSTOMIZE_DIR ?= $(E2E_ROOT_DIR)/e2e/athenz-client/kustomize
E2E_ATHENZ_ZTS_PROPERTIES ?= $(E2E_ATHENZ_DISTRIBUTION_DIR)/kubernetes/athenz-zts-server/kustomize/conf/zts.properties
E2E_ATHENZ_ZTS_CERT_DNS_SUFFIX ?= .athenz.cloud,.svc.cluster.local,svc.cluster.local

athenz-distribution-checkout:
	@echo "Preparing athenz-distribution checkout..."
	@chmod +x scripts/prepare-athenz-distribution.sh
	@./scripts/prepare-athenz-distribution.sh \
		"$(E2E_ATHENZ_DISTRIBUTION_DIR)" \
		"$(E2E_ATHENZ_DISTRIBUTION_REPO)" \
		"$(E2E_ATHENZ_DISTRIBUTION_REF)"

patch-athenz-zts-cert-dns-suffix: athenz-distribution-checkout
	@echo "Configuring ZTS cert DNS suffixes before deploy..."
	
	@if ! grep -q '^athenz\.zts\.cert_dns_suffix=' "$(E2E_ATHENZ_ZTS_PROPERTIES)"; then \
		echo 'athenz.zts.cert_dns_suffix=$(E2E_ATHENZ_ZTS_CERT_DNS_SUFFIX)' >> "$(E2E_ATHENZ_ZTS_PROPERTIES)"; \
	fi
	@grep '^athenz\.zts\.cert_dns_suffix=' "$(E2E_ATHENZ_ZTS_PROPERTIES)"

kind-create: athenz-distribution-checkout
	@echo "Creating local kind cluster..."
	@kind delete cluster || true
	@kind create cluster
	@kubectl cluster-info

k8s-athenz-sia-image-build:
	@echo "Building local k8s-athenz-sia image for e2e..."
	@docker build -t "$(E2E_K8S_ATHENZ_SIA_IMAGE)" "$(E2E_ROOT_DIR)"

kind-load-images: athenz-distribution-checkout k8s-athenz-sia-image-build
	@echo "Loading e2e images into kind..."
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" load-docker-images
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" load-kubernetes-images DOCKER_REGISTRY=ghcr.io/ctyano/
	@kind load docker-image "$(E2E_K8S_ATHENZ_SIA_IMAGE)"

athenz-deploy: kind-create kind-load-images patch-athenz-zts-cert-dns-suffix
	@echo "Deploying Athenz core components locally..."
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" clean-kubernetes-athenz
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" deploy-kubernetes-athenz
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" deploy-kubernetes-athenz-identityprovider

authzproxy-deploy: athenz-deploy
	@echo "Deploying upstream authzproxy workload..."
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)" deploy-kubernetes-athenz-authzproxy
	@kubectl rollout status deployment/authzproxy-deployment -n "$(E2E_ATHENZ_NAMESPACE)" --timeout=180s

athenz-client-deploy: authzproxy-deploy
	@echo "Deploying local athenz-client workload manifest..."
	@$(MAKE) -C "$(E2E_ATHENZ_DISTRIBUTION_DIR)/kubernetes" setup-athenz-client
	@kubectl apply -k "$(E2E_ATHENZ_CLIENT_KUSTOMIZE_DIR)"
	@kubectl rollout status deployment/client-deployment -n "$(E2E_ATHENZ_NAMESPACE)" --timeout=180s

e2e: athenz-client-deploy
	@echo "Running k8s-athenz-sia BDD e2e..."
	cd "$(CURDIR)" && go test -v -run TestFeatures -count=1 ./siae2e

setup: athenz-client-deploy
	@echo "Local k8s-athenz-sia e2e environment is ready."

clean:
	@echo "Cleaning local authzproxy e2e environment..."
	@kind delete cluster || true