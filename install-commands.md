        STEPS TO INSTALL WAZUH


        1. Run this command to generate the certificates
        	You can generate self-signed certificates for the Wazuh indexer cluster using the script at 
        	certs/indexer_cluster/generate_certs.sh 

        	Run 'chmod +x certs/indexer_cluster/generate_certs.sh' first to make the script executable.

			You can generate self-signed certificates for the Wazuh dashboard cluster using the script at 
			certs/dashboard_http/generate_certs.sh 

			Run 'chmod +x certs/dashboard_http/generate_certs.sh' first to make the script executable.


        2. Run this command to generate the Secrets and configmaps

        	kubectl create secret generic indexer-certs \
			  --from-file=certs/indexer_cluster/root-ca.pem \
			  --from-file=certs/indexer_cluster/node.pem \
			  --from-file=certs/indexer_cluster/node-key.pem \
			  --from-file=certs/indexer_cluster/dashboard.pem \
			  --from-file=certs/indexer_cluster/dashboard-key.pem \
			  --from-file=certs/indexer_cluster/admin.pem \
			  --from-file=certs/indexer_cluster/admin-key.pem \
			  --from-file=certs/indexer_cluster/filebeat.pem \
			  --from-file=certs/indexer_cluster/filebeat-key.pem \
			  --namespace=wazuh \
			  --dry-run=client -o yaml > indexer-certs-secret.yaml

			kubectl create secret generic dashboard-certs \
			  --from-file=certs/dashboard_http/cert.pem \
			  --from-file=certs/dashboard_http/key.pem \
			  --from-file=certs/indexer_cluster/root-ca.pem \
			  --namespace=wazuh \
			  --dry-run=client -o yaml > dashboard-certs-secret.yaml

			kubectl create configmap indexer-conf \
			  --from-file=indexer_stack/wazuh-indexer/indexer_conf/opensearch.yml \
			  --from-file=indexer_stack/wazuh-indexer/indexer_conf/internal_users.yml \
			  --namespace=wazuh \
			  --dry-run=client -o yaml > indexer-conf-configmap.yaml

			kubectl create configmap wazuh-conf \
			  --from-file=wazuh_managers/wazuh_conf/master.conf \
			  --from-file=wazuh_managers/wazuh_conf/worker.conf \
			  --namespace=wazuh \
			  --dry-run=client -o yaml > wazuh-conf-configmap.yaml

			kubectl create configmap dashboard-conf \
			  --from-file=indexer_stack/wazuh-dashboard/dashboard_conf/opensearch_dashboards.yml \
			  --namespace=wazuh \
			  --dry-run=client -o yaml > dashboard-conf-configmap.yaml

			Run these commands in your shell to create the following YAML files:

			indexer-certs-secret.yaml

			dashboard-certs-secret.yaml

			indexer-conf-configmap.yaml

			wazuh-conf-configmap.yaml

			dashboard-conf-configmap.yaml


		Then run this kubectl apply -f ./wazuh -R -n wazuh

		IF USING DOCKER DESKTOP , INSTALL RANCHER AS A PROVISIONER
		kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml

		 On a local cluster deployment where the external IP address is not accessible, you can use port-forward:


		kubectl -n wazuh port-forward service/dashboard 8443:443
	
		The Wazuh dashboard is accessible on https://localhost:8443.

		The default credentials are admin:SecretPassword.


        