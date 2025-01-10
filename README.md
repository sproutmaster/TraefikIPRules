# Traefik IP Rules

IPRules is a middleware plugin which accepts IP addresses or IP address ranges, and accepts or blocks requests
originating from those IPs.

## How to use (Kubernetes CRD)

1. Add plugin

   ```yaml
   # helm-values.yaml
   experimental:
      plugins:
         ipRule:
            moduleName: "github.com/sproutmaster/TraefikIPRules"
            version: "v1.0.0"
   ```
   
2. Configure Middleware
   ```yaml
   # middleware.yaml
    apiVersion: traefik.containo.us/v1alpha1
    kind: Middleware
    metadata:
      name: ip-filter
    spec:
      plugin:
        ipRule:
          denyList:
            - "192.168.1.0/24"
          allowList:
            - "0.0.0.0/0"
     ```
   
3. Reference it in ingressRoute

    ```yaml
    # ingress-route.yaml
    apiVersion: traefik.containo.us/v1alpha1
    kind: IngressRoute
    metadata:
      name: my-ing
    spec:
      entryPoints:
        - web
    routes:
      - match: Host(`svc.example.com`)
        kind: Rule
        services:
          - name: my-svc
        port: 80
        middlewares:
          - name: ip-filter
      ```
   