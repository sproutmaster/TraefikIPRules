# Traefik IP Rules

IPRules is a middleware plugin which accepts or blocks requests originating from those IPs based on an IP address, range
or subnet.

## How to use (Kubernetes CRD)

1. Add plugin

   ```yaml
   # helm-values.yaml
   experimental:
      plugins:
         iprules:
            moduleName: "github.com/sproutmaster/TraefikIPRules"
            version: "v1.1"
   ```

2. Configure Middleware
   ```yaml
   # middleware.yaml
    apiVersion: traefik.io/v1alpha1
    kind: Middleware
    metadata:
      name: ip-filter
    spec:
      plugin:
        iprules:
          allow:
           - "192.168.1.1"                    # Single IP
           - "10.0.0.0/8"                     # CIDR range
           - "172.16.1.1-172.16.1.255"        # IP range
          deny:
           - "192.168.1.100-192.168.1.200"    # Block this IP range
           - "10.0.1.0/24"                    # Block this subnet
          precedence: "deny"                  # deny first
     ```

3. Reference it in ingressRoute

    ```yaml
    # ingress-route.yaml
    apiVersion: traefik.io/v1alpha1
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

## How to use (Docker Labels)

```yaml
 labels:
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.allow=192.168.1.1"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.allow=10.0.0.0/8"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.allow=172.16.1.1-172.16.1.255"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.deny=192.168.1.100-192.168.1.200"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.precedence=deny"
```
