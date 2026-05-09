# Traefik IP Rules

IPRules is a Traefik middleware plugin that filters incoming requests by allowing or denying access based on specified
IP addresses, ranges, or subnets.

## How to use (Kubernetes CRD)

1. Add plugin

   ```yaml
   # helm-values.yaml
   experimental:
      plugins:
         iprules:
            moduleName: "github.com/sproutmaster/TraefikIPRules"
            version: "v1.0.3"
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
           - "192.168.1.1"                        # Single IP
           - "10.0.0.0/8"                         # CIDR range
           - "172.16.1.1-172.16.1.255"            # IP range
          deny:
           - "192.168.1.100-192.168.1.200"        # Block this IP range
           - "10.0.1.0/24"                        # Block this subnet
          precedence: "deny"                      # deny first
          customMessage: "Access denied"          # Custom deny message (default: "Access denied"). Set to "" for empty body.
          customMessageStatusCode: 403            # Custom HTTP status code 100-599 (default: 403)
          customMessageContentType: "text/plain"  # Custom Content-Type header (default: text/plain)
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
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.customMessage=Access denied"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.customMessageStatusCode=403"
   - "traefik.http.middlewares.iprules.plugin.traefik-ip-rules.customMessageContentType=application/json"
```
