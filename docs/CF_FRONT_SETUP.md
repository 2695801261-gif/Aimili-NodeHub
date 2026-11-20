# Optional Cloudflare front for VPN Gate probes

NodeHub can test VPN Gate OpenVPN candidates through a private VLESS front proxy. This is an optional reachability aid; it does not change the VPN Gate relay's exit IP and does not prove that the exit is residential.

## Accepted format

The current parser accepts either a **VLESS + TLS + WebSocket** share URI or a Mihomo YAML proxy/config containing at least one VLESS + TLS + WebSocket proxy. It validates the UUID, host, port, TLS, WebSocket transport, SNI and path. Trojan, XHTTP, plain WS, Reality, and generic subscription URLs are not accepted by this setting. YAML entries with `skip-cert-verify: true` are rejected.

Example shape (placeholders only):

```text
vless://<UUID>@<WORKER_HOST>:443?encryption=none&security=tls&type=ws&host=<HOST_HEADER>&sni=<SNI>&path=%2F<WS_PATH>
```

If using CFNext, use a VLESS Worker-mode node that actually exports TLS WebSocket. A CFNext Home/VPN Gate subscription is not itself the front configuration expected here. You may paste the single VLESS share URI or a Mihomo YAML file containing that proxy.

## Store it safely

1. Open the NodeHub GitHub repository.
2. Go to **Settings → Secrets and variables → Actions**.
3. Create a repository secret named `NODEHUB_CF_FRONT_URI`.
4. Put the complete VLESS share URI in the secret value.
5. Save it; the next full collection run will use it for VPN Gate CI probes.

Do not put the URI, UUID, or any private credentials in source files, issues, logs, or public subscriptions. The workflow already maps this secret into the classifier process, which uses it only as a Mihomo `dialer-proxy` for VPN Gate probes. The URI is not serialized into evidence or published node profiles.

## What changes when enabled

- Only VPN Gate probe copies receive the `dialer-proxy` field.
- The actual VPN Gate OpenVPN tunnel still has to establish successfully.
- The three independent exit-IP echo services must still reach a two-of-three quorum.
- Country, ASN, ISP, Layer3 and O-X-L checks still apply to the observed VPN Gate exit.
- The published VPN Gate profiles remain direct-connect profiles; the front is not embedded in the public subscription.

Without the secret, probes use the GitHub Actions runner's direct network path. A previous evidence snapshot with `probe_underlay: DIRECT` confirms that the front was not used for that run.
