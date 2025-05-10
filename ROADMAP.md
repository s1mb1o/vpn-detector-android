# Roadmap

## Done

- [x] Project scaffold (Gradle, Compose, empty activity)
- [x] Basic VPN flag detection (TRANSPORT_VPN)
- [x] Extended system checks (tunnel interfaces, active iface, default route)
- [x] Network-level checks (HTTP proxy, DNS, MTU, Private DNS)
- [x] Installed VPN app detection, root/mock/dev indicators
- [x] Verdict scoring system (HARD/SOFT/INFO/PASS severity model)
- [x] GeoIP probes (6 providers: ipify, ipinfo, ip-api, ifconfig.co, myip.com, Cloudflare)
- [x] GeoIP analysis (ASN classification, datacenter detection, reputation flags, probe agreement)
- [x] Consistency checks (SIM vs IP, network vs IP, MCC vs IP, carrier vs ASN, locale, timezone)
- [x] Tabbed UI per detection category (System, GeoIP, Consistency, Probes)
- [x] Active probes (latency measurement, IPv6, captive portal, local addresses)
- [ ] Detection engine orchestration (parallel execution)
- [ ] Run history persistence and sharing
- [ ] Advanced system checks (JVM proxy, VpnTransportInfo, routing anomalies)
- [ ] Local proxy listener detection
- [ ] Router egress traceroute
- [ ] Transparent proxy header detection, country history tracking
- [ ] Privacy policy, release configuration
