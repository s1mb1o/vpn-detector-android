# Roadmap

## Done

- [x] Project scaffold (Gradle, Compose, empty activity)
- [x] Basic VPN flag detection (TRANSPORT_VPN)
- [x] Extended system checks (tunnel interfaces, active iface, default route)
- [x] Network-level checks (HTTP proxy, DNS, MTU, Private DNS)
- [x] Installed VPN app detection, root/mock/dev indicators
- [ ] Verdict scoring system (HARD/SOFT/INFO/PASS severity model)
- [ ] GeoIP probes (multiple providers, external IP lookup)
- [ ] GeoIP analysis (ASN classification, datacenter detection, probe agreement)
- [ ] Consistency checks (SIM vs IP, locale vs IP, timezone vs IP)
- [ ] Tabbed UI per detection category
- [ ] Active probes (latency measurement, IPv6, captive portal)
- [ ] Detection engine orchestration (parallel execution)
- [ ] Run history persistence and sharing
- [ ] Advanced system checks (JVM proxy, VpnTransportInfo, routing anomalies)
- [ ] Local proxy listener detection
- [ ] Router egress traceroute
- [ ] Transparent proxy header detection, country history tracking
- [ ] Privacy policy, release configuration
