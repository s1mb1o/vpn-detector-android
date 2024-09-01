# Roadmap

## Done

- [x] Project scaffold (Gradle, Compose, empty activity)

## Planned

- [ ] Basic VPN flag detection (TRANSPORT_VPN)
- [ ] Extended system checks (tunnel interfaces, routes, proxy)
- [ ] Network-level checks (DNS, MTU, Private DNS)
- [ ] Installed VPN app detection
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
