# IOCs de ejemplo - Análisis Forense de Redes

## IPs (ejemplo)
- 203.0.113.10
- 198.51.100.5

## Dominios/URLs (ejemplo)
- c2.example[.]com
- data-exfil.example.org/upload

## Hashes
- SHA256 (PCAP): a3f5c5e8e0b2f5f6d0a1b2c3d4e5f67890abcdef1234567890abcdef12345678

## Firmas / Reglas de ejemplo
- Suricata (ejemplo): alert tcp any any -> 203.0.113.10 any (msg:"C2 beacon"; sid:1000001; rev:1;)

## Muestras / PCAP
- public_sample_exfil.pcap (descripción: flujo simulado de subida HTTP)
