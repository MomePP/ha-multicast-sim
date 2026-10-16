# ha-multicast-sim

Reproduce the mDNS/SSDP load of many Home Assistant instances and ESPHome devices on a Wi-Fi network, without 100 laptops running HAOS VMs.

Built to test a hypothesis from an IoT workshop: does discovery traffic from ~100 HAOS VMs and ~200 ESPHome devices exhaust Wi-Fi airtime? Group-addressed frames go out at the lowest basic rate (1 Mbps on 2.4 GHz with 802.11b rates enabled) and are never acknowledged, so a small amount of multicast data can fill a channel.

Single file, Python 3.8+, standard library only.

## Modes

| Mode | What it sends or measures |
|---|---|
| `sim` | Models H Home Assistant instances and D ESPHome devices on one VLAN. Each HA restart sends probes and announcements, then 4 zeroconf browse rounds (+0, +1, +5, +14 s, as python-zeroconf does). ESPHome devices answer the first multicast round, at most once per second each (RFC 6762 §6). Later rounds carry known-answer lists. SSDP M-SEARCH goes to multicast and 255.255.255.255 every 10 min. |
| `flood` | Fixed rate (`--pps`) or stepped (`--ramp 0,25,50,100`) multicast, as valid mDNS responses or SSDP, at a chosen size. Finds the rate where the network breaks. |
| `listen` | Counts mDNS/SSDP/broadcast arriving at this host. Confirms the AP forwards the traffic, and measures a real network. |

Each report row shows packets/s, kbps, estimated airtime at 1 Mbps and at `--basic-rate` (default 12), and optionally ping loss and p50/p95/max (`--ping HOST`).

The airtime columns are a calculation: preamble + frame + DIFS + mean backoff, no ACK. Values over 100% mean the offered load exceeds what the channel can carry. The ping column is the measured effect.

## Usage

```bash
# Client B on the 2.4 GHz SSID: confirm delivery and measure the harm
python3 mcast_sim.py listen --ping 10.0.0.1

# Sender A, ideally wired to an access port in the same VLAN: find the breaking point
python3 mcast_sim.py flood --ramp 0,25,50,100,200,400 --step 30 --size 400

# Modelled room: 33 HA + 66 ESPHome, restarts every ~3 min each
python3 mcast_sim.py sim --ha 33 --esp 66

# Everyone boots at once
python3 mcast_sim.py sim --ha 33 --esp 66 --stagger 5
```

Compare the ramp step where ping degrades with the packets/s that `sim` produces. Then raise the AP minimum basic rate (e.g. to 12 Mbps) and repeat the ramp.

Useful options (`python3 mcast_sim.py <mode> --help` lists all):

- `--iface-ip`: local IPv4 on the network under test. The default is the address the OS would use toward 224.0.0.251.
- `--aps-same-channel N`: multiplies the airtime estimate for N APs that each re-broadcast the VLAN. It sends nothing extra.
- `--ssids-per-radio N`: prints beacon airtime for N SSIDs per radio.
- `--real-names`: uses `_esphomelib._tcp` / `_home-assistant._tcp` instead of `_simtest-*` names, so real HA and ESPHome devices react. Real HA instances will then list the fake `simtest-esp-*` devices as discovered. Use only on a test network.

## Limits

- Sending from a Wi-Fi client adds one uplink transmission per frame. A wired sender isolates the AP's re-broadcast cost.
- Not modelled: association and DHCP load of hundreds of real clients, ESP uplink transmissions and retries, VirtualBox bridged-MAC behaviour, IPv6 RS/MLD.
- The HA model covers zeroconf and SSDP from `default_config`. Other integrations and add-ons, such as the ESPHome dashboard's online checks, add more.

Run it only on a network you operate.

## License

MIT
