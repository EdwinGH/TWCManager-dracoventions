# TWCManager
 
A personal fork of [TWCManager](https://github.com/cdragon/TWCManager) by Chris
Dragon (Dracoventions), which talks to Tesla Wall Connectors over RS-485 by
pretending to be the Master TWC. All the protocol reverse engineering is his;
this fork only adapts the script to my own setup and fixes what broke along the
way.
 
Not a general-purpose release. It is public because the fixes may be useful to
someone with the same hardware, not because it is configurable enough for a
different one. **Use at your own risk** — see the warning in the script header.
 
## My setup
 
- Raspberry Pi 3, Raspberry Pi OS Buster, Python 3.7, accessible via intra and internet
- Two Tesla Wall Connectors Gen2 on one RS-485 bus, sharing one 16A three-phase
  group (230V, 3 phases)
- A USB RS-485 adapter on `/dev/ttyUSB0`
- MySQL on a separate server for logging
- A PHP page for the live view
## What differs from upstream
 
- **Two chargers actually work.** VINs are read per TWC and both are reported to
  the web interface and the database. Upstream effectively assumed one car.
- **Configuration is split in two files** instead of one `TWCManagerSettings.txt`:
  - `TWCManager_config.json` — everything you set by hand. JSON5, so the
    explanation of each parameter sits next to it as a comment. Never written to.
  - `TWCManager_status.ini` — what the script changes by itself
    (`nonScheduledAmpsMax` from the web page, `approvedVINs` from the
    approve/revoke links, `kWhDelivered`). Overrides the config file, so the
    config file holds the value you *start from*.
- **VIN approval that survives real life.** A car that is unplugged stops being
  reported, a car that is merely asleep is not cut off, and a car that was just
  plugged in gets a grace period to answer before `blockUnknownVINs` applies.
- **Quiet by default.** The default level writes about one line per 10 seconds,
  which an SD card can live with.
- **Survives a MySQL outage** instead of looping on reconnect errors until the
  chargers drop off the bus.
- Two spaces per indent level throughout, and `kWh` estimated from configurable
  volts and phase count rather than hard-coded US single-phase values.
See the `Release` entries at the top of `TWCManager-edwin.py` for the full list.
 
## Install
 
```sh
git clone https://github.com/EdwinGH/TWCManager-dracoventions.git
cd TWCManager-dracoventions
```
 
Then edit `TWCManager_config.json`. At minimum: the two `wiringMaxAmps*` values,
your own VINs in `approvedVINs`, `webIPCDir`, and the four `mysql_*` settings.
The defaults in the example file are deliberately too low to charge anything.
 
Requires `pyserial`, `sysv_ipc` and `mysql-connector-python`. JSON5 parsing uses
the `json5` package when it is installed and `twc_json5.py` otherwise, which
ships here and needs no package manager — Buster has neither `python3-json5`
nor `pip3`.
 
`TWCManager_status.ini` is created automatically on first change. There is an
example only in case you want to carry a `kWhDelivered` total over from an
older installation.
 
## Running
 
```sh
./TWCManager.py                  # debugLevel from the config file
./TWCManager.py -l info          # one line per 10 s
./TWCManager.py -l debug         # several lines per second
./TWCManager.py -c /path/to/other_config.json
```
 
`-l` takes `none`, `warning`, `info`, `debug` or `all` and overrides
`debugLevel`. As a service, set `Environment=PYTHONUNBUFFERED=1` in the unit
file or journald will show the output in bursts.
 
## Database
 
The script writes one row per TWC every 30 seconds into a `twc_data` table. The
shape the INSERT expects — adjust the types to taste:
 
```sql
CREATE TABLE twc_data (
  timestamp       DATETIME     NOT NULL,
  total_amps_max  FLOAT,
  twc_id          CHAR(4),
  amps_offered    FLOAT,
  current_amps    FLOAT,
  state           TINYINT,
  VIN_connected   CHAR(17),
  INDEX (timestamp)
);
```
 
It exits at startup if it cannot reach the database, so the `mysql_*` settings
have to be right even if you do not care about the logging.
 
## Web interface
 
Slightly changed from upstream: `index.php` and the script exchange messages over a
SysV IPC queue whose key is derived from the inode of `webIPCDir`. The PHP page's
`$twcScriptDir` must point at that same directory, and recreating the directory
silently breaks the link.
 
## Credits and licence
 
Protocol reverse engineering and the original TWCManager by Chris Dragon, with
logs and hints from the Teslamotorsclub.com users TheNoOne, IanAmber and twc.
Background reading: [the TMC
thread](https://teslamotorsclub.com/tmc/threads/new-wall-connector-load-sharing-protocol.72830).
 
Released under the [Unlicense](http://unlicense.org), like the original.
 
Bugs in the original belong [upstream](https://github.com/cdragon/TWCManager/issues);
anything I broke is mine.
 
