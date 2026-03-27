# Ginit

Ginit is the GeminiOS init system and a small set of companion utilities. The design goal is to keep PID 1 boring: mount the base runtime, supervise a few services, expose a tiny text control socket, and avoid burying policy in hidden state.

## Design Notes

- Boot policy is data, not magic. Vendor defaults live in `/usr/lib/ginit/boot-services.conf`.
- Local administrator overrides live in `/etc/ginit/boot-services.conf`.
- Persistent enablement is still explicit symlink-style state in `/etc/ginit/services/system/`.
- `ginit` does not rewrite boot defaults at startup anymore; PID 1 reads them and starts what they describe.
- Service logs are plain files in `/var/log/ginit/<service>.log`.
- Inspection should not depend on the daemon being reachable. `ginit show` and `ginit check` work from files.

## Components

- `ginit`: PID 1 plus the service-control CLI.
- `ginit-netcfg`: network configuration helper kept outside PID 1.
- `login`: standalone login manager.
- `getty`: simple TTY/login launcher.
- `libgemcore.a`: shared runtime code.

## Layout

- `src/`: source code.
- `services/`: shipped `.gservice` units.
- `boot-services.conf`: shipped boot preset.
- `bin/`: built executables.
- `lib/`: built static library.

## Build

```bash
cd ginit
make
make install DESTDIR=/path/to/rootfs
```

## Service Files

Shipped service definitions live in `/usr/lib/ginit/services/`. Persistent local enablement lives in `/etc/ginit/services/system/`.

Example:

```gservice
service "dbus" {
    meta {
        description = "D-Bus System Message Bus"
    }
    process {
        commands {
            start = "/usr/bin/dbus-daemon --system --nofork"
        }
    }
}
```

## Boot Presets

`/usr/lib/ginit/boot-services.conf` is the vendor default list. `/etc/ginit/boot-services.conf` is merged after it.

- A plain service name adds it to the boot preset.
- A line starting with `-` removes a vendor preset entry.
- `enable` and `disable` affect persistent local state, not the vendor preset file.

Example override:

```text
-network
sshd
```

## Administration

```bash
ginit status
ginit show dbus
ginit check
ginit enable sshd
ginit disable elogind
```

- `status` talks to the running daemon and shows runtime state.
- `show` prefers live runtime data, but falls back to file inspection.
- `check` validates service files, dependency references, and boot preset entries without needing PID 1.

## GeminiOS Build Integration

GeminiOS builds and installs Ginit through the `geminios_core` port.

```bash
python3 builder.py geminios_core --force
```
