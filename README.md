# Ginit: GeminiOS Init System & Core Utilities

Ginit is the core initialization system for GeminiOS. It handles process supervision, service management (via `.gservice` files), user authentication, and TTY management.

## Components

- **ginit**: The system init (PID 1). Manages mounting, hardware initialization, and process supervision.
- **login**: Standalone login manager. Handles user authentication and session setup.
- **getty**: TTY manager. Opens TTY devices and launches the login program.
- **libgemcore.a**: Static library containing shared logic for networking, signals, and user management.

## Directory Structure

- `src/`: Source code for all components.
- `services/`: Default system service configurations (`.gservice`).
- `lib/`: Compiled static libraries.
- `bin/`: Compiled executable binaries.

## Building Standalone

To build Ginit manually on a Linux system:

```bash
cd ginit
make
```

To install to a specific root directory (e.g., for OS distribution):

```bash
make install DESTDIR=/path/to/your/rootfs
```

### Dependencies

- A C++17 compliant compiler (g++ recommended).
- OpenSSL (libssl and libcrypto).
- zlib.
- zstd.

## Service Management

Ginit uses a custom service format. Services are stored in:
- System: `/etc/ginit/services/system/`
- User: `/etc/ginit/services/user/`

Example `.gservice` file:
```
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

## Integration with GeminiOS

Within the GeminiOS build system, Ginit is automatically built and installed by the `geminios_core` port.
To force a rebuild within the OS:
```bash
python3 builder.py geminios_core --force
```
