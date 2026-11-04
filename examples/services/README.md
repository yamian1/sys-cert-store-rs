# Certificate maintenance service examples

Both services run one maintenance cycle immediately and then reload their
configuration before waiting for the next cycle. The only setting is:

```text
interval_minutes=30
```

Missing configuration files use the 30-minute default. Invalid settings stop
the service instead of silently changing its schedule.

## Linux .NET CRL-cache service

Build and install:

```sh
cargo build --release --example linux_crl_cache_service
sudo install -m 0755 target/release/examples/linux_crl_cache_service \
    /usr/local/bin/linux_crl_cache_service
sudo install -D -m 0644 examples/services/linux-crl-cache-service.conf \
    /etc/sys-cert-store/linux-crl-cache-service.conf
sudo install -m 0644 examples/services/linux-crl-cache-service.service \
    /etc/systemd/system/linux-crl-cache-service.service
sudo systemctl daemon-reload
sudo systemctl enable --now linux-crl-cache-service.service
```

The service must run as root to discover CoreCLR processes owned by other
accounts and write their .NET CRL caches. Logs are written to the systemd
journal. Test a single cycle with:

```sh
sudo target/release/examples/linux_crl_cache_service --once \
    --config examples/services/linux-crl-cache-service.conf
```

## Windows AIA service

Build from an elevated developer shell:

```powershell
cargo build --release --example windows_aia_service
```

Copy `examples\services\windows-aia-service.conf` to:

```text
%ProgramData%\sys-cert-store\windows-aia-service.conf
```

Install the executable as a LocalSystem automatic service:

```powershell
$binary = (Resolve-Path .\target\release\examples\windows_aia_service.exe).Path
sc.exe create SysCertStoreAiaService binPath= "`"$binary`"" start= auto obj= LocalSystem
sc.exe description SysCertStoreAiaService "Populate LocalMachine CA from certificate AIA extensions"
sc.exe start SysCertStoreAiaService
```

The service log is written to:

```text
%ProgramData%\sys-cert-store\windows-aia-service.log
```

Test a single cycle without installing the service:

```powershell
.\target\release\examples\windows_aia_service.exe --once `
    --config .\examples\services\windows-aia-service.conf
```

Remove the service with:

```powershell
sc.exe stop SysCertStoreAiaService
sc.exe delete SysCertStoreAiaService
```
