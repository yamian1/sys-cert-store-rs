#include <sys-cert-store/sys-cert-store.h>
#include <cstdio>

int main() {
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        std::fprintf(stderr, "Open failed (0x%x): %s\n", GetLastError(), SysCertGetLastErrorMessage());
        return 1;
    }
    unsigned count = 0;
    PCCERT_CONTEXT certificate = nullptr;
    while ((certificate = CertEnumCertificatesInStore(store, certificate))) ++count;
    if (GetLastError() != CRYPT_E_NOT_FOUND) {
        std::fprintf(stderr, "Enumeration failed (0x%x): %s\n", GetLastError(), SysCertGetLastErrorMessage());
        CertCloseStore(store, 0);
        return 1;
    }
    std::printf("%u certificates\n", count);
    return CertCloseStore(store, 0) ? 0 : 1;
}

