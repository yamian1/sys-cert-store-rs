use sys_cert_store::cert::Certificate;

fn main() {
    let certificate = Certificate::from_pem(include_bytes!(
        "../../../third_party/openssl/test/certs/root-ml-dsa-44-cert.pem"
    ))
    .expect("parse ML-DSA certificate");
    assert!(
        certificate.self_signed().expect("verify ML-DSA signature"),
        "ML-DSA root must be self-signed"
    );
}
