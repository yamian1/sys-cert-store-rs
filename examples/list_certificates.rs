use sys_cert_store::safe::CertificateStore;

fn main() {
    let result = CertificateStore::open_system("ROOT")
        .and_then(|store| store.certificates())
        .map(|certificates| certificates.len());
    match result {
        Ok(count) => println!("{count} certificates"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
