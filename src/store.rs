use crate::cert::{Certificate, Context, Properties};
use crate::error::{ApiError, require};
use crate::ffi::*;
use crate::key::PrivateKey;
use crate::native::{NativeLayout, native_layout, read_native};
use parking_lot::Mutex;
use rand::RngCore;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

#[derive(Clone)]
pub struct Material {
    pub der: Vec<u8>,
    pub key: Option<Arc<PrivateKey>>,
}

pub struct Store {
    pub id: usize,
    pub db: Connection,
    pub readonly: bool,
    pub archived: bool,
    pub native: bool,
    pub layout: Option<NativeLayout>,
    pub location: DWORD,
    pub name: String,
    pub pending_path: Option<PathBuf>,
    pub public_material: bool,
    pub inherited: Vec<usize>,
    pub objects: Option<PathBuf>,
    pub memory: BTreeMap<i64, Material>,
    pub references: usize,
    pub contexts: usize,
}

unsafe impl Send for Store {}

#[derive(Clone)]
pub struct SystemPaths {
    pub user: Option<PathBuf>,
    pub machine: PathBuf,
    pub root: PathBuf,
}

impl Default for SystemPaths {
    fn default() -> Self {
        Self {
            user: None,
            machine: PathBuf::from("/var/lib/sys-cert-store"),
            root: PathBuf::from("/"),
        }
    }
}

pub struct State {
    pub stores: HashMap<usize, Store>,
    pub contexts: HashMap<usize, Box<Context>>,
    pub paths: SystemPaths,
    next_store: usize,
}

unsafe impl Send for State {}

impl Default for State {
    fn default() -> Self {
        Self {
            stores: HashMap::new(),
            contexts: HashMap::new(),
            paths: SystemPaths::default(),
            next_store: 0x10000,
        }
    }
}

pub static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

pub fn store_key(handle: HCERTSTORE) -> usize {
    handle as usize
}

pub fn store_handle(key: usize) -> HCERTSTORE {
    key as HCERTSTORE
}

impl State {
    pub fn store(&self, handle: HCERTSTORE) -> Result<&Store, ApiError> {
        self.stores.get(&store_key(handle)).ok_or_else(|| {
            ApiError::new(
                ERROR_INVALID_HANDLE,
                "Invalid or closed certificate store handle",
            )
        })
    }

    pub fn store_mut(&mut self, handle: HCERTSTORE) -> Result<&mut Store, ApiError> {
        self.stores.get_mut(&store_key(handle)).ok_or_else(|| {
            ApiError::new(
                ERROR_INVALID_HANDLE,
                "Invalid or closed certificate store handle",
            )
        })
    }

    pub fn context(&self, pointer: *const CERT_CONTEXT) -> Result<&Context, ApiError> {
        self.contexts
            .get(&(pointer as usize))
            .map(Box::as_ref)
            .ok_or_else(|| {
                ApiError::new(ERROR_INVALID_HANDLE, "Invalid or freed certificate context")
            })
    }

    pub fn context_mut(&mut self, pointer: *const CERT_CONTEXT) -> Result<&mut Context, ApiError> {
        self.contexts
            .get_mut(&(pointer as usize))
            .map(Box::as_mut)
            .ok_or_else(|| {
                ApiError::new(ERROR_INVALID_HANDLE, "Invalid or freed certificate context")
            })
    }

    pub fn publish_store(&mut self, mut store: Store) -> HCERTSTORE {
        self.next_store += 1;
        store.id = self.next_store;
        let handle = store_handle(store.id);
        self.stores.insert(store.id, store);
        handle
    }

    pub fn publish_context(
        &mut self,
        mut context: Box<Context>,
        store_id: Option<usize>,
        row: i64,
        view_id: Option<usize>,
    ) -> *const CERT_CONTEXT {
        context.store_id = store_id;
        context.view_id = view_id;
        context.row = row;
        context.public.hCertStore = view_id
            .or(store_id)
            .map(store_handle)
            .unwrap_or(std::ptr::null_mut());
        if let Some(id) = store_id
            && let Some(store) = self.stores.get_mut(&id)
        {
            store.contexts += 1;
        }
        if let Some(id) = view_id
            && let Some(store) = self.stores.get_mut(&id)
        {
            store.contexts += 1;
        }
        let pointer = context.public_ptr();
        self.contexts.insert(pointer as usize, context);
        pointer
    }

    pub fn release_context(&mut self, pointer: *const CERT_CONTEXT) -> Result<(), ApiError> {
        if pointer.is_null() {
            return Ok(());
        }
        let key = pointer as usize;
        let context = self.contexts.get_mut(&key).ok_or_else(|| {
            ApiError::new(ERROR_INVALID_HANDLE, "Invalid or freed certificate context")
        })?;
        context.references -= 1;
        if context.references == 0 {
            let context = self.contexts.remove(&key).unwrap();
            if let Some(id) = context.store_id
                && let Some(store) = self.stores.get_mut(&id)
            {
                store.contexts -= 1;
            }
            if let Some(id) = context.view_id
                && let Some(store) = self.stores.get_mut(&id)
            {
                store.contexts -= 1;
            }
        }
        Ok(())
    }
}

fn initialize_database(connection: &Connection) -> Result<(), ApiError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY AUTOINCREMENT,object TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS properties(cert INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
             property INTEGER NOT NULL,value BLOB NOT NULL,PRIMARY KEY(cert,property));
         CREATE TABLE IF NOT EXISTS store_properties(property INTEGER PRIMARY KEY,value BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS garbage(object TEXT PRIMARY KEY);
         PRAGMA application_id=1396921137;
         PRAGMA user_version=2;
         COMMIT;",
    )?;
    Ok(())
}

fn validate_database(connection: &Connection) -> Result<(), ApiError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    require(
        application == 1_396_921_137,
        ERROR_INVALID_DATA,
        "Not a sys-cert-store database",
    )?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    require(
        version == 2,
        ERROR_NOT_SUPPORTED,
        "Unsupported sys-cert-store schema version",
    )
}

fn memory_connection() -> Result<Connection, ApiError> {
    let connection = Connection::open_in_memory()?;
    initialize_database(&connection)?;
    validate_database(&connection)?;
    Ok(connection)
}

fn create_file(path: &Path, public: bool) -> Result<bool, ApiError> {
    let mode = if public { 0o644 } else { 0o600 };
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(file) => {
            if public {
                file.set_permissions(fs::Permissions::from_mode(mode))?;
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn open_database(path: &Path, flags: DWORD, public: bool) -> Result<Connection, ApiError> {
    require(
        path.is_absolute(),
        E_INVALIDARG,
        "SQLite store path must be absolute",
    )?;
    let readonly = flags & CERT_STORE_READONLY_FLAG != 0;
    let existing_only = flags & CERT_STORE_OPEN_EXISTING_FLAG != 0 || readonly;
    let create_only = flags & CERT_STORE_CREATE_NEW_FLAG != 0;
    require(
        !(existing_only && create_only),
        E_INVALIDARG,
        "Conflicting store open flags",
    )?;
    let mut created = false;
    if !existing_only {
        created = create_file(path, public)?;
        require(
            !create_only || created,
            CRYPT_E_EXISTS,
            "Store already exists",
        )?;
    }
    require(
        path.exists(),
        ERROR_FILE_NOT_FOUND,
        "SQLite store does not exist",
    )?;
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        ERROR_ACCESS_DENIED,
        "SQLite store must be a regular non-symlink file",
    )?;
    let open_flags = if readonly {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } | OpenFlags::SQLITE_OPEN_FULL_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, open_flags)?;
    if created {
        initialize_database(&connection)?;
    }
    validate_database(&connection)?;
    Ok(connection)
}

fn private_directory(path: &Path, public: bool) -> Result<(), ApiError> {
    let mode = if public { 0o755 } else { 0o700 };
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        ERROR_ACCESS_DENIED,
        "Unsafe object directory",
    )?;
    require(
        metadata.permissions().mode() & if public { 0o022 } else { 0o077 } == 0,
        ERROR_ACCESS_DENIED,
        "Object directory has unsafe permissions",
    )
}

fn persistent_store(store: &mut Store, path: &Path, flags: DWORD) -> Result<(), ApiError> {
    store.db = open_database(path, flags, store.public_material)?;
    let objects = PathBuf::from(format!("{}.objects", path.display()));
    if !store.readonly {
        if let Some(parent) = objects.parent() {
            fs::create_dir_all(parent)?;
        }
        private_directory(&objects, store.public_material)?;
    }
    store.objects = Some(objects);
    collect_garbage(store)
}

pub fn user_data_directory(paths: &SystemPaths) -> Result<PathBuf, ApiError> {
    if let Some(path) = &paths.user {
        return Ok(path.clone());
    }
    let uid = unsafe { libc::geteuid() };
    let mut result = std::ptr::null_mut();
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0i8; 16384];
    require(
        unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        } == 0
            && !result.is_null(),
        ERROR_GEN_FAILURE,
        "Cannot resolve the current user's home directory",
    )?;
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }.to_string_lossy();
    Ok(PathBuf::from(home.as_ref()).join(".local/share/sys-cert-store"))
}

pub fn store_name(mut name: String) -> Result<String, ApiError> {
    require(
        !name.is_empty() && name.len() <= 64,
        E_INVALIDARG,
        "Store name must contain 1 to 64 ASCII letters, digits, '-' or '_'",
    )?;
    name.make_ascii_uppercase();
    require(
        name.bytes()
            .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_'),
        E_INVALIDARG,
        "Invalid logical store name",
    )?;
    Ok(name)
}

fn standard_store(name: &str) -> bool {
    matches!(name, "ROOT" | "CA" | "MY")
}

fn empty_store() -> Result<Store, ApiError> {
    Ok(Store {
        id: 0,
        db: memory_connection()?,
        readonly: false,
        archived: false,
        native: false,
        layout: None,
        location: 0,
        name: String::new(),
        pending_path: None,
        public_material: false,
        inherited: Vec::new(),
        objects: None,
        memory: BTreeMap::new(),
        references: 1,
        contexts: 0,
    })
}

fn scoped_backing(store: &mut Store, directory: &Path, flags: DWORD) -> Result<(), ApiError> {
    let mut path = directory.join(format!("{}.db", store.name));
    if !path.exists() && directory.exists() {
        let mut matches = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink()
                || !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|v| v.to_str()) != Some("db")
            {
                continue;
            }
            if let Some(stem) = entry.path().file_stem().and_then(|value| value.to_str())
                && store_name(stem.to_owned())? == store.name
            {
                matches.push(entry.path());
            }
        }
        require(
            matches.len() <= 1,
            ERROR_INVALID_DATA,
            "Multiple metadata files map to the same system-store name",
        )?;
        if let Some(found) = matches.pop() {
            path = found;
        }
    }
    let exists = path.exists();
    require(
        !(standard_store(&store.name) && flags & CERT_STORE_CREATE_NEW_FLAG != 0),
        CRYPT_E_EXISTS,
        "Standard system store already exists",
    )?;
    if !exists && standard_store(&store.name) {
        store.pending_path = Some(path);
        return Ok(());
    }
    if !exists && flags & (CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG) == 0 {
        fs::create_dir_all(directory)?;
        fs::set_permissions(
            directory,
            fs::Permissions::from_mode(if store.public_material { 0o755 } else { 0o700 }),
        )?;
    }
    persistent_store(store, &path, flags)
}

fn load_native_store(store: &mut Store) -> Result<(), ApiError> {
    let layout = store.layout.as_ref().unwrap();
    let certificates = read_native(layout)?;
    store.db = memory_connection()?;
    store.memory.clear();
    let transaction = store.db.transaction()?;
    for der in certificates {
        Context::new(der.clone())?;
        transaction.execute("INSERT INTO certificates(object) VALUES('')", [])?;
        let row = transaction.last_insert_rowid();
        store.memory.insert(row, Material { der, key: None });
    }
    transaction.commit()?;
    Ok(())
}

fn machine_backing(paths: &SystemPaths, name: &str, flags: DWORD) -> Result<Store, ApiError> {
    let mut store = empty_store()?;
    store.name = name.to_owned();
    store.location = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    store.readonly = flags & CERT_STORE_READONLY_FLAG != 0;
    store.public_material = true;
    if name == "ROOT" {
        store.native = true;
        store.readonly = flags & SYS_CERT_STORE_NATIVE_WRITE_FLAG == 0;
        store.layout = Some(native_layout(Some(&paths.root))?);
        load_native_store(&mut store)?;
    } else {
        scoped_backing(&mut store, &paths.machine, flags)?;
    }
    Ok(store)
}

pub enum Provider {
    Memory,
    SystemA,
    SystemW,
    Sqlite,
    Native,
}

pub fn open_store(
    state: &mut State,
    provider: Provider,
    flags: DWORD,
    parameter_utf8: Option<String>,
    native_root: Option<PathBuf>,
) -> Result<HCERTSTORE, ApiError> {
    let allowed = CERT_STORE_READONLY_FLAG
        | CERT_STORE_OPEN_EXISTING_FLAG
        | CERT_STORE_CREATE_NEW_FLAG
        | CERT_STORE_ENUM_ARCHIVED_FLAG
        | 0xff0000
        | SYS_CERT_STORE_NATIVE_WRITE_FLAG;
    require(
        flags & !allowed == 0,
        ERROR_NOT_SUPPORTED,
        "Unsupported store open flags",
    )?;
    require(
        !(flags & CERT_STORE_CREATE_NEW_FLAG != 0 && flags & CERT_STORE_OPEN_EXISTING_FLAG != 0),
        E_INVALIDARG,
        "Conflicting store open flags",
    )?;
    let native_write = flags & SYS_CERT_STORE_NATIVE_WRITE_FLAG != 0;
    require(
        !(native_write && flags & CERT_STORE_READONLY_FLAG != 0),
        E_INVALIDARG,
        "Conflicting native-write and read-only flags",
    )?;
    let mut store = empty_store()?;
    store.readonly = flags & CERT_STORE_READONLY_FLAG != 0;
    store.archived = flags & CERT_STORE_ENUM_ARCHIVED_FLAG != 0;
    match provider {
        Provider::Memory => {
            require(
                flags
                    & (0xff0000 | SYS_CERT_STORE_NATIVE_WRITE_FLAG | CERT_STORE_OPEN_EXISTING_FLAG)
                    == 0,
                E_INVALIDARG,
                "Invalid memory store parameters",
            )?;
        }
        Provider::Sqlite => {
            require(
                flags & (0xff0000 | SYS_CERT_STORE_NATIVE_WRITE_FLAG) == 0,
                E_INVALIDARG,
                "SQLite provider requires an absolute UTF-8 path and no location/native flags",
            )?;
            let path = PathBuf::from(
                parameter_utf8.ok_or_else(|| ApiError::new(E_INVALIDARG, "Missing SQLite path"))?,
            );
            persistent_store(&mut store, &path, flags)?;
        }
        Provider::Native => {
            require(
                flags & (0xff0000 | CERT_STORE_CREATE_NEW_FLAG) == 0,
                E_INVALIDARG,
                "Invalid native store flags",
            )?;
            store.native = true;
            store.readonly = !native_write;
            store.layout = Some(native_layout(native_root.as_deref())?);
            load_native_store(&mut store)?;
        }
        Provider::SystemA | Provider::SystemW => {
            let name = store_name(
                parameter_utf8
                    .ok_or_else(|| ApiError::new(E_INVALIDARG, "Missing system store name"))?,
            )?;
            let location = flags & 0xff0000;
            require(
                location == CERT_SYSTEM_STORE_CURRENT_USER
                    || location == CERT_SYSTEM_STORE_LOCAL_MACHINE,
                ERROR_NOT_SUPPORTED,
                "Only current-user and local-machine locations are supported",
            )?;
            require(
                !(native_write && (location != CERT_SYSTEM_STORE_LOCAL_MACHINE || name != "ROOT")),
                E_INVALIDARG,
                "Native-write flag is only valid for computer ROOT",
            )?;
            if location == CERT_SYSTEM_STORE_LOCAL_MACHINE {
                store = machine_backing(&state.paths, &name, flags)?;
                store.archived = flags & CERT_STORE_ENUM_ARCHIVED_FLAG != 0;
            } else {
                store.name = name.clone();
                store.location = location;
                let directory = user_data_directory(&state.paths)?;
                scoped_backing(&mut store, &directory, flags)?;
                if matches!(name.as_str(), "ROOT" | "CA") {
                    let inherited = machine_backing(&state.paths, &name, CERT_STORE_READONLY_FLAG)?;
                    let inherited_handle = state.publish_store(inherited);
                    store.inherited.push(store_key(inherited_handle));
                }
            }
        }
    }
    Ok(state.publish_store(store))
}

pub fn materialize(store: &mut Store, create: bool) -> Result<(), ApiError> {
    let Some(path) = store.pending_path.clone() else {
        return Ok(());
    };
    if path.exists() {
        persistent_store(
            store,
            &path,
            if store.readonly {
                CERT_STORE_READONLY_FLAG
            } else {
                0
            },
        )?;
        store.pending_path = None;
    } else if create && !store.readonly {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(
                parent,
                fs::Permissions::from_mode(if store.public_material { 0o755 } else { 0o700 }),
            )?;
        }
        persistent_store(store, &path, 0)?;
        store.pending_path = None;
    }
    Ok(())
}

pub fn writable(store: &mut Store) -> Result<(), ApiError> {
    require(
        !store.readonly,
        ERROR_ACCESS_DENIED,
        "Store is read-only; native stores require explicit SYS_CERT_STORE_NATIVE_WRITE_FLAG",
    )?;
    materialize(store, true)
}

fn random_object_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn object_directory(store: &Store, id: &str) -> Result<PathBuf, ApiError> {
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase()),
        ERROR_INVALID_DATA,
        "Invalid object reference in metadata",
    )?;
    Ok(store.objects.as_ref().unwrap().join(id))
}

fn write_material(path: &Path, data: &[u8], public: bool) -> Result<(), ApiError> {
    let mode = if public { 0o644 } else { 0o600 };
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    output.write_all(data)?;
    output.sync_all()?;
    if public {
        output.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn create_object(store: &Store, source: &Context) -> Result<String, ApiError> {
    let id = random_object_id();
    let directory = object_directory(store, &id)?;
    fs::create_dir(&directory)?;
    fs::set_permissions(
        &directory,
        fs::Permissions::from_mode(if store.public_material { 0o755 } else { 0o700 }),
    )?;
    write_material(
        &directory.join("certificate.pem"),
        &source.certificate.to_pem(),
        store.public_material,
    )?;
    if let Some(key) = &source.private_key {
        require(
            key.matches(&source.certificate)?,
            ERROR_INVALID_DATA,
            "Private key does not match certificate",
        )?;
        let key_directory = if store.public_material {
            let path = directory.join("keys");
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            path
        } else {
            directory.clone()
        };
        write_material(&key_directory.join("private-key.pem"), &key.to_pem(), false)?;
    }
    Ok(id)
}

pub fn load_context(store: &Store, row: i64) -> Result<Box<Context>, ApiError> {
    if store.objects.is_none() {
        let material = store
            .memory
            .get(&row)
            .ok_or_else(|| ApiError::new(ERROR_INVALID_DATA, "Missing memory-store certificate"))?;
        let mut context = Context::new(material.der.clone())?;
        context.private_key = material.key.clone();
        return Ok(context);
    }
    let object: Option<String> = store
        .db
        .query_row(
            "SELECT object FROM certificates WHERE id=?",
            [row],
            |record| record.get(0),
        )
        .optional()?;
    let object =
        object.ok_or_else(|| ApiError::new(CRYPT_E_NOT_FOUND, "Certificate object was removed"))?;
    let directory = object_directory(store, &object)?;
    let metadata = fs::symlink_metadata(&directory)?;
    require(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        ERROR_ACCESS_DENIED,
        "Unsafe certificate object directory",
    )?;
    let pem = fs::read(directory.join("certificate.pem"))?;
    let certificate = Certificate::from_pem(&pem)?;
    let mut context = Context::new(certificate.to_der())?;
    context.object_path = Some(directory.clone());
    let protected = directory.join("keys/private-key.pem");
    let local = directory.join("private-key.pem");
    if protected.exists() {
        context.key_path = Some(protected);
    } else if local.exists() {
        context.key_path = Some(local);
    }
    Ok(context)
}

pub fn load_private_key(context: &mut Context) -> Result<(), ApiError> {
    if context.private_key.is_some() || context.key_path.is_none() {
        return Ok(());
    }
    let pem = fs::read(context.key_path.as_ref().unwrap())?;
    let key = PrivateKey::from_pem(&pem)?;
    require(
        key.matches(&context.certificate)?,
        ERROR_INVALID_DATA,
        "Invalid or mismatched PKCS#8 private-key object",
    )?;
    context.private_key = Some(Arc::new(key));
    Ok(())
}

pub fn read_properties(store: &Store, row: i64) -> Result<Properties, ApiError> {
    let mut statement = store
        .db
        .prepare("SELECT property,value FROM properties WHERE cert=? ORDER BY property")?;
    let values = statement.query_map([row], |record| {
        Ok((record.get::<_, DWORD>(0)?, record.get::<_, Vec<u8>>(1)?))
    })?;
    let mut result = Properties::new();
    for value in values {
        let (id, data) = value?;
        result.insert(id, data);
    }
    Ok(result)
}

pub fn row_exists(store: &Store, row: i64) -> Result<bool, ApiError> {
    Ok(store
        .db
        .query_row("SELECT 1 FROM certificates WHERE id=?", [row], |_| Ok(()))
        .optional()?
        .is_some())
}

pub fn insert_material(store: &mut Store, source: &Context) -> Result<i64, ApiError> {
    let object = if store.objects.is_some() {
        create_object(store, source)?
    } else {
        String::new()
    };
    store
        .db
        .execute("INSERT INTO certificates(object) VALUES(?)", [&object])?;
    let row = store.db.last_insert_rowid();
    if store.objects.is_none() {
        store.memory.insert(
            row,
            Material {
                der: source.der.clone(),
                key: source.private_key.clone(),
            },
        );
    }
    Ok(row)
}

pub fn retire_row(store: &mut Store, row: i64) -> Result<(), ApiError> {
    if store.objects.is_some() {
        store.db.execute(
            "INSERT OR IGNORE INTO garbage SELECT object FROM certificates WHERE id=?",
            [row],
        )?;
    }
    store
        .db
        .execute("DELETE FROM certificates WHERE id=?", [row])?;
    store.memory.remove(&row);
    Ok(())
}

pub fn collect_garbage(store: &mut Store) -> Result<(), ApiError> {
    if store.objects.is_none() || store.readonly {
        return Ok(());
    }
    let mut statement = store.db.prepare("SELECT object FROM garbage")?;
    let objects = statement
        .query_map([], |record| record.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for object in objects {
        let directory = object_directory(store, &object)?;
        if directory.exists() {
            fs::remove_dir_all(&directory)?;
        }
        store
            .db
            .execute("DELETE FROM garbage WHERE object=?", [&object])?;
    }
    Ok(())
}

pub fn write_properties(store: &Store, row: i64, properties: &Properties) -> Result<(), ApiError> {
    for (id, value) in properties {
        store.db.execute(
            "INSERT OR REPLACE INTO properties(cert,property,value) VALUES(?,?,?)",
            params![row, id, value],
        )?;
    }
    Ok(())
}

pub fn resync_native(store: &mut Store) -> Result<(), ApiError> {
    load_native_store(store)
}
