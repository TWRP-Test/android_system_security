// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module holds global state of Keystore such as the thread local
//! database connections and connections to services that Keystore needs
//! to talk to.

use crate::async_task::AsyncTask;
use crate::gc::Gc;
use crate::km_compat::{BacklevelKeyMintWrapper, KeyMintV1};
use crate::ks_err;
use crate::legacy_blob::LegacyBlobLoader;
use crate::legacy_importer::LegacyImporter;
use crate::super_key::SuperKeyManager;
use crate::utils::{retry_get_interface, watchdog as wd};
use crate::{
    database::KeystoreDB,
    database::Uuid,
    error::{map_binder_status, map_binder_status_code, Error, ErrorCode},
};
use crate::{enforcements::Enforcements, error::map_km_error};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    IKeyMintDevice::BpKeyMintDevice, IKeyMintDevice::IKeyMintDevice,
    KeyMintHardwareInfo::KeyMintHardwareInfo, SecurityLevel::SecurityLevel,
};
use android_hardware_security_keymint::binder::{StatusCode, Strong};
use android_hardware_security_rkp::aidl::android::hardware::security::keymint::{
    IRemotelyProvisionedComponent::BpRemotelyProvisionedComponent,
    IRemotelyProvisionedComponent::IRemotelyProvisionedComponent,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    ISecureClock::BpSecureClock, ISecureClock::ISecureClock,
};
use android_security_compat::aidl::android::security::compat::IKeystoreCompatService::IKeystoreCompatService;
use anyhow::{Context, Result};
use binder::FromIBinder;
use binder::{get_declared_instances, is_declared};
use rustutils::system_properties::PropertyWatcher;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, LazyLock, Mutex, RwLock,
};
use std::{cell::RefCell, sync::Once};
use std::{collections::HashMap, path::Path, path::PathBuf};

static DB_INIT: Once = Once::new();

/// Open a connection to the Keystore 2.0 database. This is called during the initialization of
/// the thread local DB field. It should never be called directly. The first time this is called
/// we also call KeystoreDB::cleanup_leftovers to restore the key lifecycle invariant. See the
/// documentation of cleanup_leftovers for more details. The function also constructs a blob
/// garbage collector. The initializing closure constructs another database connection without
/// a gc. Although one GC is created for each thread local database connection, this closure
/// is run only once, as long as the ASYNC_TASK instance is the same. So only one additional
/// database connection is created for the garbage collector worker.
pub fn create_thread_local_db() -> KeystoreDB {
    let db_path = DB_PATH.read().expect("Could not get the database directory");

    let result = KeystoreDB::new(&db_path, Some(GC.clone()));
    let mut db = match result {
        Ok(db) => db,
        Err(e) => {
            log::error!("Failed to open Keystore database at {db_path:?}: {e:?}");
            log::error!("Has /data been mounted correctly?");
            panic!("Failed to open database for Keystore, cannot continue: {e:?}")
        }
    };

    DB_INIT.call_once(|| {
        log::info!("Touching Keystore 2.0 database for this first time since boot.");
        log::info!("Calling cleanup leftovers.");
        let n = db.cleanup_leftovers().expect("Failed to cleanup database on startup");
        if n != 0 {
            log::info!(
                "Cleaned up {n} failed entries, indicating keystore crash on key generation"
            );
        }
    });
    db
}

thread_local! {
    /// Database connections are not thread safe, but connecting to the
    /// same database multiple times is safe as long as each connection is
    /// used by only one thread. So we store one database connection per
    /// thread in this thread local key.
    pub static DB: RefCell<KeystoreDB> = RefCell::new(create_thread_local_db());
}

struct DevicesMap<T: FromIBinder + ?Sized> {
    devices_by_uuid: HashMap<Uuid, (Strong<T>, KeyMintHardwareInfo)>,
    uuid_by_sec_level: HashMap<SecurityLevel, Uuid>,
}

impl<T: FromIBinder + ?Sized> DevicesMap<T> {
    fn dev_by_sec_level(
        &self,
        sec_level: &SecurityLevel,
    ) -> Option<(Strong<T>, KeyMintHardwareInfo, Uuid)> {
        self.uuid_by_sec_level.get(sec_level).and_then(|uuid| self.dev_by_uuid(uuid))
    }

    fn dev_by_uuid(&self, uuid: &Uuid) -> Option<(Strong<T>, KeyMintHardwareInfo, Uuid)> {
        self.devices_by_uuid
            .get(uuid)
            .map(|(dev, hw_info)| ((*dev).clone(), (*hw_info).clone(), *uuid))
    }

    fn devices(&self) -> Vec<Strong<T>> {
        self.devices_by_uuid.values().map(|(dev, _)| dev.clone()).collect()
    }

    /// The requested security level and the security level of the actual implementation may
    /// differ. So we map the requested security level to the uuid of the implementation
    /// so that there cannot be any confusion as to which KeyMint instance is requested.
    fn insert(&mut self, sec_level: SecurityLevel, dev: Strong<T>, hw_info: KeyMintHardwareInfo) {
        // For now we use the reported security level of the KM instance as UUID.
        // TODO update this section once UUID was added to the KM hardware info.
        let uuid: Uuid = sec_level.into();
        self.devices_by_uuid.insert(uuid, (dev, hw_info));
        self.uuid_by_sec_level.insert(sec_level, uuid);
    }
}

impl<T: FromIBinder + ?Sized> Default for DevicesMap<T> {
    fn default() -> Self {
        Self {
            devices_by_uuid: HashMap::<Uuid, (Strong<T>, KeyMintHardwareInfo)>::new(),
            uuid_by_sec_level: Default::default(),
        }
    }
}

/// The path where keystore stores all its keys.
pub static DB_PATH: LazyLock<RwLock<PathBuf>> =
    LazyLock::new(|| RwLock::new(Path::new("/data/misc/keystore").to_path_buf()));
/// Runtime database of unwrapped super keys.
pub static SUPER_KEY: LazyLock<Arc<RwLock<SuperKeyManager>>> = LazyLock::new(Default::default);
/// Map of KeyMint devices.
static KEY_MINT_DEVICES: LazyLock<Mutex<DevicesMap<dyn IKeyMintDevice>>> =
    LazyLock::new(Default::default);
/// Timestamp service.
static TIME_STAMP_DEVICE: Mutex<Option<Strong<dyn ISecureClock>>> = Mutex::new(None);
/// A single on-demand worker thread that handles deferred tasks with two different
/// priorities.
pub static ASYNC_TASK: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);
/// Singleton for enforcements.
pub static ENFORCEMENTS: LazyLock<Enforcements> = LazyLock::new(Default::default);
/// LegacyBlobLoader is initialized and exists globally.
/// The same directory used by the database is used by the LegacyBlobLoader as well.
pub static LEGACY_BLOB_LOADER: LazyLock<Arc<LegacyBlobLoader>> = LazyLock::new(|| {
    Arc::new(LegacyBlobLoader::new(
        &DB_PATH.read().expect("Could not determine database path for legacy blob loader"),
    ))
});
/// Legacy migrator. Atomically migrates legacy blobs to the database.
pub static LEGACY_IMPORTER: LazyLock<Arc<LegacyImporter>> =
    LazyLock::new(|| Arc::new(LegacyImporter::new(Arc::new(Default::default()))));
/// Background thread which handles logging via statsd and logd
pub static LOGS_HANDLER: LazyLock<Arc<AsyncTask>> = LazyLock::new(Default::default);
/// DER-encoded module information returned by `getSupplementaryAttestationInfo(Tag.MODULE_HASH)`.
pub static ENCODED_MODULE_INFO: RwLock<Option<Vec<u8>>> = RwLock::new(None);

static GC: LazyLock<Arc<Gc>> = LazyLock::new(|| {
    Arc::new(Gc::new_init_with(ASYNC_TASK.clone(), || {
        (
            Box::new(|uuid, blob| {
                let km_dev = get_keymint_dev_by_uuid(uuid).map(|(dev, _)| dev)?;
                let _wp = wd::watch("invalidate key closure: calling IKeyMintDevice::deleteKey");
                map_km_error(km_dev.deleteKey(blob))
                    .context(ks_err!("Trying to invalidate key blob."))
            }),
            KeystoreDB::new(
                &DB_PATH.read().expect("Could not determine database path for GC"),
                None,
            )
            .expect("Failed to open database"),
            SUPER_KEY.clone(),
        )
    }))
});

/// Determine the service name for a KeyMint device of the given security level
/// gotten by binder service from the device and determining what services
/// are available.
fn keymint_service_name(security_level: &SecurityLevel) -> Result<Option<String>> {
    let keymint_descriptor: &str = <BpKeyMintDevice as IKeyMintDevice>::get_descriptor();
    let keymint_instances = get_declared_instances(keymint_descriptor).unwrap();

    let service_name = match *security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            if keymint_instances.iter().any(|instance| *instance == "default") {
                Some(format!("{}/default", keymint_descriptor))
            } else {
                None
            }
        }
        SecurityLevel::STRONGBOX => {
            if keymint_instances.iter().any(|instance| *instance == "strongbox") {
                Some(format!("{}/strongbox", keymint_descriptor))
            } else {
                None
            }
        }
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)).context(ks_err!(
                "Trying to find keymint for security level: {:?}",
                security_level
            ));
        }
    };

    Ok(service_name)
}

/// Make a new connection to a KeyMint device of the given security level.
/// If no native KeyMint device can be found this function also brings
/// up the compatibility service and attempts to connect to the legacy wrapper.
fn connect_keymint(
    security_level: &SecurityLevel,
) -> Result<(Strong<dyn IKeyMintDevice>, KeyMintHardwareInfo)> {
    // Show the keymint interface that is registered in the binder
    // service and use the security level to get the service name.
    let service_name = keymint_service_name(security_level)
        .context(ks_err!("Get service name from binder service"))?;

    let (keymint, hal_version) = if let Some(service_name) = service_name {
        let km: Strong<dyn IKeyMintDevice> =
            if SecurityLevel::TRUSTED_ENVIRONMENT == *security_level {
                map_binder_status_code(retry_get_interface(&service_name))
            } else {
                map_binder_status_code(binder::get_interface(&service_name))
            }
            .context(ks_err!("Trying to connect to genuine KeyMint service."))?;
        // Map the HAL version code for KeyMint to be <AIDL version> * 100, so
        // - V1 is 100
        // - V2 is 200
        // - V3 is 300
        // etc.
        let km_version = km.getInterfaceVersion()?;
        (km, Some(km_version * 100))
    } else {
        // This is a no-op if it was called before.
        keystore2_km_compat::add_keymint_device_service();

        let keystore_compat_service: Strong<dyn IKeystoreCompatService> =
            map_binder_status_code(binder::get_interface("android.security.compat"))
                .context(ks_err!("Trying to connect to compat service."))?;
        (
            map_binder_status(keystore_compat_service.getKeyMintDevice(*security_level))
                .map_err(|e| match e {
                    Error::BinderTransaction(StatusCode::NAME_NOT_FOUND) => {
                        Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)
                    }
                    e => e,
                })
                .context(ks_err!(
                    "Trying to get Legacy wrapper. Attempt to get keystore \
                    compat service for security level {:?}",
                    *security_level
                ))?,
            None,
        )
    };

    // If the KeyMint device is back-level, use a wrapper that intercepts and
    // emulates things that are not supported by the hardware.
    let keymint = match hal_version {
        Some(400) | Some(300) | Some(200) => {
            // KeyMint v2+: use as-is (we don't have any software emulation of v3 or v4-specific KeyMint features).
            log::info!(
                "KeyMint device is current version ({:?}) for security level: {:?}",
                hal_version,
                security_level
            );
            keymint
        }
        Some(100) => {
            // KeyMint v1: perform software emulation.
            log::info!(
                "Add emulation wrapper around {:?} device for security level: {:?}",
                hal_version,
                security_level
            );
            BacklevelKeyMintWrapper::wrap(KeyMintV1::new(*security_level), keymint)
                .context(ks_err!("Trying to create V1 compatibility wrapper."))?
        }
        None => {
            // Compatibility wrapper around a KeyMaster device: this roughly
            // behaves like KeyMint V1 (e.g. it includes AGREE_KEY support,
            // albeit in software.)
            log::info!(
                "Add emulation wrapper around Keymaster device for security level: {:?}",
                security_level
            );
            BacklevelKeyMintWrapper::wrap(KeyMintV1::new(*security_level), keymint)
                .context(ks_err!("Trying to create km_compat V1 compatibility wrapper ."))?
        }
        _ => {
            return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)).context(ks_err!(
                "unexpected hal_version {:?} for security level: {:?}",
                hal_version,
                security_level
            ));
        }
    };

    let wp = wd::watch("connect_keymint: calling IKeyMintDevice::getHardwareInfo()");
    let mut hw_info =
        map_km_error(keymint.getHardwareInfo()).context(ks_err!("Failed to get hardware info."))?;
    drop(wp);

    // The legacy wrapper sets hw_info.versionNumber to the underlying HAL version like so:
    // 10 * <major> + <minor>, e.g., KM 3.0 = 30. So 30, 40, and 41 are the only viable values.
    //
    // For KeyMint the returned versionNumber is implementation defined and thus completely
    // meaningless to Keystore 2.0.  So set the versionNumber field that is returned to
    // the rest of the code to be the <AIDL version> * 100, so KeyMint V1 is 100, KeyMint V2 is 200
    // and so on.
    //
    // This ensures that versionNumber value across KeyMaster and KeyMint is monotonically
    // increasing (and so comparisons like `versionNumber >= KEY_MINT_1` are valid).
    if let Some(hal_version) = hal_version {
        hw_info.versionNumber = hal_version;
    }

    Ok((keymint, hw_info))
}

/// Get a keymint device for the given security level either from our cache or
/// by making a new connection. Returns the device, the hardware info and the uuid.
/// TODO the latter can be removed when the uuid is part of the hardware info.
pub fn get_keymint_device(
    security_level: &SecurityLevel,
) -> Result<(Strong<dyn IKeyMintDevice>, KeyMintHardwareInfo, Uuid)> {
    let mut devices_map = KEY_MINT_DEVICES.lock().unwrap();
    if let Some((dev, hw_info, uuid)) = devices_map.dev_by_sec_level(security_level) {
        Ok((dev, hw_info, uuid))
    } else {
        let (dev, hw_info) =
            connect_keymint(security_level).context(ks_err!("Cannot connect to Keymint"))?;
        devices_map.insert(*security_level, dev, hw_info);
        // Unwrap must succeed because we just inserted it.
        Ok(devices_map.dev_by_sec_level(security_level).unwrap())
    }
}

/// Get a keymint device for the given uuid. This will only access the cache, but will not
/// attempt to establish a new connection. It is assumed that the cache is already populated
/// when this is called. This is a fair assumption, because service.rs iterates through all
/// security levels when it gets instantiated.
pub fn get_keymint_dev_by_uuid(
    uuid: &Uuid,
) -> Result<(Strong<dyn IKeyMintDevice>, KeyMintHardwareInfo)> {
    let devices_map = KEY_MINT_DEVICES.lock().unwrap();
    if let Some((dev, hw_info, _)) = devices_map.dev_by_uuid(uuid) {
        Ok((dev, hw_info))
    } else {
        Err(Error::sys()).context(ks_err!("No KeyMint instance found."))
    }
}

/// Return all known keymint devices.
pub fn get_keymint_devices() -> Vec<Strong<dyn IKeyMintDevice>> {
    KEY_MINT_DEVICES.lock().unwrap().devices()
}

/// Make a new connection to a secure clock service.
/// If no native SecureClock device can be found brings up the compatibility service and attempts
/// to connect to the legacy wrapper.
fn connect_secureclock() -> Result<Strong<dyn ISecureClock>> {
    let secure_clock_descriptor: &str = <BpSecureClock as ISecureClock>::get_descriptor();
    let secureclock_instances = get_declared_instances(secure_clock_descriptor).unwrap();

    let secure_clock_available =
        secureclock_instances.iter().any(|instance| *instance == "default");

    let default_time_stamp_service_name = format!("{}/default", secure_clock_descriptor);

    let secureclock = if secure_clock_available {
        map_binder_status_code(binder::get_interface(&default_time_stamp_service_name))
            .context(ks_err!("Trying to connect to genuine secure clock service."))
    } else {
        // This is a no-op if it was called before.
        keystore2_km_compat::add_keymint_device_service();

        let keystore_compat_service: Strong<dyn IKeystoreCompatService> =
            map_binder_status_code(binder::get_interface("android.security.compat"))
                .context(ks_err!("Trying to connect to compat service."))?;

        // Legacy secure clock services were only implemented by TEE.
        map_binder_status(keystore_compat_service.getSecureClock())
            .map_err(|e| match e {
                Error::BinderTransaction(StatusCode::NAME_NOT_FOUND) => {
                    Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)
                }
                e => e,
            })
            .context(ks_err!("Failed attempt to get legacy secure clock."))
    }?;

    Ok(secureclock)
}

/// Get the timestamp service that verifies auth token timeliness towards security levels with
/// different clocks.
pub fn get_timestamp_service() -> Result<Strong<dyn ISecureClock>> {
    let mut ts_device = TIME_STAMP_DEVICE.lock().unwrap();
    if let Some(dev) = &*ts_device {
        Ok(dev.clone())
    } else {
        let dev = connect_secureclock().context(ks_err!())?;
        *ts_device = Some(dev.clone());
        Ok(dev)
    }
}

/// Get the service name of a remotely provisioned component corresponding to given security level.
pub fn get_remotely_provisioned_component_name(security_level: &SecurityLevel) -> Result<String> {
    let remote_prov_descriptor: &str =
        <BpRemotelyProvisionedComponent as IRemotelyProvisionedComponent>::get_descriptor();

    match *security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            let instance = format!("{}/default", remote_prov_descriptor);
            if is_declared(&instance)? {
                Some(instance)
            } else {
                None
            }
        }
        SecurityLevel::STRONGBOX => {
            let instance = format!("{}/strongbox", remote_prov_descriptor);
            if is_declared(&instance)? {
                Some(instance)
            } else {
                None
            }
        }
        _ => None,
    }
    .ok_or(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
    .context(ks_err!("Failed to get rpc for sec level {:?}", *security_level))
}

/// Whether boot is complete.
static BOOT_COMPLETED: AtomicBool = AtomicBool::new(false);

/// Indicate whether boot is complete.
///
/// This in turn indicates whether it is safe to make permanent changes to state.
pub fn boot_completed() -> bool {
    BOOT_COMPLETED.load(Ordering::Acquire)
}

/// Monitor the system property for boot complete.  This blocks and so needs to be run in a separate
/// thread.
pub fn await_boot_completed() {
    // Use a fairly long watchdog timeout of 5 minutes here. This blocks until the device
    // boots, which on a very slow device (e.g., emulator for a non-native architecture) can
    // take minutes. Blocking here would be unexpected only if it never finishes.
    let _wp = wd::watch_millis("await_boot_completed", 300_000);
    log::info!("monitoring for sys.boot_completed=1");
    while let Err(e) = watch_for_boot_completed() {
        log::error!("failed to watch for boot_completed: {e:?}");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    BOOT_COMPLETED.store(true, Ordering::Release);
    log::info!("wait_for_boot_completed done, triggering GC");

    // Garbage collection may have been skipped until now, so trigger a check.
    GC.notify_gc();
}

fn watch_for_boot_completed() -> Result<()> {
    let mut w = PropertyWatcher::new("sys.boot_completed")
        .context(ks_err!("PropertyWatcher::new failed"))?;
    w.wait_for_value("1", None).context(ks_err!("Failed to wait for sys.boot_completed"))?;
    Ok(())
}
