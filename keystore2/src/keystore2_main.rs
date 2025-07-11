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

//! This crate implements the Keystore 2.0 service entry point.

use keystore2::entropy;
use keystore2::globals::ENFORCEMENTS;
use keystore2::maintenance::Maintenance;
use keystore2::metrics::Metrics;
use keystore2::metrics_store;
use keystore2::service::KeystoreService;
use keystore2::{apc::ApcManager, shared_secret_negotiation};
use keystore2::{authorization::AuthorizationManager, id_rotation::IdRotationState};
use legacykeystore::LegacyKeystore;
use log::{error, info};
use rusqlite::trace as sqlite_trace;
use std::{os::raw::c_int, panic, path::Path, sync::mpsc::channel};

static KS2_SERVICE_NAME: &str = "android.system.keystore2.IKeystoreService/default";
static APC_SERVICE_NAME: &str = "android.security.apc";
static AUTHORIZATION_SERVICE_NAME: &str = "android.security.authorization";
static METRICS_SERVICE_NAME: &str = "android.security.metrics";
static USER_MANAGER_SERVICE_NAME: &str = "android.security.maintenance";
static LEGACY_KEYSTORE_SERVICE_NAME: &str = "android.security.legacykeystore";

/// Keystore 2.0 takes one argument which is a path indicating its designated working directory.
fn main() {
    // Initialize android logging.
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2")
            .with_max_level(log::LevelFilter::Debug)
            .with_log_buffer(android_logger::LogId::System)
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{}:{} - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                )
            }),
    );
    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    // Saying hi.
    info!("Keystore2 is starting.");

    let mut args = std::env::args();
    args.next().expect("That's odd. How is there not even a first argument?");

    // This must happen early before any other sqlite operations.
    log::info!("Setting up sqlite logging for keystore2");
    fn sqlite_log_handler(err: c_int, message: &str) {
        log::error!("[SQLITE3] {}: {}", err, message);
    }
    // SAFETY: There are no other threads yet, `sqlite_log_handler` is threadsafe, and it doesn't
    // invoke any SQLite calls.
    unsafe { sqlite_trace::config_log(Some(sqlite_log_handler)) }
        .expect("Error setting sqlite log callback.");

    // Write/update keystore.crash_count system property.
    metrics_store::update_keystore_crash_sysprop();

    // Send KeyMint module information for attestations.
    // Note that the information should be sent before code from modules starts running.
    // (This is guaranteed by waiting for `keystore.module_hash.sent` == true during device boot.)
    Maintenance::check_send_module_info();

    // Keystore 2.0 cannot change to the database directory (typically /data/misc/keystore) on
    // startup as Keystore 1.0 did because Keystore 2.0 is intended to run much earlier than
    // Keystore 1.0. Instead we set a global variable to the database path.
    // For the ground truth check the service startup rule for init (typically in keystore2.rc).
    let id_rotation_state = if let Some(dir) = args.next() {
        let db_path = Path::new(&dir);
        *keystore2::globals::DB_PATH.write().expect("Could not lock DB_PATH.") =
            db_path.to_path_buf();
        IdRotationState::new(db_path)
    } else {
        panic!("Must specify a database directory.");
    };

    let (confirmation_token_sender, confirmation_token_receiver) = channel();

    ENFORCEMENTS.install_confirmation_token_receiver(confirmation_token_receiver);

    std::thread::spawn(keystore2::globals::await_boot_completed);
    entropy::register_feeder();
    shared_secret_negotiation::perform_shared_secret_negotiation();

    info!("Starting thread pool now.");
    binder::ProcessState::start_thread_pool();

    let ks_service = KeystoreService::new_native_binder(id_rotation_state).unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });
    binder::add_service(KS2_SERVICE_NAME, ks_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", KS2_SERVICE_NAME, e);
    });

    let apc_service =
        ApcManager::new_native_binder(confirmation_token_sender).unwrap_or_else(|e| {
            panic!("Failed to create service {} because of {:?}.", APC_SERVICE_NAME, e);
        });
    binder::add_service(APC_SERVICE_NAME, apc_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", APC_SERVICE_NAME, e);
    });

    let authorization_service = AuthorizationManager::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", AUTHORIZATION_SERVICE_NAME, e);
    });
    binder::add_service(AUTHORIZATION_SERVICE_NAME, authorization_service.as_binder())
        .unwrap_or_else(|e| {
            panic!("Failed to register service {} because of {:?}.", AUTHORIZATION_SERVICE_NAME, e);
        });

    let (delete_listener, legacykeystore) = LegacyKeystore::new_native_binder(
        &keystore2::globals::DB_PATH.read().expect("Could not get DB_PATH."),
    );

    let maintenance_service = Maintenance::new_native_binder(delete_listener).unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", USER_MANAGER_SERVICE_NAME, e);
    });
    binder::add_service(USER_MANAGER_SERVICE_NAME, maintenance_service.as_binder()).unwrap_or_else(
        |e| {
            panic!("Failed to register service {} because of {:?}.", USER_MANAGER_SERVICE_NAME, e);
        },
    );

    let metrics_service = Metrics::new_native_binder().unwrap_or_else(|e| {
        panic!("Failed to create service {} because of {:?}.", METRICS_SERVICE_NAME, e);
    });
    binder::add_service(METRICS_SERVICE_NAME, metrics_service.as_binder()).unwrap_or_else(|e| {
        panic!("Failed to register service {} because of {:?}.", METRICS_SERVICE_NAME, e);
    });

    binder::add_service(LEGACY_KEYSTORE_SERVICE_NAME, legacykeystore.as_binder()).unwrap_or_else(
        |e| {
            panic!(
                "Failed to register service {} because of {:?}.",
                LEGACY_KEYSTORE_SERVICE_NAME, e
            );
        },
    );

    info!("Successfully registered Keystore 2.0 service.");

    info!("Joining thread pool now.");
    binder::ProcessState::join_thread_pool();
}
