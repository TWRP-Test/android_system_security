// Copyright 2021, The Android Open Source Project
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

//! Provide the [`KeyMintDevice`] wrapper for operating directly on a KeyMint device.

use crate::{
    database::{
        BlobInfo, BlobMetaData, BlobMetaEntry, CertificateInfo, DateTime, KeyEntry,
        KeyEntryLoadBits, KeyIdGuard, KeyMetaData, KeyMetaEntry, KeyType, KeystoreDB,
        Uuid,
    },
    error::{map_km_error, Error, ErrorCode},
    globals::get_keymint_device,
    ks_err,
    super_key::KeyBlob,
    utils::{key_characteristics_to_internal, watchdog as wd, AID_KEYSTORE},
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, IKeyMintDevice::IKeyMintDevice,
    IKeyMintOperation::IKeyMintOperation, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use anyhow::{Context, Result};
use binder::Strong;

/// Wrapper for operating directly on a KeyMint device.
/// These methods often mirror methods in [`crate::security_level`]. However
/// the functions in [`crate::security_level`] make assumptions that hold, and has side effects
/// that make sense, only if called by an external client through binder.
/// In addition we are trying to maintain a separation between interface services
/// so that the architecture is compatible with a future move to multiple thread pools.
/// So the simplest approach today is to write new implementations of them for internal use.
/// Because these methods run very early, we don't even try to cooperate with
/// the operation slot database; we assume there will be plenty of slots.
pub struct KeyMintDevice {
    km_dev: Strong<dyn IKeyMintDevice>,
    km_uuid: Uuid,
    version: i32,
    security_level: SecurityLevel,
}

impl KeyMintDevice {
    /// Version number of KeyMasterDevice@V4_0
    pub const KEY_MASTER_V4_0: i32 = 40;
    /// Version number of KeyMasterDevice@V4_1
    pub const KEY_MASTER_V4_1: i32 = 41;
    /// Version number of KeyMintDevice@V1
    pub const KEY_MINT_V1: i32 = 100;
    /// Version number of KeyMintDevice@V2
    pub const KEY_MINT_V2: i32 = 200;
    /// Version number of KeyMintDevice@V3
    pub const KEY_MINT_V3: i32 = 300;

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`]
    pub fn get(security_level: SecurityLevel) -> Result<KeyMintDevice> {
        let (km_dev, hw_info, km_uuid) =
            get_keymint_device(&security_level).context(ks_err!("get_keymint_device failed"))?;

        Ok(KeyMintDevice {
            km_dev,
            km_uuid,
            version: hw_info.versionNumber,
            security_level: hw_info.securityLevel,
        })
    }

    /// Get a [`KeyMintDevice`] for the given [`SecurityLevel`], return
    /// [`None`] if the error `HARDWARE_TYPE_UNAVAILABLE` is returned
    pub fn get_or_none(security_level: SecurityLevel) -> Result<Option<KeyMintDevice>> {
        KeyMintDevice::get(security_level).map(Some).or_else(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                Some(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)) => Ok(None),
                _ => Err(e),
            }
        })
    }

    /// Returns the version of the underlying KeyMint/KeyMaster device.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns the self advertised security level of the KeyMint device.
    /// This may differ from the requested security level if the best security level
    /// on the device is Software.
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Create a KM key and store in the database.
    pub fn create_and_store_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        creator: F,
    ) -> Result<()>
    where
        F: FnOnce(&Strong<dyn IKeyMintDevice>) -> Result<KeyCreationResult, binder::Status>,
    {
        let creation_result =
            map_km_error(creator(&self.km_dev)).context(ks_err!("creator failed"))?;
        let key_parameters = key_characteristics_to_internal(creation_result.keyCharacteristics);

        let creation_date = DateTime::now().context(ks_err!("DateTime::now() failed"))?;

        let mut key_metadata = KeyMetaData::new();
        key_metadata.add(KeyMetaEntry::CreationDate(creation_date));
        let mut blob_metadata = BlobMetaData::new();
        blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

        db.store_new_key(
            key_desc,
            key_type,
            &key_parameters,
            &BlobInfo::new(&creation_result.keyBlob, &blob_metadata),
            &CertificateInfo::new(None, None),
            &key_metadata,
            &self.km_uuid,
        )
        .context(ks_err!("store_new_key failed"))?;
        Ok(())
    }

    /// Generate a KeyDescriptor for internal-use keys.
    pub fn internal_descriptor(alias: String) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: AID_KEYSTORE as i64,
            alias: Some(alias),
            blob: None,
        }
    }

    /// Look up an internal-use key in the database given a key descriptor.
    fn lookup_from_desc(
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        db.load_key_entry(key_desc, key_type, KeyEntryLoadBits::KM, AID_KEYSTORE, |_, _| Ok(()))
            .context(ks_err!("load_key_entry failed."))
    }

    /// Look up the key in the database, and return None if it is absent.
    fn not_found_is_none(
        lookup: Result<(KeyIdGuard, KeyEntry)>,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        match lookup {
            Ok(result) => Ok(Some(result)),
            Err(e) => match e.root_cause().downcast_ref::<Error>() {
                Some(&Error::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                _ => Err(e),
            },
        }
    }

    /// This does the lookup and store in separate transactions; caller must
    /// hold a lock before calling.
    pub fn lookup_or_generate_key<F>(
        &self,
        db: &mut KeystoreDB,
        key_desc: &KeyDescriptor,
        key_type: KeyType,
        params: &[KeyParameter],
        validate_characteristics: F,
    ) -> Result<(KeyIdGuard, KeyBlob)>
    where
        F: FnOnce(&[KeyCharacteristics]) -> bool,
    {
        // We use a separate transaction for the lookup than for the store
        // - to keep the code simple
        // - because the caller needs to hold a lock in any case
        // - because it avoids holding database locks during slow
        //   KeyMint operations
        let lookup = Self::not_found_is_none(Self::lookup_from_desc(db, key_desc, key_type))
            .context(ks_err!("first lookup failed"))?;

        if let Some((key_id_guard, mut key_entry)) = lookup {
            // If the key is associated with a different km instance
            // or if there is no blob metadata for some reason the key entry
            // is considered corrupted and needs to be replaced with a new one.
            let key_blob = key_entry.take_key_blob_info().and_then(|(key_blob, blob_metadata)| {
                if Some(&self.km_uuid) == blob_metadata.km_uuid() {
                    Some(key_blob)
                } else {
                    None
                }
            });

            if let Some(key_blob_vec) = key_blob {
                let (key_characteristics, key_blob) = self
                    .upgrade_keyblob_if_required_with(
                        db,
                        &key_id_guard,
                        KeyBlob::NonSensitive(key_blob_vec),
                        |key_blob| {
                            map_km_error({
                                let _wp = wd::watch(concat!(
                                    "KeyMintDevice::lookup_or_generate_key: ",
                                    "calling IKeyMintDevice::getKeyCharacteristics."
                                ));
                                self.km_dev.getKeyCharacteristics(key_blob, &[], &[])
                            })
                        },
                    )
                    .context(ks_err!("calling getKeyCharacteristics"))?;

                if validate_characteristics(&key_characteristics) {
                    return Ok((key_id_guard, key_blob));
                }

                // If this point is reached the existing key is considered outdated or corrupted
                // in some way. It will be replaced with a new key below.
            };
        }

        self.create_and_store_key(db, key_desc, key_type, |km_dev| {
            km_dev.generateKey(params, None)
        })
        .context(ks_err!("generate_and_store_key failed"))?;
        Self::lookup_from_desc(db, key_desc, key_type)
            .and_then(|(key_id_guard, mut key_entry)| {
                Ok((
                    key_id_guard,
                    key_entry
                        .take_key_blob_info()
                        .ok_or(Error::Rc(ResponseCode::KEY_NOT_FOUND))
                        .map(|(key_blob, _)| KeyBlob::NonSensitive(key_blob))
                        .context(ks_err!("Missing key blob info."))?,
                ))
            })
            .context(ks_err!("second lookup failed"))
    }

    /// Call the passed closure; if it returns `KEY_REQUIRES_UPGRADE`, call upgradeKey, and
    /// write the upgraded key to the database.
    fn upgrade_keyblob_if_required_with<'a, T, F>(
        &self,
        _db: &mut KeystoreDB,
        _key_id_guard: &KeyIdGuard,
        key_blob: KeyBlob<'a>,
        f: F,
    ) -> Result<(T, KeyBlob<'a>)>
    where
        F: Fn(&[u8]) -> Result<T, Error>,
    {
        let (f_result, upgraded_blob) = crate::utils::upgrade_keyblob_if_required_with(
            &*self.km_dev,
            self.version(),
            &key_blob,
            &[],
            f,
            |_upgraded_blob| {
                let mut new_blob_metadata = BlobMetaData::new();
                new_blob_metadata.add(BlobMetaEntry::KmUuid(self.km_uuid));

                /*
                db.set_blob(
                    key_id_guard,
                    SubComponentType::KEY_BLOB,
                    Some(upgraded_blob),
                    Some(&new_blob_metadata),
                )
                .context(ks_err!("Failed to insert upgraded blob into the database"))?;

*/
                Ok(())
            },
        )?;
        let returned_blob = match upgraded_blob {
            None => key_blob,
            Some(upgraded_blob) => KeyBlob::NonSensitive(upgraded_blob),
        };
        Ok((f_result, returned_blob))
    }

    /// Use the created key in an operation that can be done with
    /// a call to begin followed by a call to finish.
    #[allow(clippy::too_many_arguments)]
    pub fn use_key_in_one_step(
        &self,
        db: &mut KeystoreDB,
        key_id_guard: &KeyIdGuard,
        key_blob: &[u8],
        purpose: KeyPurpose,
        operation_parameters: &[KeyParameter],
        auth_token: Option<&HardwareAuthToken>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let key_blob = KeyBlob::Ref(key_blob);

        let (begin_result, _) = self
            .upgrade_keyblob_if_required_with(db, key_id_guard, key_blob, |blob| {
                map_km_error({
                    let _wp = wd::watch(
                        "KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::begin",
                    );
                    self.km_dev.begin(purpose, blob, operation_parameters, auth_token)
                })
            })
            .context(ks_err!("Failed to begin operation."))?;
        let operation: Strong<dyn IKeyMintOperation> =
            begin_result.operation.ok_or_else(Error::sys).context(ks_err!("Operation missing"))?;
        map_km_error({
            let _wp =
                wd::watch("KeyMintDevice::use_key_in_one_step: calling IKeyMintDevice::finish");
            operation.finish(Some(input), None, None, None, None)
        })
        .context(ks_err!("Failed to finish operation."))
    }
}
