use std::{collections::HashMap, ffi::c_void, ptr};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use widestring::{U16CStr, U16CString};
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::SECURITY_DESCRIPTOR,
    },
};

const PROVIDER_KEY: GUID = GUID::from_values(
    0xd9f1c5f7,
    0x13be,
    0x4f2b,
    [0xb5, 0x01, 0xe4, 0xf0, 0x7b, 0xdb, 0x6d, 0x93],
);
const SUBLAYER_KEY: GUID = GUID::from_values(
    0x5d2b9e18,
    0xea68,
    0x4a38,
    [0x93, 0xc7, 0x83, 0xf3, 0xf1, 0x4f, 0x0a, 0x01],
);
const PROVIDER_NAME: &str = "SLS WFP Manager Provider";
const SUBLAYER_NAME: &str = "SLS WFP Manager SubLayer";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WfpAction {
    Permit,
    Block,
    Callout,
}

impl WfpAction {
    fn to_fwpm(self) -> FWP_ACTION_TYPE {
        match self {
            WfpAction::Permit => FWP_ACTION_PERMIT,
            WfpAction::Block => FWP_ACTION_BLOCK,
            WfpAction::Callout => FWP_ACTION_CALLOUT_TERMINATING,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WfpAction::Permit => "Permit",
            WfpAction::Block => "Block",
            WfpAction::Callout => "Callout",
        }
    }
}

pub struct Engine(HANDLE);
impl Engine {
    pub fn open() -> Result<Self> {
        unsafe {
            let mut h = HANDLE::default();
            let session = FWPM_SESSION0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::null(),
                    description: PWSTR::null(),
                },
                ..Default::default()
            };
            let status = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, &session, &mut h);
            if status != 0 {
                return Err(anyhow!("FwpmEngineOpen0 failed: 0x{status:08X}"));
            }
            let engine = Self(h);
            engine.ensure_provider_setup()?;
            Ok(engine)
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let providers = self.enumerate_providers()?;
        let sublayers = self.enumerate_sublayers()?;
        let layers = self.enumerate_layers()?;

        let provider_map: HashMap<GUID, String> =
            providers.iter().map(|n| (n.key, n.name.clone())).collect();
        let sublayer_map: HashMap<GUID, String> =
            sublayers.iter().map(|n| (n.key, n.name.clone())).collect();
        let layer_map: HashMap<GUID, String> =
            layers.iter().map(|n| (n.key, n.name.clone())).collect();

        let filters = self.list_filters(&layer_map, &sublayer_map, &provider_map)?;

        Ok(Snapshot {
            filters,
            providers,
            sublayers,
            layers,
        })
    }

    pub fn add_simple_tcp_filter_v4(
        &self,
        name: &str,
        remote_port: u16,
        action: WfpAction,
    ) -> Result<u64> {
        unsafe {
            self.ensure_provider_setup()?;
            begin_transaction(self.0)?;
            let result = self.add_simple_tcp_filter_v4_inner(name, remote_port, action);
            finish_transaction(self.0, result)
        }
    }

    pub fn update_simple_tcp_filter_v4(
        &self,
        id: u64,
        name: &str,
        remote_port: u16,
        action: WfpAction,
    ) -> Result<()> {
        unsafe {
            self.ensure_provider_setup()?;
            begin_transaction(self.0)?;

            let mut filter_ptr: *mut FWPM_FILTER0 = ptr::null_mut();
            let status = FwpmFilterGetById0(self.0, id, &mut filter_ptr);
            if status != 0 {
                abort_transaction(self.0);
                return Err(anyhow!("FwpmFilterGetById0 failed: 0x{status:08X}"));
            }
            if filter_ptr.is_null() {
                abort_transaction(self.0);
                return Err(anyhow!("Filter {id} returned null"));
            }
            let filter = &*filter_ptr;

            // Only allow edits to filters we created.
            let owned = filter.subLayerKey == SUBLAYER_KEY
                && !filter.providerKey.is_null()
                && unsafe { *filter.providerKey } == PROVIDER_KEY;
            if !owned {
                abort_transaction(self.0);
                free_wfp_single(filter_ptr);
                return Err(anyhow!("Filter {id} is not managed by this application"));
            }

            let name_ws = U16CString::from_str(name)?;
            let mut provider_key = PROVIDER_KEY;
            let display = FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_ws.as_ptr() as *mut _),
                description: PWSTR::null(),
            };

            let proto_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            };

            let port_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: remote_port,
                    },
                },
            };
            let conds = [proto_cond, port_cond];

            let mut updated = FWPM_FILTER0 {
                displayData: display,
                layerKey: filter.layerKey,
                subLayerKey: filter.subLayerKey,
                weight: filter.weight,
                numFilterConditions: conds.len() as u32,
                filterCondition: conds.as_ptr(),
                action: FWPM_ACTION0 {
                    r#type: action.to_fwpm(),
                    ..Default::default()
                },
                providerKey: &mut provider_key,
                flags: filter.flags,
                rawContext: filter.rawContext,
                providerData: filter.providerData,
                effectiveWeight: filter.effectiveWeight,
                ..Default::default()
            };

            let status = FwpmFilterUpdate0(self.0, id, &mut updated);
            free_wfp_single(filter_ptr);
            if status != 0 {
                abort_transaction(self.0);
                return Err(anyhow!("FwpmFilterUpdate0 failed: 0x{status:08X}"));
            }

            finish_transaction(self.0, Ok(()))
        }
    }

    pub fn delete_filter_by_id(&self, id: u64) -> Result<()> {
        unsafe {
            begin_transaction(self.0)?;

            let mut filter_ptr: *mut FWPM_FILTER0 = ptr::null_mut();
            let status = FwpmFilterGetById0(self.0, id, &mut filter_ptr);
            if status != 0 {
                abort_transaction(self.0);
                return Err(anyhow!("FwpmFilterGetById0 failed: 0x{status:08X}"));
            }
            let filter = if filter_ptr.is_null() {
                None
            } else {
                Some(&*filter_ptr)
            };
            let owned = filter
                .map(|f| {
                    f.subLayerKey == SUBLAYER_KEY
                        && !f.providerKey.is_null()
                        && unsafe { *f.providerKey } == PROVIDER_KEY
                })
                .unwrap_or(false);

            if !owned {
                free_wfp_single(filter_ptr);
                abort_transaction(self.0);
                return Err(anyhow!("Filter {id} is not managed by this application"));
            }

            let status = FwpmFilterDeleteById0(self.0, id);
            free_wfp_single(filter_ptr);
            if status != 0 {
                abort_transaction(self.0);
                return Err(anyhow!("FwpmFilterDeleteById0 failed: 0x{status:08X}"));
            }

            finish_transaction(self.0, Ok(()))
        }
    }

    pub fn export_owned_filters(&self) -> Result<String> {
        let snapshot = self.snapshot()?;
        let configs: Vec<FilterConfig> = snapshot
            .filters
            .into_iter()
            .filter(|f| f.owned_by_app)
            .filter_map(|f| {
                f.remote_port.map(|port| FilterConfig {
                    name: f.name,
                    remote_port: port,
                    action: f.action,
                })
            })
            .collect();
        Ok(serde_json::to_string_pretty(&configs)?)
    }

    pub fn import_filters(&self, configs: &[FilterConfig]) -> Result<()> {
        unsafe {
            self.ensure_provider_setup()?;
            begin_transaction(self.0)?;
            for cfg in configs {
                if cfg.remote_port == 0 {
                    abort_transaction(self.0);
                    return Err(anyhow!("Remote port cannot be zero"));
                }
                if let Err(e) =
                    self.add_simple_tcp_filter_v4_inner(&cfg.name, cfg.remote_port, cfg.action)
                {
                    abort_transaction(self.0);
                    return Err(e);
                }
            }
            finish_transaction(self.0, Ok(()))
        }
    }

    fn add_simple_tcp_filter_v4_inner(
        &self,
        name: &str,
        remote_port: u16,
        action: WfpAction,
    ) -> Result<u64> {
        unsafe {
            let name_ws = U16CString::from_str(name)?;
            let display = FWPM_DISPLAY_DATA0 {
                name: PWSTR(name_ws.as_ptr() as *mut _),
                description: PWSTR::null(),
            };

            let mut provider_key = PROVIDER_KEY;

            let proto_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 },
                },
            };
            let port_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: remote_port,
                    },
                },
            };
            let conds = [proto_cond, port_cond];

            let mut filter = FWPM_FILTER0 {
                displayData: display,
                layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                subLayerKey: SUBLAYER_KEY,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_VALUE0_0 { uint64: 10 },
                },
                numFilterConditions: conds.len() as u32,
                filterCondition: conds.as_ptr(),
                action: FWPM_ACTION0 {
                    r#type: action.to_fwpm(),
                    ..Default::default()
                },
                providerKey: &mut provider_key,
                ..Default::default()
            };

            let mut id = 0u64;
            let status = FwpmFilterAdd0(self.0, &mut filter, ptr::null(), &mut id);
            if status != 0 {
                return Err(anyhow!("FwpmFilterAdd0 failed: 0x{status:08X}"));
            }
            Ok(id)
        }
    }

    fn ensure_provider_setup(&self) -> Result<()> {
        unsafe {
            let provider_name = U16CString::from_str(PROVIDER_NAME)?;
            let provider = FWPM_PROVIDER0 {
                providerKey: PROVIDER_KEY,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(provider_name.as_ptr() as *mut _),
                    description: PWSTR::null(),
                },
                ..Default::default()
            };
            let status = FwpmProviderAdd0(self.0, &provider, ptr::null::<SECURITY_DESCRIPTOR>());
            if status != 0 && status != FWP_E_ALREADY_EXISTS.0 as u32 {
                return Err(anyhow!("FwpmProviderAdd0 failed: 0x{status:08X}"));
            }

            let sublayer_name = U16CString::from_str(SUBLAYER_NAME)?;
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER_KEY,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR(sublayer_name.as_ptr() as *mut _),
                    description: PWSTR::null(),
                },
                providerKey: PROVIDER_KEY,
                weight: 0x7FFF,
                ..Default::default()
            };
            let status = FwpmSubLayerAdd0(self.0, &sublayer, ptr::null::<SECURITY_DESCRIPTOR>());
            if status != 0 && status != FWP_E_ALREADY_EXISTS.0 as u32 {
                return Err(anyhow!("FwpmSubLayerAdd0 failed: 0x{status:08X}"));
            }
        }
        Ok(())
    }

    fn list_filters(
        &self,
        layer_map: &HashMap<GUID, String>,
        sublayer_map: &HashMap<GUID, String>,
        provider_map: &HashMap<GUID, String>,
    ) -> Result<Vec<FilterSummary>> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let status = FwpmFilterCreateEnumHandle0(self.0, ptr::null(), &mut enum_handle);
            if status != 0 {
                return Err(anyhow!(
                    "FwpmFilterCreateEnumHandle0 failed: 0x{status:08X}"
                ));
            }

            let mut filters = Vec::new();
            loop {
                let mut entries_ptr: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut count: u32 = 0;
                let status =
                    FwpmFilterEnum0(self.0, enum_handle, 128, &mut entries_ptr, &mut count);
                if status != 0 {
                    let _ = FwpmFilterDestroyEnumHandle0(self.0, enum_handle);
                    return Err(anyhow!("FwpmFilterEnum0 failed: 0x{status:08X}"));
                }
                if entries_ptr.is_null() || count == 0 {
                    break;
                }

                for idx in 0..count as isize {
                    let filter_ptr = *entries_ptr.offset(idx);
                    if filter_ptr.is_null() {
                        continue;
                    }
                    let filter = &*filter_ptr;

                    let name = if !filter.displayData.name.is_null() {
                        let cstr = U16CStr::from_ptr_str(filter.displayData.name.0);
                        cstr.to_string_lossy()
                    } else {
                        String::from("<no name>")
                    };

                    let layer_name = layer_map
                        .get(&filter.layerKey)
                        .cloned()
                        .unwrap_or_else(|| format!("{:#?}", filter.layerKey));
                    let sublayer_name = sublayer_map
                        .get(&filter.subLayerKey)
                        .cloned()
                        .unwrap_or_else(|| format!("{:#?}", filter.subLayerKey));

                    let provider_key = if filter.providerKey.is_null() {
                        None
                    } else {
                        Some(unsafe { *filter.providerKey })
                    };
                    let provider_name = provider_key
                        .and_then(|key| provider_map.get(&key).cloned())
                        .unwrap_or_else(|| String::from("<unknown provider>"));

                    let action = match filter.action.r#type {
                        FWP_ACTION_PERMIT => WfpAction::Permit,
                        FWP_ACTION_BLOCK => WfpAction::Block,
                        _ => WfpAction::Callout,
                    };

                    let conds = std::slice::from_raw_parts(
                        filter.filterCondition,
                        filter.numFilterConditions as usize,
                    );
                    let mut remote_port = None;
                    for cond in conds {
                        if cond.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT
                            && cond.conditionValue.r#type == FWP_UINT16
                        {
                            remote_port = Some(unsafe { cond.conditionValue.Anonymous.uint16 });
                        }
                    }

                    let owned = filter.subLayerKey == SUBLAYER_KEY
                        && provider_key.map(|key| key == PROVIDER_KEY).unwrap_or(false);

                    filters.push(FilterSummary {
                        id: filter.filterId,
                        name,
                        layer: layer_name,
                        layer_key: filter.layerKey,
                        sublayer: sublayer_name,
                        sublayer_key: filter.subLayerKey,
                        provider: provider_name,
                        provider_key,
                        action,
                        remote_port,
                        owned_by_app: owned,
                    });
                }

                free_wfp_array(entries_ptr);
            }

            let _ = FwpmFilterDestroyEnumHandle0(self.0, enum_handle);
            Ok(filters)
        }
    }

    fn enumerate_layers(&self) -> Result<Vec<NamedGuid>> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let status = FwpmLayerCreateEnumHandle0(self.0, ptr::null(), &mut enum_handle);
            if status != 0 {
                return Err(anyhow!("FwpmLayerCreateEnumHandle0 failed: 0x{status:08X}"));
            }

            let mut out = Vec::new();
            loop {
                let mut entries_ptr: *mut *mut FWPM_LAYER0 = ptr::null_mut();
                let mut count = 0u32;
                let status = FwpmLayerEnum0(self.0, enum_handle, 128, &mut entries_ptr, &mut count);
                if status != 0 {
                    let _ = FwpmLayerDestroyEnumHandle0(self.0, enum_handle);
                    return Err(anyhow!("FwpmLayerEnum0 failed: 0x{status:08X}"));
                }
                if entries_ptr.is_null() || count == 0 {
                    break;
                }
                for idx in 0..count as isize {
                    let entry = *entries_ptr.offset(idx);
                    if entry.is_null() {
                        continue;
                    }
                    let layer = &*entry;
                    out.push(NamedGuid {
                        key: layer.layerKey,
                        name: display_name(&layer.displayData),
                        description: display_description(&layer.displayData),
                    });
                }
                free_wfp_array(entries_ptr);
            }
            let _ = FwpmLayerDestroyEnumHandle0(self.0, enum_handle);
            Ok(out)
        }
    }

    fn enumerate_providers(&self) -> Result<Vec<NamedGuid>> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let status = FwpmProviderCreateEnumHandle0(self.0, ptr::null(), &mut enum_handle);
            if status != 0 {
                return Err(anyhow!(
                    "FwpmProviderCreateEnumHandle0 failed: 0x{status:08X}"
                ));
            }

            let mut out = Vec::new();
            loop {
                let mut entries_ptr: *mut *mut FWPM_PROVIDER0 = ptr::null_mut();
                let mut count = 0u32;
                let status =
                    FwpmProviderEnum0(self.0, enum_handle, 128, &mut entries_ptr, &mut count);
                if status != 0 {
                    let _ = FwpmProviderDestroyEnumHandle0(self.0, enum_handle);
                    return Err(anyhow!("FwpmProviderEnum0 failed: 0x{status:08X}"));
                }
                if entries_ptr.is_null() || count == 0 {
                    break;
                }
                for idx in 0..count as isize {
                    let entry = *entries_ptr.offset(idx);
                    if entry.is_null() {
                        continue;
                    }
                    let provider = &*entry;
                    out.push(NamedGuid {
                        key: provider.providerKey,
                        name: display_name(&provider.displayData),
                        description: display_description(&provider.displayData),
                    });
                }
                free_wfp_array(entries_ptr);
            }
            let _ = FwpmProviderDestroyEnumHandle0(self.0, enum_handle);
            Ok(out)
        }
    }

    fn enumerate_sublayers(&self) -> Result<Vec<NamedGuid>> {
        unsafe {
            let mut enum_handle = HANDLE::default();
            let status = FwpmSubLayerCreateEnumHandle0(self.0, ptr::null(), &mut enum_handle);
            if status != 0 {
                return Err(anyhow!(
                    "FwpmSubLayerCreateEnumHandle0 failed: 0x{status:08X}"
                ));
            }

            let mut out = Vec::new();
            loop {
                let mut entries_ptr: *mut *mut FWPM_SUBLAYER0 = ptr::null_mut();
                let mut count = 0u32;
                let status =
                    FwpmSubLayerEnum0(self.0, enum_handle, 128, &mut entries_ptr, &mut count);
                if status != 0 {
                    let _ = FwpmSubLayerDestroyEnumHandle0(self.0, enum_handle);
                    return Err(anyhow!("FwpmSubLayerEnum0 failed: 0x{status:08X}"));
                }
                if entries_ptr.is_null() || count == 0 {
                    break;
                }
                for idx in 0..count as isize {
                    let entry = *entries_ptr.offset(idx);
                    if entry.is_null() {
                        continue;
                    }
                    let sublayer = &*entry;
                    out.push(NamedGuid {
                        key: sublayer.subLayerKey,
                        name: display_name(&sublayer.displayData),
                        description: display_description(&sublayer.displayData),
                    });
                }
                free_wfp_array(entries_ptr);
            }
            let _ = FwpmSubLayerDestroyEnumHandle0(self.0, enum_handle);
            Ok(out)
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.0);
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Clone)]
pub struct FilterSummary {
    pub id: u64,
    pub name: String,
    pub layer: String,
    pub layer_key: GUID,
    pub sublayer: String,
    pub sublayer_key: GUID,
    pub provider: String,
    pub provider_key: Option<GUID>,
    pub action: WfpAction,
    pub remote_port: Option<u16>,
    pub owned_by_app: bool,
}

#[derive(Clone)]
pub struct NamedGuid {
    pub key: GUID,
    pub name: String,
    pub description: Option<String>,
}

pub struct Snapshot {
    pub filters: Vec<FilterSummary>,
    pub providers: Vec<NamedGuid>,
    pub sublayers: Vec<NamedGuid>,
    pub layers: Vec<NamedGuid>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub name: String,
    pub remote_port: u16,
    pub action: WfpAction,
}

fn display_name(display: &FWPM_DISPLAY_DATA0) -> String {
    if display.name.is_null() {
        String::from("<unnamed>")
    } else {
        let cstr = unsafe { U16CStr::from_ptr_str(display.name.0) };
        cstr.to_string_lossy()
    }
}

fn display_description(display: &FWPM_DISPLAY_DATA0) -> Option<String> {
    if display.description.is_null() {
        None
    } else {
        let cstr = unsafe { U16CStr::from_ptr_str(display.description.0) };
        Some(cstr.to_string_lossy())
    }
}

fn begin_transaction(handle: HANDLE) -> Result<()> {
    let status = unsafe { FwpmTransactionBegin0(handle, 0) };
    if status != 0 {
        Err(anyhow!("FwpmTransactionBegin0 failed: 0x{status:08X}"))
    } else {
        Ok(())
    }
}

fn finish_transaction<T>(handle: HANDLE, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            let status = unsafe { FwpmTransactionCommit0(handle) };
            if status != 0 {
                Err(anyhow!("FwpmTransactionCommit0 failed: 0x{status:08X}"))
            } else {
                Ok(value)
            }
        }
        Err(e) => {
            abort_transaction(handle);
            Err(e)
        }
    }
}

fn abort_transaction(handle: HANDLE) {
    let _ = unsafe { FwpmTransactionAbort0(handle) };
}

fn free_wfp_array<T>(ptr: *mut *mut T) {
    if !ptr.is_null() {
        unsafe { FwpmFreeMemory0(ptr.cast::<*mut c_void>()) };
    }
}

fn free_wfp_single<T>(ptr: *mut T) {
    if !ptr.is_null() {
        unsafe {
            let mut tmp = ptr as *mut c_void;
            FwpmFreeMemory0(&mut tmp as *mut *mut c_void);
        }
    }
}
