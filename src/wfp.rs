use anyhow::{anyhow, Result};
use widestring::U16CStr;
use windows::{
    core::{GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::SECURITY_DESCRIPTOR,
    },
};

pub enum WfpAction { Permit, Block, Callout }

pub struct Engine(HANDLE);
impl Engine {
    pub fn open() -> Result<Self> {
        let mut h = HANDLE::default();
        // RPC_C_AUTHN_WINNT is recommended for local engine. Session can be named.
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::null(),
                description: PWSTR::null(),
            },
            ..Default::default()
        };
        let status = unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, &session, &mut h) };
        if status != 0 { return Err(anyhow!("FwpmEngineOpen0 failed: 0x{status:08X}")); }
        Ok(Self(h))
    }

    pub fn list_filters(&self) -> Result<Vec<FilterSummary>> {
        unsafe {
            // 1) Create enumerator
            let mut enum_handle = HANDLE::default();
            let st = FwpmFilterCreateEnumHandle0(self.0, std::ptr::null(), &mut enum_handle);
            if st != 0 { return Err(anyhow!("FwpmFilterCreateEnumHandle0 failed: 0x{st:08X}")); }

            let mut out = Vec::new();
            loop {
                let mut entries_ptr: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut count: u32 = 0;
                let st = FwpmFilterEnum0(self.0, enum_handle, 128, &mut entries_ptr, &mut count);
                if st != 0 { 
                    // destroy enum and bail
                    let _ = FwpmFilterDestroyEnumHandle0(self.0, enum_handle);
                    return Err(anyhow!("FwpmFilterEnum0 failed: 0x{st:08X}"));
                }
                if entries_ptr.is_null() || count == 0 { break; }

                for i in 0..count as isize {
                    let p = *entries_ptr.offset(i);
                    let f = &*p;

                    // Name
                    let name = if !f.displayData.name.is_null() {
                        let s = U16CStr::from_ptr_str(f.displayData.name.0);
                        s.to_string_lossy()
                    } else { String::from("<no name>") };

                    // Layer GUID -> friendly token where possible
                    let layer = guid_to_layer_name(&f.layerKey);

                    // Action
                    let action = match f.action.r#type {
                        FWP_ACTION_PERMIT => WfpAction::Permit,
                        FWP_ACTION_BLOCK  => WfpAction::Block,
                        _ => WfpAction::Callout,
                    };

                    out.push(FilterSummary {
                        id: f.filterId,
                        name,
                        layer,
                        action,
                    });
                }

                // Free page of results
                FwpmFreeMemory0(&mut entries_ptr.cast());
            }

            // Destroy enumerator
            let _ = FwpmFilterDestroyEnumHandle0(self.0, enum_handle);
            Ok(out)
        }
    }

    /// Minimal example: add a TCP permit/block at ALE_AUTH_CONNECT_V4 with a remote port condition.
    /// Extend to add address/SD/providermetadata/weights/etc.
    pub fn add_simple_tcp_filter_v4(&self, name: &str, remote_port: u16, action: WfpAction) -> Result<u64> {
        unsafe {
            // Create (or reuse a constant) sublayer to scope rule order
            let sublayer_key = GUID::from_u128(0x5d2b9e18_ea68_4a38_93c7_83f3f14f0a01);
            let sub = FWPM_SUBLAYER0 {
                subLayerKey: sublayer_key,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: PWSTR::from_raw(PCWSTR::from_raw(windows::w!("SLS SubLayer").as_ptr()).0 as *mut _),
                    description: PWSTR::null(),
                },
                weight: 0x7FFF,
                ..Default::default()
            };
            let _ = FwpmSubLayerAdd0(self.0, &sub, std::ptr::null());

            // Begin a transaction so the add is atomic
            let st = FwpmTransactionBegin0(self.0, 0);
            if st != 0 { return Err(anyhow!("FwpmTransactionBegin0 failed: 0x{st:08X}")); }

            let name_ws = widestring::U16CString::from_str(name).unwrap();
            let display = FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(PCWSTR::from_raw(name_ws.as_ptr()).0 as *mut _),
                description: PWSTR::null(),
            };

            // Condition: Protocol == TCP
            let proto_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 6 }, // TCP
                },
            };

            // Condition: Remote Port == remote_port
            let port_cond = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: remote_port },
                },
            };

            let conds = [proto_cond, port_cond];

            let action_type = match action {
                WfpAction::Permit => FWP_ACTION_PERMIT,
                WfpAction::Block => FWP_ACTION_BLOCK,
                WfpAction::Callout => FWP_ACTION_CALLOUT_TERMINATING, // placeholder
            };

            let mut filter = FWPM_FILTER0 {
                displayData: display,
                layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4, // outbound connect authorization (IPv4)
                subLayerKey: sublayer_key,
                // NOTE: weights drive precedence among same-layer/sublayer filters
                weight: FWP_VALUE0 { r#type: FWP_UINT64, Anonymous: FWP_VALUE0_0 { uint64: 10 } },
                action: FWPM_ACTION0 { r#type: action_type, ..Default::default() },
                numFilterConditions: conds.len() as u32,
                filterCondition: conds.as_ptr(),
                ..Default::default()
            };

            let mut id = 0u64;
            let st = FwpmFilterAdd0(self.0, &mut filter, std::ptr::null(), &mut id);
            if st != 0 {
                let _ = FwpmTransactionAbort0(self.0);
                return Err(anyhow!("FwpmFilterAdd0 failed: 0x{st:08X}"));
            }

            let st = FwpmTransactionCommit0(self.0);
            if st != 0 { return Err(anyhow!("FwpmTransactionCommit0 failed: 0x{st:08X}")); }
            Ok(id)
        }
    }

    // TODO: add delete/update helpers
    // pub fn delete_filter_by_id(&self, id: u64) -> Result<()> { ... }
    // pub fn update_filter(&self, ...) -> Result<()> { ... }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { let _ = FwpmEngineClose0(self.0); let _ = CloseHandle(self.0); }
    }
}

pub struct FilterSummary {
    pub id: u64,
    pub name: String,
    pub layer: String,
    pub action: WfpAction,
}

fn guid_to_layer_name(g: &GUID) -> String {
    // Minimal pretty-printer. You can enumerate layers with FwpmLayerEnum0 to build a map.
    if *g == FWPM_LAYER_ALE_AUTH_CONNECT_V4 { "ALE_AUTH_CONNECT_V4".into() }
    else if *g == FWPM_LAYER_ALE_AUTH_CONNECT_V6 { "ALE_AUTH_CONNECT_V6".into() }
    else if *g == FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 { "ALE_FLOW_ESTABLISHED_V4".into() }
    else { format!("{g:?}") }
}
