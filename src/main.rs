extern crate libc;

use libc::{c_void, dl_iterate_phdr, dl_phdr_info, dlopen};
use std::convert::TryInto;
use std::ffi::CStr;
use std::fmt::{Debug, Error, Formatter};
use std::ops::Deref;
use std::os::raw::c_char;

#[derive(Debug, Clone)]
struct Module {
    address: usize,
    size: usize,
    name: String,
}

#[derive(Debug, Clone)]
struct CallbackContext {
    modules: Vec<Module>,
    pagesize: u64,
}

type CreateClientClassFn = fn(i32, i32) -> *mut c_void;
type CreateEventFn = fn() -> *mut c_void;

#[allow(non_snake_case)]
#[repr(C)]
struct RecvTable {
    m_pProps: *const RecvProp,
    m_nProps: i32,
    m_pDecoder: *const c_void,
    m_pNetTableName: *const c_char,
    m_bInitialized: bool,
    m_bInMainList: bool,
}

impl Debug for RecvTable {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "{:#?}",
            (0..self.m_nProps)
                .filter_map(|i| unsafe { self.m_pProps.add(i as usize).as_ref() })
                .collect::<Vec<_>>()
        )
    }
}

impl Debug for RecvProp {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let propname = unsafe { CStr::from_ptr(self.m_pVarName) };
        if let Some(table) = unsafe { self.m_pDataTable.as_ref() } {
            let name = unsafe { CStr::from_ptr(table.m_pNetTableName) };
            write!(f, "{:?} @ {:#X} -> {:?} {:#?}",propname, self.m_Offset,name,table)
        } else {

            write!(f, "{:?} -> {:#X}", propname, self.m_Offset)
        }
    }
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug)]
struct ClientClass {
    m_pCreateFn: CreateClientClassFn,
    m_pCreateEventFn: CreateEventFn,
    m_pNetworkName: *const c_char,
    m_pRecvTable: *const RecvTable,
    m_pNext: *const ClientClass,
    m_ClassID: i32,
}

struct ClientClassIterator {
    current: *const ClientClass,
}

impl<'a> Iterator for ClientClassIterator {
    type Item = *const ClientClass;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe { self.current.as_ref() }.and_then(|v| {
            self.current = v.m_pNext;
            Some(v as *const _)
        })
    }
}

#[allow(non_snake_case)]
#[repr(C)]
struct RecvProp {
    m_pVarName: *const c_char,
    m_RecvType: i32,
    m_Flags: i32,
    m_StringBufferSize: i32,
    m_bInsideArray: bool,
    m_pExtraData: *const c_void,
    m_pArrayProp: *const RecvProp,
    m_ArrayLengthProxy: *const c_void,
    m_ProxyFn: *const c_void, /* RecvVarProxyFn */
    m_DataTableProxyFn: *const c_void,
    m_pDataTable: *const RecvTable,
    m_Offset: i32,
    m_ElementStride: i32,
    m_nElements: i32,
    m_pParentArrayPropName: *const c_char,
}

impl CallbackContext {
    pub fn new() -> Self {
        let pagesize: u64 = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
            .try_into()
            .expect("page size doesn't fit into u64! This should *never* happen.");

        CallbackContext {
            modules: Vec::new(),
            pagesize,
        }
    }
}

impl Module {
    pub fn new(info: &dl_phdr_info, pagesize: u64) -> Option<Self> {
        // TODO: Linux shared modules have gaps in their allocations.
        // This usually isn't a problem if the signature is valid, but it may cause a segfault if it is invalid.

        let name = unsafe { CStr::from_ptr(info.dlpi_name) }.to_str().ok()?;
        let size: u64 = (0..info.dlpi_phnum)
            .filter_map(|i| unsafe { info.dlpi_phdr.add(i as usize).as_ref() })
            // https://github.com/lattera/glibc/blob/master/elf/dl-load.c#L1085
            .map(|e| e.p_vaddr + e.p_memsz)
            // Align to pagesize
            // https://github.com/lattera/glibc/blob/master/elf/dl-load.c#L1085
            .map(|a| (a + pagesize - 1) & !(pagesize - 1))
            .max()?;
        Some(Module {
            address: info.dlpi_addr as usize,
            size: size as usize,
            name: name.to_string(),
        })
    }

    pub unsafe fn find_pattern(&self, pattern: &str) -> Option<usize> {
        use regex::bytes::Regex;
        use std::iter::once;
        // Credits: https://github.com/frk1/hazedumper-rs/blob/master/src/memlib/findpattern.rs
        let res = once("(?s-u)".to_string())
            .chain(pattern.split_whitespace().map(|x| match &x {
                &"?" | &"??" => ".".to_string(),
                x => format!("\\x{}", x),
            }))
            .collect::<Vec<_>>()
            .join("");
        let base = self.address as *const u8;
        let slice = std::slice::from_raw_parts(base, self.size);
        let offset = Regex::new(&res).ok()?.find(slice)?.start();
        Some(base.add(offset) as usize)
    }
}

extern "C" fn callback(info: *mut dl_phdr_info, size: usize, data: *mut c_void) -> i32 {
    let context =
        unsafe { (data as *mut CallbackContext).as_mut() }.expect("Modulelist was invalid!");
    let pagesize = context.pagesize;

    // (In)sanity check: Assert that the page size is a power of 2
    // i.e. 8: 1000 & 0111 = 0000
    debug_assert_eq!((pagesize & (pagesize - 1)), 0);
    // (In)sanity check: Have the bindings been generated properly?
    debug_assert_eq!(std::mem::size_of::<dl_phdr_info>(), size);

    let info = unsafe { info.as_ref() }.expect("Invalid module pointer passed!");

    // Non-zero return values cause dl_iterate_phdr to abort
    Module::new(info, pagesize)
        .and_then(|module| {
            context.modules.insert(0, module);
            Some(0)
        })
        .unwrap_or(1)
}

fn main() {
    if let Some(gamedir) = &std::env::args().nth(1) {
        let library: *mut c_void = unsafe {
            dlopen(
                "client_panorama_client.so\0".as_ptr() as *const c_char,
                libc::RTLD_LAZY | libc::RTLD_GLOBAL,
            )
        };
        println!("Client: {:?}", library);
        let mut context = CallbackContext::new();

        unsafe {
            dl_iterate_phdr(Some(callback), &mut context as *mut _ as *mut c_void);
        }

        let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        println!("Pagesize: {:#X}", pagesize);

        let client = context
            .modules
            .iter()
            .find(|m| m.deref().name.ends_with("panorama_client.so"))
            .and_then(|module| unsafe { module.find_pattern("91 48 8B 05 ? ? ? ? 8B 53 14") })
            .unwrap();
        // g_pClientClassHead
        // 91 48 8B 05 ? ? ? ? 8B 53 14
        println!("{:#X?}", client);
        let off_client = unsafe { ((client + 4) as *const u32).read() };
        println!("{:#X?}", off_client);
        println!("{:#X?}", off_client as usize + client + 8);

        let client = (off_client as usize + client + 8) as *const *const *const ClientClass;
        if let Some(client) = unsafe { client.as_ref() } {
            let class = unsafe { client.read() };

            let iter = ClientClassIterator { current: class };
            let classes: Vec<_> = iter
                .filter_map(|c| unsafe { c.as_ref() })
                .map(|c| (c, unsafe { c.m_pRecvTable.as_ref() }))
                .filter_map(|(c, r)| r.and_then(|t| Some((c, t))))
                .collect();

            println!("{:#?}", classes);
        }
    } else {
        eprintln!("usage: csgobot <path to CS:GO>");
    }
}
