//! Lot 285: the module-load judge's kernel objects — its configuration, the
//! trust map, the package managers' images, the write history — taken from
//! the loaded object for the controller ([`super::start`]).

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap, MapData};
use aya::Ebpf;
use common::module_judge::{conf_slot, ModuleTrust};
use common::wire::InodeKey;

/// `InodeKey` for aya (its own `Pod` marker; the orphan rule forbids
/// implementing it on the `common` type).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AyaKey(pub InodeKey);
// SAFETY: `#[repr(C)]` over two u64, no padding; transparent wrapper.
unsafe impl aya::Pod for AyaKey {}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AyaTrust(pub ModuleTrust);
// SAFETY: `#[repr(C)]`, two i64 then two u32, no padding.
unsafe impl aya::Pod for AyaTrust {}

/// What the controller holds.
pub struct Kernel {
    conf: Array<MapData, u64>,
    trust: HashMap<MapData, AyaKey, AyaTrust>,
    pkg_images: HashMap<MapData, AyaKey, u32>,
    writes: HashMap<MapData, AyaKey, u32>,
    gen: Array<MapData, u64>,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

/// Take the judge's maps out of the object (before its programs attach:
/// the maps exist from the load on).
pub fn take(ebpf: &mut Ebpf) -> Result<Kernel> {
    let mut take = |name: &str| {
        ebpf.take_map(name)
            .ok_or_else(|| anyhow!("{name} missing from the eBPF object"))
    };
    Ok(Kernel {
        conf: Array::try_from(take("MODULE_CONF")?).context("MODULE_CONF")?,
        trust: HashMap::try_from(take("MODULE_TRUST")?).context("MODULE_TRUST")?,
        pkg_images: HashMap::try_from(take("MODULE_PKG_IMAGES")?).context("MODULE_PKG_IMAGES")?,
        writes: HashMap::try_from(take("MODULE_WRITES")?).context("MODULE_WRITES")?,
        gen: Array::try_from(take("MODULE_WRITE_GEN")?).context("MODULE_WRITE_GEN")?,
    })
}

impl Kernel {
    pub fn set_mode(&mut self, mode: u64) -> Result<()> {
        self.conf
            .set(conf_slot::MODE, mode, 0)
            .context("MODULE_CONF mode")
    }

    pub fn set_tree(&mut self, tree: InodeKey) -> Result<()> {
        // the inode first: the kernel reads the device as "set"
        self.conf
            .set(conf_slot::TREE_INO, tree.ino, 0)
            .context("MODULE_CONF tree")?;
        self.conf
            .set(conf_slot::TREE_DEV, tree.dev, 0)
            .context("MODULE_CONF tree")
    }

    pub fn put(&mut self, key: InodeKey, t: ModuleTrust) -> Result<()> {
        self.trust
            .insert(AyaKey(key), AyaTrust(t), 0)
            .context("MODULE_TRUST insert")
    }

    pub fn drop_key(&mut self, key: InodeKey) {
        let _ = self.trust.remove(&AyaKey(key));
    }

    /// Replace the package managers' images with `keys`.
    pub fn set_pkg_images(&mut self, keys: &[InodeKey]) {
        let old: Vec<AyaKey> = self.pkg_images.keys().filter_map(|k| k.ok()).collect();
        for k in old {
            if !keys.contains(&k.0) {
                let _ = self.pkg_images.remove(&k);
            }
        }
        for k in keys {
            let _ = self.pkg_images.insert(AyaKey(*k), 1, 0);
        }
    }

    /// The kernel's write history of `key`.
    pub fn history(&self, key: InodeKey) -> Option<u32> {
        self.writes.get(&AyaKey(key), 0).ok()
    }

    /// The write history's generation (bumped at each write recorded).
    pub fn write_gen(&self) -> u64 {
        self.gen.get(&0, 0).unwrap_or(0)
    }
}
