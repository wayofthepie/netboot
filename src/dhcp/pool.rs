use std::{collections::HashMap, net::Ipv4Addr};

use mac_address::MacAddress;

pub struct DhcpPool {
    addresses: Vec<Ipv4Addr>,
    allocations: HashMap<MacAddress, Ipv4Addr>,
}

impl DhcpPool {
    pub fn new(addresses: Vec<Ipv4Addr>) -> Self {
        Self {
            addresses,
            allocations: HashMap::new(),
        }
    }

    pub fn allocate(&mut self, mac: MacAddress) -> Option<Ipv4Addr> {
        self.addresses.pop().map(|address| {
            self.allocations.insert(mac, address);
            address
        })
    }

    pub fn get(&self, mac: &MacAddress) -> Option<&Ipv4Addr> {
        self.allocations.get(mac)
    }
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, str::FromStr};

    use mac_address::MacAddress;

    use super::DhcpPool;

    #[test]
    fn should_allocate_first_address() {
        let mac = MacAddress::from_str("00:00:00:00:00:00").unwrap();
        let addresses = vec![Ipv4Addr::from_str("192.168.1.2").unwrap()];
        let mut pool = DhcpPool::new(addresses.clone());
        let allocated = pool.allocate(mac).unwrap();
        let stored = pool.get(&mac).unwrap();
        assert_eq!(allocated, addresses[0]);
        assert_eq!(stored, &addresses[0]);
    }
}
