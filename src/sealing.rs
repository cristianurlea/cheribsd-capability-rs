use morello::capability::*;

// Derive a new sealing capability
// TODO: keep within bounds of what's representable 
pub fn new_sealing_capability<T>(root_seal: *const T, otype: Address) -> *const T {

    // should we check for the sealing permission ? 
    let new_sealing_cap_address: usize = get_address(root_seal) ^ otype;

    let new_sealing_cap: *const T = new_cap_with_provenance(root_seal, new_sealing_cap_address);

    let new_sealing_cap_bounded: *const T = set_bounds(new_sealing_cap, 1);

    return new_sealing_cap_bounded;
}