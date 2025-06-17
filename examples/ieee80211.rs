use std::marker::PhantomData;

use ether_type::EtherType;
use ieee80211::{
    common::{FCFFlags, SequenceControl},
    data_frame::{header::DataFrameHeader, DataFrame},
    mac_parser::BROADCAST,
};
use llc_rs::SnapLlcFrame;
use scroll::Pwrite;

fn main() {
    let fcf = FCFFlags::new().with_to_ds(true);

    let snapllc = SnapLlcFrame {
        oui: [0, 0, 0],
        ether_type: EtherType::Unknown(0x0800),
        payload: [0x0u8].as_slice(),
        _phantom: PhantomData,
    };
    let data_frame = DataFrame {
        header: DataFrameHeader {
            fcf_flags: fcf,
            duration: 0,          // TODO
            address_1: BROADCAST, // RA
            address_2: BROADCAST, // TA
            address_3: BROADCAST, // DA
            sequence_control: SequenceControl::new()
                .with_fragment_number(1)
                .with_sequence_number(1), // TODO update these instead of hardcoding
            address_4: None,
            ..Default::default()
        },
        payload: Some(snapllc),
        _phantom: PhantomData,
    };
    let mut buf = [0x00u8; 1500];
    let len = buf.pwrite_with(data_frame, 0, false).unwrap();
    println!("{:?}", &buf[..len]);
}
