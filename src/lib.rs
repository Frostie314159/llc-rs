#![no_std]

use core::marker::PhantomData;

use ether_type::EtherType;
use macro_bits::{bit, check_bit};
use scroll::{
    ctx::{MeasureWith, TryFromCtx, TryIntoCtx},
    Endian, Pread, Pwrite,
};

const SNAP_CODE: u8 = 0xaa;

/// An unnumbered LLC frame, with the SNAP extension.
///
/// ## Structure
/// This struct represents an unnumbered LLC frame with a SNAP header.
/// This means, that DSAP and SSAP are equal to `0xaa`.
/// It is also expected, that the first two bits of the control field are set to one.
/// If any of these assumptions aren't met, an error will be returned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapLlcFrame<'a, Payload = &'a [u8]> {
    /// The organizationally unique identifier.
    ///
    /// In most cases this is just all zeroes.
    pub oui: [u8; 3],
    /// The type of the protocol carried in [Self::payload].
    ///
    /// NOTE: If the oui isn't all zeroes, this isn't actually an ether type.
    /// However this is quite uncommon, and an ether type is usually correct.
    /// If this isn't the case, use `self.ether_type.into_bits()` to get the raw [u16] protocol ID.
    pub ether_type: EtherType,
    /// The payload of the LLC frame.
    pub payload: Payload,
    pub _phantom: PhantomData<&'a ()>,
}
impl<'a> TryFromCtx<'a> for SnapLlcFrame<'a> {
    type Error = scroll::Error;
    fn try_from_ctx(from: &'a [u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let mut offset = 0;
        let dsap = from.gread::<u8>(&mut offset)?;
        let ssap = from.gread::<u8>(&mut offset)?;
        if dsap != SNAP_CODE || ssap != SNAP_CODE {
            return Err(scroll::Error::BadInput {
                size: offset,
                msg: "DSAP/SSAP wasn't set to 0xaa (SNAP).",
            });
        }
        let control = from.gread::<u8>(&mut offset)?;
        if !check_bit!(control, bit!(0, 1)) {
            return Err(scroll::Error::BadInput {
                size: offset,
                msg: "LLC control field wasn't set to unnumbered.",
            });
        }
        let oui = from.gread(&mut offset)?;
        let ether_type = EtherType::from_bits(from.gread_with(&mut offset, Endian::Little)?);
        let payload = &from[offset..];
        Ok((
            Self {
                oui,
                ether_type,
                payload,
                _phantom: PhantomData,
            },
            offset,
        ))
    }
}
impl<Payload: MeasureWith<()>> MeasureWith<()> for SnapLlcFrame<'_, Payload> {
    fn measure_with(&self, ctx: &()) -> usize {
        7 + self.payload.measure_with(ctx)
    }
}
impl<Payload: TryIntoCtx<Error = scroll::Error>> TryIntoCtx for SnapLlcFrame<'_, Payload> {
    type Error = scroll::Error;
    fn try_into_ctx(self, buf: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let mut offset = 0;
        buf.gwrite(SNAP_CODE, &mut offset)?;
        buf.gwrite(SNAP_CODE, &mut offset)?;
        buf.gwrite(0b11u8, &mut offset)?;
        buf.gwrite(self.oui.as_slice(), &mut offset)?;
        buf.gwrite_with(self.ether_type.into_bits(), &mut offset, Endian::Little)?;
        buf.gwrite(self.payload, &mut offset)?;
        Ok(offset)
    }
}
