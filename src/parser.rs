use nom::{IResult, multi::length_data, number::streaming::be_u32, combinator::{map_res, into}, branch::alt};
use rasn::der;
use rasn_kerberos::{AsReq, AsRep, TgsRep, TgsReq, KrbError};

use crate::codec::KdcFrame;

pub fn kdc_frame(input: &[u8]) -> IResult<&[u8], KdcFrame> {
    alt((
        into(as_req),
        into(as_rep),
        into(tgs_req),
        into(tgs_rep),
        into(krb_error),
    ))(input)
}

fn as_req(input: &[u8]) -> IResult<&[u8], AsReq> {
    map_res(
        length_data(be_u32),
        |s| der::decode(s)
    )(input)
}

fn as_rep(input: &[u8]) -> IResult<&[u8], AsRep> {
    map_res(
        length_data(be_u32),
        |s| der::decode(s)
    )(input)
}

fn tgs_req(input: &[u8]) -> IResult<&[u8], TgsReq> {
    map_res(
        length_data(be_u32),
        |s| der::decode(s)
    )(input)
}

fn tgs_rep(input: &[u8]) -> IResult<&[u8], TgsRep> {
    map_res(
        length_data(be_u32),
        |s| der::decode(s)
    )(input)
}

fn krb_error(input: &[u8]) -> IResult<&[u8], KrbError> {
    map_res(
        length_data(be_u32),
        |s| der::decode(s)
    )(input)
}