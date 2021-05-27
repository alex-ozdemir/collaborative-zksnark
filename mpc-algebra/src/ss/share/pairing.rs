use ark_ec::PairingEngine;

use std::fmt::Debug;

use super::field::{ScalarShare, ExtFieldShare};
use super::group::GroupShare;

pub trait PairingShare<E: PairingEngine>:
    Clone + Copy + Debug + 'static + Send + Sync + PartialEq + Eq
{
    type FrShare: ScalarShare<E::Fr>;
    type FqShare: ScalarShare<E::Fq>;
    type FqeShare: ExtFieldShare<E::Fqe>;
    // TODO: wrong. Need to fix the PairingEngine interface though..
    type FqkShare: ExtFieldShare<E::Fqk>;
    //type FqkShare: GroupShare<MulFieldGroup<E::Fqk, E::Fr>, ScalarShare = Self::FrShare>;
    type G1AffineShare: GroupShare<E::G1Affine, ScalarShare = Self::FrShare>;
    type G2AffineShare: GroupShare<E::G2Affine, ScalarShare = Self::FrShare>;
    type G1ProjectiveShare: GroupShare<E::G1Projective, ScalarShare = Self::FrShare>;
    type G2ProjectiveShare: GroupShare<E::G2Projective, ScalarShare = Self::FrShare>;
    fn g1_share_aff_to_proj(g: Self::G1AffineShare) -> Self::G1ProjectiveShare;
    fn g1_share_proj_to_aff(g: Self::G1ProjectiveShare) -> Self::G1AffineShare;
    fn g2_share_aff_to_proj(g: Self::G2AffineShare) -> Self::G2ProjectiveShare;
    fn g2_share_proj_to_aff(g: Self::G2ProjectiveShare) -> Self::G2AffineShare;
}

