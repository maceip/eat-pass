use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::schema::VerificationPolicy;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub left_id: String,
    pub right_id: String,
    pub same_class: bool,
    pub same_profile: bool,
    pub same_min_tier: bool,
    pub same_tier_details: bool,
    pub valid_until_changed: bool,
    pub added_allow: Vec<String>,
    pub removed_allow: Vec<String>,
    pub notes_changed: bool,
}

fn allow_id_hex(entry: &crate::schema::AllowEntry) -> Option<String> {
    entry
        .measurement
        .as_ref()
        .or(entry.app_id_hash.as_ref())
        .map(hex::encode)
}

pub fn diff(left: &VerificationPolicy, right: &VerificationPolicy) -> PolicyDiff {
    let left_set: HashSet<String> = left.allow.iter().filter_map(allow_id_hex).collect();
    let right_set: HashSet<String> = right.allow.iter().filter_map(allow_id_hex).collect();
    PolicyDiff {
        left_id: left.id.clone(),
        right_id: right.id.clone(),
        same_class: left.class.name == right.class.name
            && left.class.version == right.class.version,
        same_profile: left.evidence_profile == right.evidence_profile,
        same_min_tier: left.min_tier == right.min_tier,
        same_tier_details: left.allowed_tier_details == right.allowed_tier_details,
        valid_until_changed: left.valid_until != right.valid_until,
        added_allow: right_set.difference(&left_set).cloned().collect(),
        removed_allow: left_set.difference(&right_set).cloned().collect(),
        notes_changed: left.notes != right.notes,
    }
}

impl PolicyDiff {
    pub fn is_empty(&self) -> bool {
        self.same_class
            && self.same_profile
            && self.same_min_tier
            && self.same_tier_details
            && !self.valid_until_changed
            && self.added_allow.is_empty()
            && self.removed_allow.is_empty()
            && !self.notes_changed
    }
}
