use super::{entry::Entry, gadget::GadgetID, origin::Origin, value::ScalarOrVec};

#[derive(Clone, Debug, PartialEq)]
pub struct AnchoredKey(pub Origin, pub String);

impl AnchoredKey {
    pub fn eq(&self, ak: &AnchoredKey) -> bool {
        let AnchoredKey(self_origin, self_key) = self;
        let AnchoredKey(other_origin, other_key) = ak;
        (self_origin.origin_id == other_origin.origin_id) && (self_key == other_key)
    }
}

#[derive(Clone, Debug)]
pub enum Statement {
    None,
    ValueOf(AnchoredKey, ScalarOrVec),
    Equal(AnchoredKey, AnchoredKey),
    NotEqual(AnchoredKey, AnchoredKey),
    Gt(AnchoredKey, AnchoredKey),
    Contains(AnchoredKey, AnchoredKey),
    SumOf(AnchoredKey, AnchoredKey, AnchoredKey),
    ProductOf(AnchoredKey, AnchoredKey, AnchoredKey),
    MaxOf(AnchoredKey, AnchoredKey, AnchoredKey),
}

impl Statement {
    pub fn predicate(&self) -> &'static str {
        match self {
            Statement::None => "NONE",
            Statement::ValueOf(_, _) => "VALUEOF",
            Statement::Equal(_, _) => "EQUAL",
            Statement::NotEqual(_, _) => "NOTEQUAL",
            Statement::Gt(_, _) => "GT",
            Statement::Contains(_, _) => "CONTAINS",
            Statement::SumOf(_, _, _) => "SUMOF",
            Statement::ProductOf(_, _, _) => "PRODUCTOF",
            Statement::MaxOf(_, _, _) => "MAXOF",
        }
    }
    pub fn from_entry(entry: &Entry, this_gadget_id: GadgetID) -> Self {
        Statement::ValueOf(
            AnchoredKey(
                Origin::auto("_SELF".to_string(), this_gadget_id),
                entry.key.to_string(),
            ),
            entry.value.clone(),
        )
    }
}
