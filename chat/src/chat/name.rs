use gpui::{div, rgba, IntoElement, ParentElement, Render, Styled, ViewContext};
use iroh::net::key::PublicKey;
use std::sync::Arc;

use crate::logic::Logic;

pub struct Name {
    pubkey: PublicKey,
    logic: Arc<Logic>,
}

impl Name {
    pub fn new(_cx: &mut ViewContext<Self>, pubkey: PublicKey, logic: Arc<Logic>) -> Self {
        Name { pubkey, logic }
    }
}

impl Render for Name {
    fn render(&mut self, _cx: &mut ViewContext<Self>) -> impl IntoElement {
        let name = self.logic.get_name(&self.pubkey);
        div().text_color(rgba(0x00000050)).child(name)
    }
}
