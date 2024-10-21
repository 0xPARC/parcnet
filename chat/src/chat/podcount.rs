use gpui::{div, IntoElement, ParentElement, Render, ViewContext};
use std::sync::Arc;

use crate::logic::Logic;

pub struct Podcount {
    logic: Arc<Logic>,
}

impl Podcount {
    pub fn new(cx: &mut ViewContext<Self>, logic: Arc<Logic>) -> Self {
        let mut pod_watch = logic.get_pod_watch();
        cx.spawn(|view, mut cx| async move {
            while pod_watch.changed().await.is_ok() {
                let _ = cx.update(|cx| {
                    view.update(cx, |_, cx| {
                        cx.notify();
                    })
                });
            }
        })
        .detach();
        Podcount { logic }
    }
}

impl Render for Podcount {
    fn render(&mut self, _cx: &mut ViewContext<Self>) -> impl IntoElement {
        let podcount = self.logic.get_num_pods();
        div().child(format!("{} pods", podcount)).into_element()
    }
}
