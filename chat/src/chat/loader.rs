use std::time::Duration;

use gpui::{
    black, bounce, div, ease_in_out, percentage, svg, white, Animation, AnimationExt, IntoElement,
    Length, ParentElement, Pixels, Render, Styled, Transformation, ViewContext,
};

pub struct Loader {}

impl Loader {
    pub fn new(_cx: &mut ViewContext<Self>) -> Self {
        Loader {}
    }
}

impl Render for Loader {
    fn render(&mut self, _cx: &mut ViewContext<Self>) -> impl IntoElement {
        div().flex().flex_col().size_full().justify_around().child(
            div().flex().flex_row().w_full().justify_around().child(
                div()
                    .flex()
                    .bg(white())
                    .size(Length::Definite(Pixels(30.0).into()))
                    .justify_center()
                    .items_center()
                    .child(
                        svg()
                            .size_8()
                            .path("icon/arrow_circle.svg")
                            .text_color(black())
                            .with_animation(
                                "image_circle",
                                Animation::new(Duration::from_secs(2))
                                    .repeat()
                                    .with_easing(bounce(ease_in_out)),
                                |svg, delta| {
                                    svg.with_transformation(Transformation::rotate(percentage(
                                        delta,
                                    )))
                                },
                            ),
                    ),
            ),
        )
    }
}
