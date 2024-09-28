use chrono::{DateTime, Utc};
use iced::widget::{button, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};

struct Message {
    timestamp: DateTime<Utc>,
    text: String,
}

#[derive(Default)]
pub struct Chat {
    messages: Vec<Message>,
    input: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    Send,
    Input(String),
}

impl Chat {
    pub fn update(&mut self, event: Event) {
        match event {
            Event::Send => {
                if !self.input.is_empty() {
                    self.messages.push(Message {
                        timestamp: Utc::now(),
                        text: self.input.clone(),
                    });
                    self.input.clear();
                }
            }
            Event::Input(new_input) => {
                self.input = new_input;
            }
        }
    }

    pub fn view(&self) -> Element<Event> {
        let messages = self
            .messages
            .iter()
            .fold(column![].spacing(10).padding(20), |col, msg| {
                col.push(
                    row![
                        text(msg.timestamp.format("%H:%M:%S").to_string())
                            .width(Length::Fixed(80.0)),
                        text(&msg.text)
                    ]
                    .spacing(20),
                )
            });

        let content = column![
            scrollable(messages).height(Length::Fill),
            row![
                text_input("message...", &self.input)
                    .on_input(Event::Input)
                    .padding(10),
                button("send").on_press(Event::Send).padding(10)
            ]
            .spacing(10)
            .padding(10)
        ]
        .spacing(20);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}
