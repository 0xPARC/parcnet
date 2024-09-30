// use std::sync::{mpsc, Arc, RwLock};

// use chrono::{DateTime, Utc};
// use futures::{Stream, StreamExt};
// use iced::widget::{self, button, column, container, row, scrollable, text, text_input};
// use iced::{Element, Length, Task};
// use iroh_net::endpoint::SendStream;
// use iroh_net::key::SecretKey;
// use iroh_net::{endpoint::get_remote_node_id, Endpoint};
// use tracing::{info, warn};

// const CHAT_ALPN: &[u8] = b"pkarr-discovery-demo-chat";

// #[derive(Clone)]
// struct Message {
//     timestamp: DateTime<Utc>,
//     text: String,
// }

// #[derive(Default)]
// pub struct Chat {
//     messages: Arc<RwLock<Vec<Message>>>,
//     input: String,
// }

// #[derive(Debug, Clone)]
// pub enum Event {
//     Send,
//     Input(String),
// }

// pub async fn listen() -> Result<(impl Stream<Item = Message>, SendStream)> {
//     let secret_key = SecretKey::generate();
//     let node_id = secret_key.public();
//     let builder = iroh_net::discovery::pkarr::dht::DhtDiscovery::builder()
//         .dht(true)
//         .n0_dns_pkarr_relay();
//     let discovery = builder.secret_key(secret_key.clone()).build()?;
//     let endpoint = Endpoint::builder()
//         .alpns(vec![CHAT_ALPN.to_vec()])
//         .secret_key(secret_key)
//         .discovery(Box::new(discovery))
//         .bind()
//         .await?;
//     let zid = pkarr::PublicKey::try_from(node_id.as_bytes())?.to_z32();

//     info!("listening on {}", node_id);
//     info!("pkarr z32: {}", zid);
//     info!("see https://app.pkarr.org/?pk={}", zid);

//     let (tx, rx) = mpsc::channel();

//     let incoming = endpoint
//         .accept()
//         .await
//         .ok_or(anyhow::anyhow!("bo incoming connection"))?;
//     let connecting = incoming
//         .accept()
//         .map_err(|err| anyhow::anyhow!("incoming connection failed: {}", err))?;

//     let connection = connecting.await?;
//     let remote_node_id = get_remote_node_id(&connection)?;
//     println!("got connection from {}", remote_node_id);

//     let (writer, mut reader) = connection.accept_bi().await?;

//     tokio::spawn(async move {
//         loop {
//             let mut buffer = vec![0; 1024];
//             match reader.read(&mut buffer).await {
//                 Ok(None) => break, // Connection closed
//                 Ok(Some(n)) => {
//                     let message = String::from_utf8_lossy(&buffer[..n]).to_string();
//                     info!("received message: {}", message);
//                     let _ = tx
//                         .send(Message {
//                             timestamp: Utc::now(),
//                             text: message,
//                         })
//                         .await;
//                 }
//                 Err(_) => break, // Read error
//             }
//         }
//     });

//     Ok((stream, writer))
// }

// impl Chat {
//     pub fn new() -> (Self, Task<Event>) {
//         let c = Chat::default();
//         let messages = c.messages.clone();
//         tokio::spawn(Self::listen(messages));
//         return (c, Task::batch([widget::focus_next()]));
//     }

//     pub fn update(&mut self, event: Event) {
//         match event {
//             Event::Send => {
//                 if !self.input.is_empty() {
//                     // self.messages.push(Message {
//                     //     timestamp: Utc::now(),
//                     //     text: self.input.clone(),
//                     // });
//                     //self.input.clear();
//                 }
//             }
//             Event::Input(new_input) => {
//                 self.input = new_input;
//             }
//         }
//     }

//     pub fn view(&self) -> Element<Event> {
//         let messages = self.messages.clone();
//         let messages_read = messages.read().unwrap();
//         let messages =
//             messages_read
//                 .iter()
//                 .cloned()
//                 .fold(column![].spacing(10).padding(20), |col, msg| {
//                     col.push(
//                         row![
//                             text(msg.timestamp.format("%H:%M:%S").to_string())
//                                 .width(Length::Fixed(80.0)),
//                             text(msg.text)
//                         ]
//                         .spacing(20),
//                     )
//                 });

//         let content = column![
//             scrollable(messages).height(Length::Fill),
//             row![
//                 text_input("message...", &self.input)
//                     .on_input(Event::Input)
//                     .padding(10),
//                 button("send").on_press(Event::Send).padding(10)
//             ]
//             .spacing(10)
//             .padding(10)
//         ]
//         .spacing(20);

//         container(content)
//             .width(Length::Fill)
//             .height(Length::Fill)
//             .into()
//     }
// }
