use std::env;

fn main() {
    let dc_net_message_length = env::var("DC_NET_MESSAGE_LENGTH")
        .unwrap_or_else(|_| "100".to_string()) // 设置默认值为100
        .parse::<u32>()
        .expect("Invalid DC_NET_MESSAGE_LENGTH value");

    // 在这里使用dc_net_message_length进行性能测试或其他操作
    println!("DC_NET_MESSAGE_LENGTH: {}", dc_net_message_length);
}
