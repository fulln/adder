use tracing::{info, Level};

fn main() {
    // 初始化默认订阅器（Subscriber），输出到 stderr
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO) // 设置全局日志级别
        .init();

    info!("This is an info message");
}
