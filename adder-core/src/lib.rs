// 核心功能模块

// 简单的加法函数
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

// 矩形结构体
pub struct Rectangle {
    pub width: u32,
    pub height: u32,
}

impl Rectangle {
    pub fn can_hold(&self, other: &Rectangle) -> bool {
        self.width > other.width && self.height > other.height
    }
}
