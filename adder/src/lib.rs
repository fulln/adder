// 导出核心模块和工具模块
// 重导出外部crate的功能
pub use adder_core::{add, Rectangle};
pub use adder_utils::{calculate_area, is_square};

// 也可以添加一些本地功能来增强外部模块
pub fn enhanced_add(a: i32, b: i32, c: i32) -> i32 {
    // 使用adder-core中的add函数
    adder_core::add(adder_core::add(a, b), c)
}

