// 可以直接测试导入的外部模块功能
#[test]
fn external_modules_direct() {
    use adder_core;
    use adder_utils;

    let value = adder_core::add(10, 20);
    assert_eq!(30, value);

    let is_square = adder_utils::is_square(5, 5);
    assert!(is_square);
}
