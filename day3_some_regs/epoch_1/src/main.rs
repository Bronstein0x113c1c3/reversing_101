// #![feature(naked_functions)] // Bắt buộc phải bật tính năng này vì naked_functions chưa ổn định hoàn toàn
use std::arch::{asm, naked_asm};

fn main() {
    println!("Hello, world!");
    let mut a: i64 = 0;
    unsafe {
        asm!(
            "mov rdi, 6",
             "mov rsi, 4",
             "call {}",
             "mov {}, rax",
             sym add,         // Truyền symbol của hàm add vào vị trí {}
             // clobber_abi("C"),   // Bắt buộc: Bảo vệ các thanh ghi xung quan
             inout(reg) a


        );
    }
    println!("{}", a); // In ra 10
}

// 1. extern "C" bắt buộc hàm tuân theo ABI của hệ điều hành (Tham số 1: rdi, Tham số 2: rsi)
// 2. #[naked] ngăn Rust tự sinh mã quản lý ngăn xếp (stack), giữ nguyên trạng thái thanh ghi đầu vào

 fn add(a: i64, b: i64) -> i64 {
     let mut a_x:i64 = 0;
     let mut b_x:i64 = 0;
    unsafe {
       asm!(
            // Bước 1: Sao chép tham số thứ 1 (rdi) vào thanh ghi rax
            "mov {}, rdi",

             // Bước 2: Cộng tham số thứ 2 (rsi) vào thanh ghi rax
             "add {}, rsi",

             // Bước 3: Lệnh 'ret' bắt buộc phải có trong hàm #[naked] để quay về hàm main.
             // Theo chuẩn ABI, kết quả nằm trong thanh ghi 'rax' sẽ được coi là giá trị trả về của hàm.
            inout(reg) a_x,
            inout(reg) b_x,
             // options(noreturn) // Bắt buộc đối với hàm #[naked] để báo rằng assembly tự quản lý việc thoát hàm
        );

    }
    println!("{}",a_x);
    println!("{}",b_x);
    a_x+b_x
}
