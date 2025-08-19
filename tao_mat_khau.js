    // tao_mat_khau.js
    const bcrypt = require('bcryptjs');

    // Mật khẩu mặc định cần mã hóa
    const password = '1';
    
    // Độ phức tạp của mã hóa, 10 là tiêu chuẩn
    const saltRounds = 10;

    bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) {
            console.error("Lỗi khi mã hóa:", err);
            return;
        }
        console.log("============================================================");
        console.log("Đây là chuỗi password_hash của bạn cho mật khẩu '1':");
        console.log(hash);
        console.log("============================================================");
        console.log("Hãy sao chép chuỗi dài ở trên và dán vào lệnh SQL ở Bước 2.");
    });