# Deep Clean & Repair — bản thử nghiệm v1.2

**Trạng thái:** chưa phát hành production, chỉ thử nghiệm trên máy ảo/snapshot. Theo dõi toàn bộ lộ trình ở [Issue #1](https://github.com/orderthangtinstore-creator/licensefix/issues/1).

## Hệ thống đang chạy
Lệnh \`irm https://kwo.thangtinstore.com | iex\` hiện sử dụng GitHub \`main\` và mã SHA-256 cố định. **Không thay đổi** các tệp production trước khi kiểm thử và cập nhật hash launcher.

## Chạy thử từ nhánh tính năng
Tải về \`LicenseFix.ps1\` từ nhánh \`feature/deep-clean-v1.2\` vào máy test, kiểm tra file rồi chạy:

\`\`\`powershell
powershell -NoProfile -File .\LicenseFix.ps1 -Mode Deep
\`\`\`

## Có gì trong bản preview
- Menu \`6. Sua loi chuyen sau - preview\`; cũng hỗ trợ \`-Mode Deep\`.
- Quét thông tin cấp phép gốc, KMS Registry/WMI, và bổ sung tín hiệu từ cổng 1688, thư mục phần mềm kích hoạt, chữ ký sppsvc.exe, hosts Microsoft activation, DLL Office VFS.
- Menu dry-run hiển thị *chỉ* thay đổi Registry đã được xác minh, không sửa hệ thống.
- Thực hiện thao tác Registry low-risk thông qua sao lưu + xác nhận \`SUA\` và quét lại.
- Xuất JSON báo cáo mở rộng.
- Khi không có lỗi được phép sửa, \`RepairEligible=False\`.

## Giới hạn và yêu cầu nghiệm thu
- Đây **không phải** công cụ tự động sửa 19/19 nhóm; đa số nhóm chuyên sâu mới có tín hiệu tham khảo.
- Không thay timestamp \`data.dat/tokens.dat\`, không xóa log/history, không sửa key hay cấp phép để làm đẹp báo cáo.
- Một tên file, đường dẫn hay cổng mở không đủ chứng minh hoạt động trái phép; cần đối chiếu hash, chữ ký và bối cảnh IT.
- Tất cả máy domain joined / KMS Volume hoặc không xác minh được trạng thái cấp phép: không cho auto-repair.
- Trước khi merge: kiểm thử trên Windows 10/11 và Office, kiểm thử backup + rollback, cập nhật \`$lfExpectedSHA256\` trong launcher theo byte thực tế trên GitHub, kiểm thử URL \`kwo.thangtinstore.com\`.

**Mục tiêu cuối:** bảo đảm nguyên nhân thật được xử lý trên máy có bản quyền chính hãng và báo cáo có thể kiểm toán; không hứa mọi phiên bản bộ quét bên thứ ba đều trả màu xanh.