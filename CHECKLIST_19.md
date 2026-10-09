# LicenseFix v1.0.0 – đối chiếu 19 nhóm kiểm tra License Info

Đối chiếu về **phạm vi chức năng**, không sao chép kết luận hay bảo đảm 19/19 mục luôn xanh. Nguồn tham khảo: [tiennnict/license.info.vn](https://github.com/tiennnict/license.info.vn) (Apache-2.0).

| # | Nhóm kiểm tra | Hỗ trợ trong LicenseFix 1.0 | Can thiệp |
|---|---|---|---|
| 1 | Thông tin Windows và OEM BIOS | Một phần (trạng thái Windows), chưa đọc key BIOS | Không |
| 2 | Windows WMI/SPP | Có | Không gỡ key |
| 3 | Office WMI / OSPP | Một phần; Microsoft 365 vNext có thể không hiển thị | Không gỡ key |
| 4 | KMS Windows / Office | Có: Registry và WMI | Xóa riêng giá trị Registry bất thường khi đủ điều kiện |
| 5 | Cổng KMS 1688, giả lập cục bộ | Chưa | Không |
| 6 | Tệp/thư mục công cụ kích hoạt | Chưa | Không |
| 7 | Chữ ký và toàn vẹn SPP | Chưa; có lệnh SFC /verifyonly thủ công | Không |
| 8 | TSforge / KMS38 Windows | Chưa | Không |
| 9 | Digital License / GenuineTicket | Chưa | Không |
| 10 | Rearm | Chưa | Không |
| 11 | Scheduled Tasks | Có: nhận diện một số tên cần kiểm tra | Không tự xóa |
| 12 | Defender / exclusions | Chưa | Không |
| 13 | PowerShell history | Chưa | Không xóa lịch sử |
| 14 | Hosts chặn kích hoạt | Chưa | Không |
| 15 | Thời gian `data.dat` / `tokens.dat` | Có: hiển thị thông tin | Không thay đổi timestamp / kho SPP |
| 16 | Ohook Office | Chưa | Không |
| 17 | KMS Office / OSPP / ClickToRun | Có: Registry, WMI | Xóa riêng giá trị Registry khi đủ điều kiện |
| 18 | Retail sang Volume Office | Chưa | Không |
| 19 | TSforge Office | Chưa | Không |

**Giới hạn an toàn:** công cụ khóa chức năng sửa nếu Windows chưa xác nhận Licensed, có sản phẩm KMS/Volume, máy thuộc domain hoặc không xác minh được domain, hay một giấy phép Office phát hiện được chưa được xác nhận hợp lệ. Nó chỉ tạo đề xuất từ bằng chứng hiện tại, sao lưu mọi khóa Registry trước khi thay đổi, đòi gõ `SUA`, và quét lại.

**Không dùng để che giấu:** không sửa timestamps, không xóa lịch sử hay dữ liệu cấp phép nhằm đánh lừa công cụ kiểm tra. Không khẳng định nguồn gốc pháp lý của bản quyền.

**Chưa kiểm thử trên Windows thật:** đây là bản preview cần chạy `Scan` trong VM trước khi sử dụng `Repair`.
