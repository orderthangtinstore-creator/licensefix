# LicenseFix v2.1.4-beta – đối chiếu 19 nhóm kiểm tra License Info

Đối chiếu về **phạm vi chức năng**, không sao chép kết luận hay bảo đảm 19/19 mục luôn xanh. Nguồn tham khảo: [tiennnict/license.info.vn](https://github.com/tiennnict/license.info.vn) (Apache-2.0).

| # | Nhóm kiểm tra | Hỗ trợ trong LicenseFix 2.1.4-beta | Can thiệp |
|---|---|---|---|
| 1 | Thông tin Windows và OEM BIOS | Quét sâu đọc trạng thái Windows; menu key đọc 5 ký tự cuối key OEM BIOS nếu có | Không |
| 2 | Windows WMI/SPP | Có | Không gỡ key |
| 3 | Office WMI / OSPP | Một phần; menu key đọc sản phẩm Click-to-Run và có lối xem vNext | Không gỡ key |
| 4 | KMS Windows / Office | Có: Registry và WMI | Xóa riêng giá trị Registry bất thường khi đủ điều kiện |
| 5 | Cổng KMS 1688, giả lập cục bộ | Kiểm tra cổng lắng nghe; chưa xác minh tiến trình | Không |
| 6 | Tệp/thư mục công cụ kích hoạt | Kiểm tra một số vị trí phổ biến; chưa kết luận từ tên | Không |
| 7 | Chữ ký và toàn vẹn SPP | Kiểm tra chữ ký một tệp đại diện; có SFC/DISM thủ công | SFC/DISM sau xác nhận |
| 8 | TSforge / KMS38 Windows | Chưa | Không |
| 9 | Digital License / GenuineTicket | Chưa | Không |
| 10 | Rearm | Hiển thị số liệu WMI để tham khảo | Không |
| 11 | Scheduled Tasks | Có: nhận diện một số tên cần kiểm tra | Không tự xóa |
| 12 | Defender / exclusions | Kiểm tra một số tên ngoại lệ; chưa xét lịch sử Defender | Không |
| 13 | PowerShell history | Chưa | Không xóa lịch sử |
| 14 | Hosts chặn kích hoạt | Kiểm tra tên miền kích hoạt Microsoft | Gỡ riêng dòng đủ điều kiện sau sao lưu và xác nhận |
| 15 | Thời gian `data.dat` / `tokens.dat` | Có: hiển thị thông tin | Không thay đổi timestamp / kho SPP |
| 16 | Ohook Office | Kiểm tra hai thư mục VFS phổ biến; chưa xác minh chữ ký DLL | Không |
| 17 | KMS Office / OSPP / ClickToRun | Có: Registry, WMI | Xóa riêng giá trị Registry khi đủ điều kiện |
| 18 | Retail sang Volume Office | Không tự phân tích lịch sử chuyển đổi; menu key tách sản phẩm đang cài khỏi bản ghi WMI cũ | Không tự chuyển kênh |
| 19 | TSforge Office | Chưa | Không |

**Giới hạn an toàn:** công cụ khóa sửa Registry nếu Windows chưa xác nhận Licensed, có sản phẩm KMS/Volume, máy thuộc domain hoặc không xác minh được domain, hay một giấy phép Office phát hiện được chưa xác nhận hợp lệ. Chính sách `NoGenTicket` không tự xóa. Chỉ các giá trị Registry KMS đủ điều kiện mới được xử lý sau khi chọn `1`, xác nhận `Y`, sao lưu và xác minh. Sửa `hosts` có điều kiện riêng qua mục `2` và xác nhận `Y`.

**Không dùng để che giấu:** không sửa timestamps, không xóa lịch sử hay dữ liệu cấp phép nhằm đánh lừa công cụ kiểm tra. Không khẳng định nguồn gốc pháp lý của bản quyền.

**Menu sửa:** mục 2 ở menu chính trình bày kế hoạch và lý do khóa, mục 3 cho chọn hành động bằng số `1–6`. Mục `6` nhận số hạng mục quét `1–19` và dẫn tới hành động liên quan hoặc nêu rõ vì sao chỉ có hướng kiểm tra thủ công. Nhãn **THÔNG TIN** không cần sửa; **CHƯA QUÉT** không được coi là đạt. Key Windows/Office chỉ được nhập sau xác nhận riêng, với điều kiện phù hợp và key do người dùng sở hữu.

**Chưa kiểm thử thao tác sửa hoặc nhập key thật:** các kiểm tra chỉ đọc và đường đi menu đã chạy trên Windows PowerShell 5.1; thao tác thay đổi cần kiểm thử trên VM trước khi dùng rộng rãi.
