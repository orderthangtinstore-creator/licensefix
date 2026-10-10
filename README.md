# LicenseFix v2.0.2-beta

Công cụ kiểm tra bản quyền Windows/Office và xử lý **từng lỗi có bằng chứng** trên Windows PowerShell 5.1. Bản này vẫn cần kiểm thử trên máy ảo trước khi dùng thao tác sửa trên máy thật.

## Chạy bản cục bộ

Mở `START_HERE.cmd`, hoặc chạy `LicenseFix.ps1` bằng Windows PowerShell 5.1. Chế độ `Scan` chỉ đọc; các thao tác sửa yêu cầu quyền Administrator và xác nhận riêng.

Launcher `launch.ps1` tải mã từ nhánh `main` và kiểm tra SHA-256 trước khi chạy. Chỉ dùng launcher trực tuyến sau khi **cả** `LicenseFix.ps1` và `launch.ps1` của cùng phiên bản đã được phát hành. Lệnh `irm ... | iex` thực thi launcher tải từ Internet; hãy xem nội dung và ghim commit khi cần mức bảo đảm cao hơn.

## Menu

- Menu chính: kiểm tra, xem đề xuất, sửa Registry có sao lưu, xuất JSON, `sfc /verifyonly`, và sửa lỗi chuyên sâu.
- Menu chuyên sâu: quét 19 nhóm, xem bằng chứng theo số mục, xem kế hoạch xử lý, chọn hành động sửa, xuất báo cáo.
- Kế hoạch xử lý liệt kê các giá trị Registry đủ điều kiện, những dòng `hosts` đủ điều kiện, cùng **lý do bị khóa**. Các mục cần xem/chưa quét được trình bày riêng; không coi chúng là lỗi đã xác nhận.
- Hành động chuyên sâu: `R` sửa giá trị Registry đã được phép sau khi xuất `.reg`; `H` sao lưu và gỡ riêng những dòng `hosts` chỉ ánh xạ máy chủ kích hoạt Microsoft; `S` chạy `sfc /scannow`; `D` chạy `DISM /RestoreHealth`. Mỗi hành động yêu cầu xác nhận. Dòng `hosts` có thêm tên miền khác được giữ lại để kiểm tra thủ công.

## Giới hạn an toàn

- Dấu thời gian `data.dat`/`tokens.dat` chỉ là thông tin tham khảo, không chứng minh có crack và không được sửa để làm đẹp kết quả.
- Công cụ không tự gỡ product key, xóa kho SPP, xóa lịch sử PowerShell hay kết luận quyền sở hữu bản quyền từ trạng thái kích hoạt.
- Máy domain, KMS/Volume hợp lệ hoặc trạng thái cấp phép chưa xác minh có thể làm thao tác Registry bị khóa. Kế hoạch sẽ hiện lý do cụ thể.
- Sao lưu Registry/`hosts` giúp hoàn tác các thay đổi tương ứng; nó không thể tự phục hồi một product key đầy đủ nếu key bị thay hoặc gỡ.
- Chưa kiểm thử thao tác sửa trên Windows thật trong bản này. Hãy thử trên VM với cấu hình OEM/Retail, Microsoft 365, Office Volume và máy domain/KMS trước khi phát hành rộng.

## Nguồn tham khảo

Giao diện bằng chứng và luồng đi từ kết luận tới hành động được nghiên cứu từ [license.info.vn](https://github.com/tiennnict/license.info.vn) (Apache-2.0). LicenseFix không nhúng mã nguồn của dự án đó và không đồng nhất mọi heuristic hay thao tác xóa của họ với quy tắc sửa tự động của mình.
