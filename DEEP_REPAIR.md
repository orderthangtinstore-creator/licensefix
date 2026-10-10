# LicenseFix v2.1.0-beta — sửa lỗi chuyên sâu

Bản thử nghiệm kiểm tra **19 nhóm** tương ứng phạm vi License Info. Không có nghĩa đã triển khai đầy đủ toàn bộ quy tắc gốc; phần nào chưa đủ bằng chứng sẽ được báo **NOT_CHECKED**, thay vì tô xanh.

## Cách mở

Đọc mã nguồn rồi mở `START_HERE.cmd`, hoặc chạy `LicenseFix.ps1 -Mode Deep` trong Windows PowerShell 5.1. Menu số **6** cũng mở chế độ này. Bản beta cần được thử trên máy ảo trước khi sửa trên máy thật.

`launch.ps1` tải mã từ nhánh `main` và kiểm tra SHA-256 của `LicenseFix.ps1`. Hãy đọc launcher trước khi chạy; bản thân launcher trực tuyến không được ghim vào một commit.

## Hành động

1. Quét và phân loại các kiểm tra PASS/WARN/REVIEW/NOT_CHECKED.
2. Xem kế hoạch Registry/`hosts`, lý do khóa sửa và đề xuất cho từng mục.
3. Sao lưu và chỉ xóa các giá trị Registry KMS đã đủ điều kiện, sau xác nhận gõ `SUA`. Chính sách `NoGenTicket` chỉ để xem xét, không tự xóa.
4. Sao lưu rồi gỡ riêng những dòng `hosts` chỉ ánh xạ máy chủ kích hoạt Microsoft, sau xác nhận gõ `HOSTS`; dòng có tên miền khác được giữ nguyên.
5. SFC/DISM theo xác nhận riêng, không tự kích hoạt.
6. Xuất báo cáo JSON tại `C:\ProgramData\LicenseFix\Reports`.
7. Mở menu key riêng để xem 5 ký tự cuối của key, sản phẩm Office đang cài và chọn cách kích hoạt chính thức. Nhập key không được khôi phục bằng bản sao Registry/`hosts`.

Ở menu chính, mục 2 mở trực tiếp kế hoạch xử lý; mục 3 mở danh sách hành động sau khi quét nếu cần. Nếu không có giá trị Registry đủ điều kiện sửa, chương trình hiện lý do thay vì quay về âm thầm.

**Không** sửa đổi timestamp `data.dat`, `tokens.dat`, can thiệp registry để che giấu giấy phép, xóa lịch sử kiểm toán, xóa key OEM/Volume, hoặc bảo đảm 19/19 màu xanh.

## Giới hạn và checklist

- Các nhóm chưa có phép kiểm đầy đủ: TSforge, GenuineTicket, PowerShell history, Office Retail/Volume, TSforge Office.
- Một số nhóm khác chỉ có heuristic hữu hạn, ví dụ đường dẫn công cụ cũ, VFS Office và cổng KMS; một PASS không chứng nhận toàn bộ tình trạng cấp phép.
- Máy domain hoặc đang dùng KMS/Volume hợp pháp bị khóa sửa tự động như v1.
- Cần thử trên Windows VM có tài khoản OEM/Retail, Microsoft 365, Office perpetual, KMS doanh nghiệp hợp pháp và KMS cấu hình tồn dư. Báo cáo sau sửa phải có bằng chứng trước/sau.
- Chỉ phát hành chính thức sau kiểm thử PowerShell 5.1, UI tương tác và trạng thái bản quyền thực tế.

LicenseFix độc lập với Microsoft và tác giả [License Info](https://github.com/tiennnict/license.info.vn).
