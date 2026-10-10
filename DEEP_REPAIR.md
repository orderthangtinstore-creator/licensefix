# LicenseFix v2.1.4-beta — sửa lỗi chuyên sâu

Bản thử nghiệm kiểm tra **19 nhóm** tương ứng phạm vi License Info. Không có nghĩa đã triển khai đầy đủ toàn bộ quy tắc gốc; phần nào chưa đủ bằng chứng sẽ được báo **NOT_CHECKED**, thay vì tô xanh. Mục chỉ mang số liệu tham khảo được báo **INFO**.

Sau khi chọn quét, màn hình kết quả nhận trực tiếp `2` để xem chi tiết, `3` để xem kế hoạch, `4` để chọn lệnh xử lý và `0` để về menu chuyên sâu. Các lựa chọn này không cần nhấn Enter trước.

## Cách mở

Đọc mã nguồn rồi mở `START_HERE.cmd`, hoặc chạy `LicenseFix.ps1 -Mode Deep` trong Windows PowerShell 5.1. Menu số **6** cũng mở chế độ này. Bản beta cần được thử trên máy ảo trước khi sửa trên máy thật.

`launch.ps1` tải bản lõi từ commit phát hành đã ghim và kiểm tra SHA-256 của `LicenseFix.ps1`. Hãy đọc launcher trước khi chạy; bản thân launcher trực tuyến không được ghim vào một commit.

## Hành động

1. Quét và phân loại các kiểm tra PASS/WARN/REVIEW/NOT_CHECKED/INFO.
2. Xem kế hoạch Registry/`hosts`, lý do khóa sửa và đề xuất cho từng mục.
3. Chọn `1`, xem các giá trị Registry KMS đủ điều kiện, rồi nhấn `Y`. Công cụ tự xuất và xác minh toàn bộ khóa liên quan trước khi xóa đúng các giá trị đã liệt kê. Nếu sao lưu thất bại thì dừng và giải thích, không sửa. Chính sách `NoGenTicket` chỉ để xem xét, không tự xóa.
4. Chọn `2`, xem những dòng `hosts` đủ điều kiện, rồi nhấn `Y`. Công cụ tự sao lưu, so khớp bản sao và mới gỡ riêng những dòng chỉ ánh xạ máy chủ kích hoạt Microsoft; dòng có tên miền khác được giữ nguyên.
5. Chọn `3` cho SFC hoặc `4` cho DISM; cả hai có xác nhận `Y` riêng. Bản sao Registry/`hosts` không hoàn tác được hai lệnh này.
6. Xuất báo cáo JSON tại `C:\ProgramData\LicenseFix\Reports`.
7. Chọn `5` để mở menu key riêng, xem 5 ký tự cuối của key, sản phẩm Office đang cài và chọn cách kích hoạt chính thức. Nhập key không được khôi phục bằng bản sao Registry/`hosts`.
8. Chọn `6`, nhập số mục quét 1–19: công cụ hiện bằng chứng, hướng xử lý và chỉ cho chọn số hành động liên quan. Mục chưa có phương án an toàn sẽ không mở lệnh sửa tự động.

Ở menu chính, mục 2 chỉ xem kế hoạch; mục 3 mở menu sửa bằng số sau khi quét nếu cần. Không phải sao lưu thủ công trước khi chọn `1`/`2`. Nếu không có mục đủ điều kiện sửa, chương trình hiện lý do; trạng thái “CẦN XEM” hoặc “CHƯA QUÉT” riêng lẻ chưa đủ để cho phép sửa tự động. Rearm và dấu thời gian SPP chỉ là **THÔNG TIN**, không phải lỗi cần sửa.

**Không** sửa đổi timestamp `data.dat`, `tokens.dat`, can thiệp registry để che giấu giấy phép, xóa lịch sử kiểm toán, xóa key OEM/Volume, hoặc bảo đảm 19/19 màu xanh.

Các nhóm 5, 6, 8–13, 15, 16 và 19 hiện chỉ có bằng chứng hoặc hướng kiểm tra thủ công. LicenseFix chưa có bộ xác minh đủ tin cậy để tự gỡ dịch vụ, task, ngoại lệ Defender hay DLL chỉ dựa vào tên/đường dẫn. Nhóm 4/17 chỉ sửa giá trị Registry đủ điều kiện; nhóm 14 chỉ sửa dòng `hosts` đủ điều kiện; nhóm 7 có SFC/DISM tùy chọn. Menu hiện rõ giới hạn này trước khi hỏi xác nhận.

## Giới hạn và checklist

- Các nhóm chưa có phép kiểm đầy đủ: TSforge, GenuineTicket, PowerShell history, Office Retail/Volume, TSforge Office.
- Một số nhóm khác chỉ có heuristic hữu hạn, ví dụ đường dẫn công cụ cũ, VFS Office và cổng KMS; một PASS không chứng nhận toàn bộ tình trạng cấp phép.
- Máy domain hoặc đang dùng KMS/Volume hợp pháp bị khóa sửa tự động như v1.
- Cần thử trên Windows VM có tài khoản OEM/Retail, Microsoft 365, Office perpetual, KMS doanh nghiệp hợp pháp và KMS cấu hình tồn dư. Báo cáo sau sửa phải có bằng chứng trước/sau.
- Chỉ phát hành chính thức sau kiểm thử PowerShell 5.1, UI tương tác và trạng thái bản quyền thực tế.

LicenseFix độc lập với Microsoft và tác giả [License Info](https://github.com/tiennnict/license.info.vn).
