# LicenseFix v2.0.1-beta — tối ưu hiệu năng và giao diện

Bản vá thử nghiệm cho Windows PowerShell 5.1+.

## Thay đổi

- Menu chính và chuyên sâu tiếng Việt, tên chức năng ngắn gọn.
- Quét chuyên sâu hiển thị 19 dòng trạng thái thay vì mọi bằng chứng ngay lập tức.
- Mục **2 — Xem chi tiết theo số mục** để đọc bằng chứng và đề xuất khi cần.
- Ghi số giây quét nền/chuyên sâu. Trong khi quét, hiển thị ba giai đoạn: cấp phép, Registry, tác vụ/dịch vụ.
- Dùng WMI có bộ lọc và tự quay về truy vấn đầy đủ nếu không có kết quả hoặc lỗi.
- ClickToRun chỉ kiểm tra khóa chính + nhánh trực tiếp; phạm vi kiểm tra không đầy đủ được ghi chú. Các nhánh SPP vẫn quét sâu tối đa 3.000 khóa, báo ghi chú nếu chưa quét hết.
- Tái sử dụng kết quả trong cùng phiên khi xem chi tiết/xuất báo cáo/lập kế hoạch, chỉ quét lại sau khi Registry thực sự được thay đổi.
- SFC/DISM và xóa Registry vẫn yêu cầu xác nhận; không xóa key, nhật ký kiểm toán hay giả timestamp.

## Vì sao font vẫn lớn trên một số máy?

PowerShell không điều khiển cỡ chữ của Windows Terminal. Nhấn **Ctrl + -** để giảm cỡ chữ; đặt **Settings → Profiles → Appearance → Font size** khoảng 11–13 tùy màn hình.

## Kiểm thử & giới hạn

- Kiểm thử CI PowerShell 5.1 phải xác minh cú pháp, SHA-256, kết quả Deep 19 nhóm, menu tóm tắt và chế độ xem chi tiết.
- Chưa có đo đối chứng trực tiếp trên máy người dùng. Thời gian thực tế phụ thuộc tốc độ WMI, Registry và dịch vụ hệ thống.
- Bản này ưu tiên tốc độ và khả năng đọc, **không** có nghĩa đã kiểm tra 100% 19 quy tắc của License Info; trạng thái REVIEW và NOT_CHECKED được giữ trung thực.
- Chưa được xác nhận an toàn khi dùng sửa chữa tự động trong môi trường doanh nghiệp ngoài các cơ chế được hỗ trợ từ v1.
