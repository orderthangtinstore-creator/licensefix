# LicenseFix Deep Repair 2.0 beta

Bản thử nghiệm kiểm tra **19 nhóm** tương ứng phạm vi License Info. Không có nghĩa đã triển khai đầy đủ toàn bộ quy tắc gốc; phần nào chưa đủ bằng chứng sẽ được báo **NOT_CHECKED**, thay vì tô xanh.

## Dùng thử trước khi phát hành chính thức

Tải và đọc `LicenseFix.ps1` từ nhánh `feature/deep-repair-v2`, sau đó thử trên Windows 10/11 VM. Menu số **6** hoặc tham số `-Mode Deep` mở chế độ mới. Launcher beta tại:

```powershell
irm https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/feature/deep-repair-v2/launch.ps1 | iex
```

*Lệnh có iex thực thi script tải từ Internet. Chỉ dùng khi bạn kiểm soát và tin cậy nội dung.* Domain `kwo.thangtinstore.com` vẫn đang phục vụ launcher chính trên nhánh `main` cho tới khi kiểm thử và merge.

## Hành động

1. Quét và phân loại các kiểm tra PASS/WARN/REVIEW/NOT_CHECKED.
2. Xem kế hoạch sửa Registry (dry-run).
3. Sao lưu và chỉ xóa các giá trị KMS/NoGenTicket đã đủ điều kiện theo chính sách an toàn của v1, có xác nhận gõ `SUA`, báo cáo JSON trước/sau.
4. SFC/DISM theo xác nhận riêng, không tự kích hoạt.
5. Xuất báo cáo JSON tại `C:\ProgramData\LicenseFix\Reports`.

**Không** sửa đổi timestamp `data.dat`, `tokens.dat`, can thiệp registry để che giấu giấy phép, xóa lịch sử kiểm toán, xóa key OEM/Volume, hoặc bảo đảm 19/19 màu xanh.

## Giới hạn và checklist

- Các nhóm chưa có phép kiểm đầy đủ: TSforge, GenuineTicket, PowerShell history, Office Retail/Volume, TSforge Office.
- Một số nhóm khác chỉ có heuristic hữu hạn, ví dụ đường dẫn công cụ cũ, VFS Office và cổng KMS; một PASS không chứng nhận toàn bộ tình trạng cấp phép.
- Máy domain hoặc đang dùng KMS/Volume hợp pháp bị khóa sửa tự động như v1.
- Cần thử trên Windows VM có tài khoản OEM/Retail, Microsoft 365, Office perpetual, KMS doanh nghiệp hợp pháp và KMS cấu hình tồn dư. Báo cáo sau sửa phải có bằng chứng trước/sau.
- Chỉ phát hành chính thức sau kiểm thử PowerShell 5.1, UI tương tác và trạng thái bản quyền thực tế.

LicenseFix độc lập với Microsoft và tác giả [License Info](https://github.com/tiennnict/license.info.vn).
