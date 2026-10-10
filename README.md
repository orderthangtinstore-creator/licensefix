# LicenseFix v2.1.3-beta

Công cụ kiểm tra bản quyền Windows/Office và xử lý **từng lỗi có bằng chứng** trên Windows PowerShell 5.1. Bản này vẫn cần kiểm thử trên máy ảo trước khi dùng thao tác sửa trên máy thật.

## Chạy bản cục bộ

Mở `START_HERE.cmd`, hoặc chạy `LicenseFix.ps1` bằng Windows PowerShell 5.1. Chế độ `Scan` chỉ đọc; các thao tác sửa yêu cầu quyền Administrator và xác nhận riêng.

Launcher `launch.ps1` tải bản lõi theo commit phát hành đã ghim và kiểm tra SHA-256 trước khi chạy. Chỉ dùng launcher trực tuyến sau khi **cả** `LicenseFix.ps1` và `launch.ps1` của cùng phiên bản đã được phát hành. Lệnh `irm ... | iex` thực thi launcher tải từ Internet; hãy xem nội dung và ghim chính launcher vào commit khi cần mức bảo đảm cao hơn.

## Menu

- Menu chính: kiểm tra, xem **kế hoạch và lý do khóa sửa** (mục 2), mở **danh sách hành động sửa được hỗ trợ** (mục 3), xuất JSON, `sfc /verifyonly`, sửa lỗi chuyên sâu, và xem/nhập key chính hãng (mục 7). Màn hình kết quả chờ Enter rồi mới quay lại.
- Menu chuyên sâu: quét 19 nhóm rồi chọn ngay `2` (bằng chứng), `3` (kế hoạch), `4` (hành động sửa) hoặc `0` (quay về) tại màn hình kết quả. Các số này là lựa chọn thật, không còn bị lời nhắc Enter nuốt mất.
- Kế hoạch xử lý liệt kê các giá trị Registry đủ điều kiện, những dòng `hosts` đủ điều kiện, cùng **lý do bị khóa**. Các mục cần xem/chưa quét được trình bày riêng; không coi chúng là lỗi đã xác nhận.
- Mục `4` dẫn tới `R` (sao lưu rồi sửa đúng giá trị Registry đủ điều kiện), `H` (sao lưu rồi gỡ dòng hosts đủ điều kiện), `S` (chạy `sfc.exe /scannow`), `D` (chạy `dism.exe /Online /Cleanup-Image /RestoreHealth`) hoặc `K` (menu key). Với `R`/`H`, chương trình liệt kê thay đổi và hỏi `Y`; sau đó **tự sao lưu, xác minh bản sao và mới sửa**. Không cần tự sao lưu trước. Nếu không có mục đủ điều kiện hoặc sao lưu thất bại, chương trình giải thích và không sửa. Các lệnh hệ thống chạy từ PowerShell sau xác nhận; kết quả phụ thuộc trạng thái máy. Phần lớn mục “CẦN XEM” chỉ là việc cần kiểm tra, không có lệnh sửa an toàn để chạy hàng loạt.
- Hành động chuyên sâu: `R` sửa giá trị Registry đã được phép sau khi xuất `.reg`; `H` sao lưu và gỡ riêng những dòng `hosts` chỉ ánh xạ máy chủ kích hoạt Microsoft; `S` chạy `sfc /scannow`; `D` chạy `DISM /RestoreHealth`; `K` mở menu key. Mỗi hành động thay đổi hệ thống yêu cầu xác nhận. Dòng `hosts` có thêm tên miền khác được giữ lại để kiểm tra thủ công.

## Key Windows và Office

- Mục 7 ở menu chính hiển thị trạng thái cấp phép Windows/Office, kênh key, 5 ký tự cuối của key đang cài và key OEM nhúng BIOS (nếu đọc được). Dòng `KMS/Volume: False` cũ được thay bằng nhãn “Chưa thấy trong phạm vi quét”; đây không phải xác nhận key chính hãng.
- Trong menu key, mục 1 **làm mới cùng bảng thông tin** và hiện kết quả ngay sau khi đọc xong. Mục 7 riêng cho phép xem **đầy đủ key Windows OEM trong BIOS và key giải mã từ Registry** sau khi gõ `HIENTHI`. Key Registry có thể là key chung hoặc giá trị cũ; đừng coi nó là key đã mua chỉ vì hiển thị đủ 25 ký tự.
- Key đầy đủ chỉ hiện tại cửa sổ PowerShell sau xác nhận; LicenseFix không ghi key đó vào JSON hay bản sao. Ảnh chụp và bản ghi phiên PowerShell vẫn có thể chứa key, nên hãy giữ kín. Việc hiện đủ key Office/Microsoft 365 không được hứa hẹn vì cơ chế cấp phép khác nhau.
- Office được nhận diện từ sản phẩm Click-to-Run đang cài, phiên bản, kiến trúc, kênh cập nhật; các bản ghi WMI cấp phép được liệt kê riêng vì có thể còn lưu sản phẩm cũ. Kênh cập nhật và kiến trúc không quyết định loại key.
- Windows: nhập key 25 ký tự đang sở hữu trên máy cá nhân đã xác minh không thuộc domain/Volume; chương trình cảnh báo rằng key cũ có thể bị thay và không có bản sao đầy đủ để khôi phục. Nhập key và kích hoạt là hai bước riêng.
- Microsoft 365: dùng tài khoản/thuê bao; Office Retail: đổi key và liên kết tài khoản theo hướng dẫn Microsoft. Mục nhập key qua `ospp.vbs` chỉ mở khi nhận diện được **Office Volume đang cài**; công cụ có thể để lộ key tạm thời trong dòng lệnh của tiến trình. Chỉ dùng key do tổ chức cấp.
- “Đã kích hoạt”, kênh KMS/MAK hay dấu vết can thiệp là tín hiệu kỹ thuật; phần mềm không thể tự xác minh chứng từ mua và không kết luận một key cụ thể là “crack”.

## Giới hạn an toàn

- Dấu thời gian `data.dat`/`tokens.dat` chỉ là thông tin tham khảo, không chứng minh có crack và không được sửa để làm đẹp kết quả.
- Công cụ không tự gỡ product key, xóa kho SPP, xóa lịch sử PowerShell hay kết luận quyền sở hữu bản quyền từ trạng thái kích hoạt.
- Máy domain, KMS/Volume hợp lệ hoặc trạng thái cấp phép chưa xác minh có thể làm thao tác Registry bị khóa. Kế hoạch sẽ hiện lý do cụ thể.
- Sao lưu Registry/`hosts` giúp hoàn tác các thay đổi tương ứng; nó không thể tự phục hồi một product key đầy đủ nếu key bị thay hoặc gỡ. `SFC`/`DISM` không được bảo vệ bằng các bản sao này và có xác nhận riêng.
- Nhập key là thay đổi riêng, không được hoàn tác bằng bản sao Registry/`hosts`. Hãy giữ chứng từ và key gốc trước khi thay. Không lưu key vào báo cáo JSON.
- Chưa kiểm thử thao tác sửa trên Windows thật trong bản này. Hãy thử trên VM với cấu hình OEM/Retail, Microsoft 365, Office Volume và máy domain/KMS trước khi phát hành rộng.

## Nguồn tham khảo

Giao diện bằng chứng, luồng đi từ kết luận tới hành động và cách diễn giải key Registry được tham khảo từ [license.info.vn](https://github.com/tiennnict/license.info.vn) (Apache-2.0). LicenseFix có triển khai riêng tính năng giải mã `DigitalProductId`; kết quả không được dùng làm bằng chứng sở hữu bản quyền. Các quy tắc sửa tự động vẫn do LicenseFix xác định riêng.

Hướng dẫn kích hoạt tham khảo: [Microsoft 365/Office Retail](https://support.microsoft.com/en-us/microsoft-365-activation-licensing/office-install/where-to-enter-your-office-product-key), [Office Volume](https://learn.microsoft.com/en-us/deployoffice/vlactivation/tools-to-manage-volume-activation-of-office), [trạng thái Microsoft 365 vNext](https://learn.microsoft.com/en-gb/microsoft-365-apps/licensing-activation/vnextdiag).
