# Chứng minh pipeline chạy thật trên GitHub Actions

Mở repository → Actions → **Task 1 - Build Test Security**.

## Lần PASS trên main

1. Trang run hiển thị commit SHA và runner GitHub-hosted.
2. Build xanh: mở log `Build application image` để thấy Docker build.
3. Test xanh: mở log unit tests và smoke test HTTP từ image đã build.
4. Security xanh: mở log Semgrep và gate, xem số file/rule/findings thực tế.
5. Ở Summary, xem bảng kết quả gate và tải artifact `sast-report`.
6. Artifact `approved-image-<SHA>` chỉ được xuất sau khi gate pass.

## Lần BLOCK trên codex/demo-sast-block

Nhánh demo có file `app/demo_block.py` chứa hàm dùng eval, chỉ để scanner đọc;
ứng dụng không import hoặc gọi hàm đó. Đây là source fixture cố ý có lỗi,
không phải report JSON giả.

Build và Test vẫn phải xanh. Security đỏ vì finding ERROR, gate exit 1.
JSON `sast-report` vẫn tải được dù job fail. Không có artifact `approved-image-<SHA>`.
Không merge hoặc triển khai nhánh demo. Main vẫn là bản dùng tiếp cho Task 2.

## Evidence nên giữ cho PDF sau này

- Link run PASS và BLOCK, commit SHA của từng run.
- Ảnh Summary của hai lần chạy.
- Log test và log gate có exit code.
- JSON tải trực tiếp từ artifact của mỗi run.

Artifacts SAST lưu 30 ngày; nên tải về trước khi hết hạn. Bằng chứng local không thay thế
run GitHub-hosted. Gate fail chặn job/artifact; chặn merge còn cần branch protection
với required status check, chưa cấu hình trong task này.

## Runs đã xác minh (2026-09-20)

| Case | Run | Commit | Kết quả |
| --- | --- | --- | --- |
| PASS | [35487185141](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487185141) | `01162b80ddc9e9098167c33f0257351d72a73630` | Build, Test, Security success |
| BLOCK | [35487187658](https://github.com/naolia1211/appsec-secops-case-study/actions/runs/35487187658) | `84b8ef57495a5cebd52a11834dbd5f00141a3f8d` | Build/Test success, Security failure |

- Cả hai run sử dụng 155 rule. Main: 4 file, 0 finding, PASS.
- Demo: 5 file, 1 ERROR `python-dynamic-evaluation`, gate exit 1.
- Hai run đều có artifact `sast-report`; chỉ PASS có `approved-image-01162b80ddc9e9098167c33f0257351d72a73630`.
- Lần chạy ban đầu gặp race khi container chưa sẵn sàng; bản sửa thêm retry HTTP có thời hạn và đã pass trên GitHub.
- Commit tài liệu sau các run chỉ cập nhật bằng chứng, không thay đổi code đã kiểm thử.
