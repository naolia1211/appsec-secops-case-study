# AppSec / SecOps case study — Task 1

Ứng dụng Flask nhỏ để minh họa Build → Test → SAST JSON → Security Gate.
Task 1: đã có code và pipeline; xem `docs/validation.md` để biết phần đã chạy thực tế.
Task 2 và Task 3: planned. Các thư mục `k8s/` chỉ là placeholder. PDF làm sau.

## Cấu trúc

```text
.github/workflows/ci.yml    Build → Test → Security
app/                       JSON API, /health
tests/                     API tests và security gate tests
scripts/run_sast.py         Chạy scanner thật, chống dùng report cũ
scripts/security_gate.py    Parse JSON, policy và exit code
.semgrep.yml               Bộ rule local, được version control
reports/sast/               Report thực tế được sinh tại đây
Dockerfile                 Image chạy non-root, Waitress, port 8080
docker-compose.yml         Demo local
k8s/                       Placeholder cho Task 2
docs/                      Ghi chú validation
```

## Chạy ứng dụng và test

Cần Python 3.12 và Docker Desktop chạy Linux containers. Từ thư mục repo:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m pytest -q
waitress-serve --listen=127.0.0.1:18080 --call app:create_app
```

Mở `http://localhost:18080/health` hoặc `http://localhost:18080/api/greeting?name=Linh`.
Trên Linux/macOS, activate bằng `source .venv/bin/activate`.

```powershell
docker compose up --build -d
curl.exe --fail http://localhost:18080/health
docker compose down
```

## SAST và gate

Trên môi trường Python tương thích Semgrep (Linux/WSL được khuyến nghị):

```sh
python -m pip install -r requirements-security.txt
python scripts/run_sast.py
python scripts/security_gate.py reports/sast/semgrep.json
```

Scanner không dùng `--error`: findings được ghi vào JSON và **gate riêng** quyết định.
Wrapper block ngay nếu scanner exit khác 0. Không sử dụng `continue-on-error`.

| Điều kiện | Quyết định |
| --- | --- |
| ERROR: eval/exec, shell execution, debug mode | BLOCK, exit 1 |
| WARNING: MD5/SHA1 cần review theo ngữ cảnh | In finding, PASS nếu không có ERROR |
| INFO | In finding, PASS nếu không có ERROR |
| Scan lỗi, JSON lỗi/thiếu, severity lạ, không scan file nào | BLOCK, exit 2 |

Severity ở đây là policy của rule, không khẳng định tương đương CVSS.
Chọn Semgrep vì CLI đơn giản, rule nằm trong repo, JSON dễ parse, không cần server/token.
Scan sau build/test để lỗi build hoặc hành vi cơ bản được phát hiện trước; chỉ phát hành
artifact `approved-image-<commit SHA>` sau khi gate PASS. Task 2 dùng chính image này.
Artifact `built-image` chỉ là đầu vào trung gian chưa được duyệt.

Scan kết hợp 4 rule local với ruleset `p/python` từ Semgrep Registry. Ruleset Registry cần mạng và có thể thay đổi theo thời gian; đây không phải audit đầy đủ. Chưa quét dependencies,
container hoặc IaC. Không dùng findings giả để chứng minh scan thành công.
Report thật được upload bởi CI kể cả khi gate BLOCK; report local được gitignore.

## Demo BLOCK bằng scan thật

Tạo file tạm `app/demo_block.py` chỉ có `eval("1 + 1")`, chạy
`python scripts/run_sast.py`: Semgrep phải tìm thấy ERROR và gate trả exit 1.
Không import/chạy file này. Xóa file sau demo, chạy scan lại để trở về PASS.
Để demo warning, thay nội dung bằng `import hashlib` và `hashlib.md5(b"demo")`.
Tests của gate dùng dữ liệu synthetic chỉ để kiểm thử parser/policy.

## CI

Workflow chạy khi push, pull request hoặc manual dispatch. Build image một lần, lưu artifact,
test API/gate và smoke-test đúng image đó, rồi SAST và xuất image đã duyệt.
Không tự deploy hoặc push image ra registry. Chưa thiết lập branch protection: để chặn merge,
cần đặt job Security làm required check trên GitHub.

Tham khảo: https://docs.semgrep.dev/cli-reference và
https://docs.github.com/en/actions/tutorials/build-and-test-code/python.

## Bằng chứng chạy trên GitHub Actions

Xem [hướng dẫn đọc bằng chứng CI](docs/ci-evidence.md).
Nhánh `main` giữ code sạch. Nhánh `codex/demo-sast-block` chỉ phục vụ demo gate chặn
finding thật; không merge nhánh demo vào main.
