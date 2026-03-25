                    Incoming Email
                          │
                          ▼
                    API Endpoint
                  (/api/v1/analyze)
                          │
                          ▼
                    Whitelist Check
                          │
            ┌─────────────┴─────────────┐
            │                           │
            ▼                           ▼
      Trusted Domain              Unknown Domain
        (whitelist)                (not trusted)
            │                           │
            ▼                           ▼
   Protocol Verification        Protocol Verification
   (SPF / DKIM / DMARC)         (SPF / DKIM / DMARC)
            │                           │
            ▼                           ▼
      Risk Scoring                Input Guardrails
            │                    (Prompt Injection Filter)
            ▼                           │
      Response JSON                     ▼
            │                    LLM Content Analysis
            ▼                           │
 Publish reputation                     ▼
  (Redis pub/sub)                 Risk Scoring
                                        │
                                        ▼
                                   Response JSON
                                        │
                                        ▼
                              Publish reputation
                               (Redis pub/sub)

Cách cài đặt và chạy ứng dụng (Quick Start):
- Lệnh để build Docker image (như trong task 1.1 yêu cầu): docker build -t email-module .
- Khi đã báo chữ FINISHED ở bước build trên, bạn chạy container bằng lệnh sau: docker run -d -p 8000:8000 --name email_module_container email-module

Task 1.1:
Hướng dẫn kiểm tra (Testing/Verification):
- Mở Chrome/Edge và truy cập vào đường dẫn: http://localhost:8000/health
- Nếu giao diện trả về đoạn chữ {"status":"ok"} thì xin chúc mừng, API đã chạy thành công!

Task 1.2:
- Đảm bảo bạn đã vào thư mục SecureMail: cd SecureMail
- Chạy lệnh thực thi kiểm thử: python -m unittest email_module.tests.test_protocol
  + Nếu mọi thứ tốt đẹp, màn hình Terminal sẽ in ra 16 dấu chấm ................ và cuối cùng là chữ OK. 

Task 1.4:
Bạn có thể kiểm tra trực tiếp trong Redis bằng lệnh:
  docker exec -it redis-test redis-cli KEYS "whitelist:*"
  docker exec -it redis-test redis-cli GET "whitelist:google.com"
  danh sách whitelist đề xuất:
    company.com
    mail.company.com
    internal.company.com
    alerts.company.com
    notifications.company.com

    github.com
    gitlab.com
    bitbucket.org

    amazonaws.com
    cloudflare.com
    digitalocean.com

    slack.com
    notion.so
    atlassian.com

    stripe.com
    sendgrid.net
    mailgun.org

    auth0.com
    okta.com