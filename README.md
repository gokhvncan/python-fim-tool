# 🛡️ FIM Ultimate - Python File Integrity Monitor

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**FIM Ultimate**, Python ile yazılmış hafif ve güçlü bir Dosya Bütünlük İzleyicisidir (File Integrity Monitor). Sisteminizdeki yetkisiz dosya değişikliklerini algılar, **VirusTotal API** ile tehdit istihbaratı sağlar ve anlık e-posta bildirimleri gönderir.

## 🚀 Özellikler (Features)
- **🔍 Gerçek Zamanlı Bütünlük Kontrolü:** Değişiklikleri algılamak için SHA-256 hash algoritması kullanır.
- **🦠 VirusTotal Entegrasyonu:** Değiştirilen dosyaların hash değerlerini otomatik olarak VirusTotal veritabanında tarar.
- **📧 E-posta Bildirimleri:** Kritik durumlarda SMTP üzerinden anlık uyarı gönderir.
- **📂 Baseline Yönetimi:** Güvenli durum (baseline) oluşturur ve sistemi buna göre kıyaslar.

## 🛠️ Kurulum ve Kullanım (Installation & Usage)

### 1. Projeyi İndirin (Clone)
Terminali açın ve aşağıdaki komutu girin:

```bash
git clone [https://github.com/gokhvncan/python-fim-tool.git](https://github.com/gokhvncan/python-fim-tool.git)
cd python-fim-tool
2. Gerekli Kütüphaneleri Yükleyin
Bash

pip install -r requirements.txt
3. Konfigürasyon (Configuration)
fim_tool.py dosyasını herhangi bir metin editörü ile açın ve aşağıdaki alanları kendi bilgilerinizle doldurun:

EMAIL_SENDER: Gönderici Gmail adresi.

EMAIL_PASSWORD: Google hesabınızdan alacağınız Uygulama Şifresi (App Password).

EMAIL_RECEIVER: Bildirimlerin gideceği e-posta adresi.

VIRUSTOTAL_API_KEY: VirusTotal'den alacağınız ücretsiz API anahtarı.

4. Aracı Çalıştırın
Bash

python fim_tool.py
📂 Proje Yapısı
Plaintext

python-fim-tool/
├── baselines/          # Oluşturulan hash veritabanları
├── fim_tool.py         # Ana yazılım dosyası
├── requirements.txt    # Gerekli kütüphaneler
├── security_events.log # Log kayıtları
└── README.md           # Dokümantasyon
⚠️ Yasal Uyarı (Disclaimer)
Bu araç eğitim ve savunma (Blue Team) amaçlı geliştirilmiştir.
