<div align="center">
  <img src="assets/banner.png" alt="WP-Hunter Banner" width="600"/>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey" alt="Platform">
</p>

<p align="center">
  <b>🌐 Dil Seçimi:</b><br>
  <a href="README.md"><img src="https://img.shields.io/badge/🇬🇧-English-blue" alt="English"></a>
  <a href="README.tr.md"><img src="https://img.shields.io/badge/🇹🇷-Türkçe-red" alt="Türkçe"></a>
  <a href="README.zh.md"><img src="https://img.shields.io/badge/🇨🇳-简体中文-yellow" alt="简体中文"></a>
  <a href="README.ar.md"><img src="https://img.shields.io/badge/🇸🇦-العربية-green" alt="العربية"></a>
  <a href="README.de.md"><img src="https://img.shields.io/badge/🇩🇪-Deutsch-orange" alt="Deutsch"></a>
</p>

WP-Hunter, **WordPress eklenti/tema keşif ve statik analiz (SAST) aracıdır**. Güvenlik araştırmacıları için tasarlanmış olup, eklentilerin metadata analizi, kurulum paternleri, güncelleme geçmişi ve derin **Semgrep destekli kaynak kod analizi** ile **güvenlik açığı olasılığını** değerlendirir.

## 🚀 Ana Özellikler

*   **Gerçek Zamanlı Web Dashboard**: Görsel tarama ve analiz için modern FastAPI tabanlı arayüz.
*   **Derin SAST Entegrasyonu**: Özel kural desteği ile entegre **Semgrep** taraması.
*   **Offline Keşif**: WordPress eklenti kataloğunun tamamını yerel SQLite veritabanına senkronize ederek anlık sorgulama.
*   **Risk Skorlama (VPS)**: WordPress ekosistemindeki "düşük asılı meyveleri" bulmak için sezgisel tabanlı puanlama.
*   **Tema Analizi**: WordPress tema deposunu tarama desteği.
*   **Güvenlik Güçlendirmesi**: Dahili SSRF koruması ve güvenli çalıştırma paternleri.

---

## 🖥️ Modern Web Dashboard

WP-Hunter artık görsel araştırmacılar için güçlü bir yerel dashboard sunuyor.

### Dashboard Galerisi

<table>
  <tr>
    <td width="50%">
      <b>Ana Arayüz</b><br>
      Sezgisel kontrollerle tarama parametrelerini yapılandırma
    </td>
    <td width="50%">
      <b>Tarama Geçmişi</b><br>
      Tüm önceki taramalarınızı takip edin ve yönetin
    </td>
  </tr>
  <tr>
    <td>
      <img src="assets/screenshots/dashboard-main.png" alt="Ana Dashboard" width="100%"/>
    </td>
    <td>
      <img src="assets/screenshots/scan-history.png" alt="Tarama Geçmişi" width="100%"/>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <b>Semgrep ile Tarama Detayları</b><br>
      Sorun takibi ile derin SAST analizi
    </td>
    <td width="50%">
      <b>Güvenlik Kural Setleri</b><br>
      OWASP ve özel Semgrep kurallarını yönetin
    </td>
  </tr>
  <tr>
    <td>
      <img src="assets/screenshots/scan-details.png" alt="Tarama Detayları" width="100%"/>
    </td>
    <td>
      <img src="assets/screenshots/security-rulesets.png" alt="Güvenlik Kural Setleri" width="100%"/>
    </td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <b>CLI Çıktısı</b><br>
      Güvenlik istihbaratı ile zengin terminal arayüzü
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <img src="assets/screenshots/cli-output.png" alt="CLI Çıktısı" width="100%"/>
    </td>
  </tr>
</table>

### Dashboard Yetenekleri:
*   **Gerçek Zamanlı Çalıştırma Sırası**: WebSocket üzerinden tarama sonuçlarını canlı izleyin.
*   **Entegre Semgrep**: Tek tıklama ile derin statik analiz çalıştırın.
*   **Tarama Geçmişi**: Önceki tarama oturumlarını kaydedin ve karşılaştırın.
*   **Favoriler Sistemi**: Manuel inceleme için "ilginç" hedefleri takip edin.
*   **Özel Kurallar**: Kendi Semgrep güvenlik kurallarınızı doğrudan UI'dan ekleyin ve yönetin.

---

## 📦 Kurulum

### Ön Koşullar
- Python 3.8 veya üzeri
- pip (Python paket yöneticisi)
- [Semgrep](https://semgrep.dev/docs/getting-started/) (İsteğe bağlı, derin analiz için)

### Kurulum Adımları
1. Repoyu klonlayın:
```bash
git clone https://github.com/xeloxa/WP-Hunter.git
cd WP-Hunter
```
2. Virtual environment oluşturun ve aktive edin:
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```
3. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

---

## 🛠️ Kullanım

### 1. Web Dashboard'u Başlatma (Önerilen)
```bash
python3 wp-hunter.py --gui
```
Arayüze `http://localhost:8080` adresinden erişin.

### 2. Veritabanı Senkronizasyonu (Offline Keşif için)
Yerel veritabanınızı eklenti metadata'sı ile doldurun:
```bash
# İlk 100 sayfayı senkronize et
python3 wp-hunter.py --sync-db --sync-pages 100

# Tüm WordPress kataloğunu senkronize et (~60k eklenti)
python3 wp-hunter.py --sync-all
```

### 3. Yerel Veritabanı Sorgulama
WordPress API'sine hitap etmeden yerel veritabanınızı sorgulayın:
```bash
# 10k+ kurulumu olan ve 2 yıldır güncellenmemiş eklentileri bul
python3 wp-hunter.py --query-db --min 10000 --abandoned

# "form" içeren ve düşük ratingli eklentileri ara
python3 wp-hunter.py --query-db --search "form" --sort-by rating --sort-order asc
```

### 4. CLI Tarama (Klasik Mod)
```bash
# Semgrep analizi etkinken 10 sayfa güncellenmiş eklenti tara
python3 wp-hunter.py --pages 10 --semgrep-scan --limit 20
```

---

## 🎯 Hunter Stratejileri

### 1. "Zombi" Avı (Yüksek Başarı Oranı)
Geniş kullanılan ama terk edilmiş eklentileri hedefleyin.
*   **Mantık:** Eski kod genellikle modern güvenlik standartlarından yoksundur (nonce eksikliği, zayıf sanitizasyon).
*   **Komut:** `python3 wp-hunter.py --abandoned --min 1000 --sort popular`

### 2. "Agresif" Mod
Yüksek hızlı, yüksek eşzamanlılıkta geniş kapsamlı keşif.
*   **Komut:** `python3 wp-hunter.py --aggressive --pages 200`

### 3. "Karmaşıklık" Tuzağı
Orta ölçekli eklentilerde karmaşık fonksiyonelliği (Dosya Yükleme, Ödemeler) hedefleyin.
*   **Komut:** `python3 wp-hunter.py --smart --min 500 --max 10000`

---

## 📊 VPS Mantığı (Güvenlik Açığı Olasılık Skoru)

Skor (0-100), **yamanmamış** veya **bilinmeyen** güvenlik açıklarının olasılığını yansıtır:

| Metrik | Koşul | Etki | Gerekçe |
|--------|-------|------|---------|
| **Kod Çürümesi** | > 2 Yıllık | **+40 puan** | Terk edilmiş kod kritik risktir. |
| **Saldırı Yüzeyi** | Riskli Etiketler | **+30 puan** | Ödeme, Yükleme, SQL, Formlar yüksek karmaşıklıktır. |
| **İhmal** | Destek < 20% | **+15 puan** | Kullanıcıları görmezden gelen geliştiriciler güvenlik raporlarını da görmezden gelir. |
| **Kod Analizi** | Tehlikeli Fonksiyonlar | **+5-25 puan** | `eval()`, `exec()` veya korumasız AJAX varlığı. |
| **Teknik Borç** | Eski WP | **+15 puan** | Son WordPress çekirdeği ile test edilmemiş. |
| **Bakım** | Güncelleme < 14g | **-5 puan** | Aktif geliştiriciler olumlu bir sinyaldir. |

---

## ⚖️ Yasal Sorumluluk Reddi

Bu araç yalnızca **güvenlik araştırması ve yetkili keşif** amaçları için tasarlanmıştır. Güvenlik profesyonellerinin ve geliştiricilerin saldırı yüzeylerini değerlendirmesine ve eklenti sağlığını analiz etmesine yardımcı olmayı amaçlar. Yazarlar herhangi bir kötüye kullanımdan sorumlu değildir. Güvenlikle ilgili herhangi bir faaliyet gerçekleştirmeden önce her zaman uygun yetkilendirmeye sahip olduğunuzdan emin olun.
