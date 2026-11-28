# Önyükleme Sağlığı (BİL461 dönem projesi)

Bu depo, [pardus/pardus-about](https://github.com/pardus/pardus-about)
uygulamasının bir fork'udur. TOBB ETÜ BİL461 İşletim Sistemleri dersi
kapsamında, uygulamaya salt okunur bir **Önyükleme Sağlığı** modülü
eklenmektedir.

Kök dizindeki `README.md` Pardus'un özgün dosyasıdır ve değiştirilmez.
Projeye ait her belge bu `docs/` klasöründedir.

## Ne yapıyor

Secure Boot açıkken Pardus'un başlatılamaması (örneğin "Security
Violation" hatası) kullanıcıların kendi başına yorumlayamadığı bir
durumdur. Modül, UEFI önyükleme zincirini (shim, GRUB, çekirdek) ve
Secure Boot, MOK, SBAT durumunu inceleyip sonucu Türkçe, anlaşılır bir
özet olarak pardus-about içinde gösterir. Sisteme hiçbir şey yazmaz.

- Hedef sürüm: Pardus 25.2 (Debian 13 tabanlı)
- Dil ve araçlar: Python 3, GTK3 (PyGObject), polkit
- Ek paket bağımlılığı yok: `mokutil` ve `sbverify` gerekmez

## Ekip

| Üye | Sorumluluk |
|---|---|
| Alime Feyza Şahin | Yetkisiz okuma kodu, PE ayrıştırıcı, kural motoru, birim testleri |
| Sena Çoban | GTK arayüzü, yetki akışı, mesajlar ve çeviri, sistem raporu satırı, `.deb` paketi, pull request |
| Kıvanç Taş | Yetkili yardımcı araç ve polkit, test ortamı, doğrulama ve karşılaştırma testleri |

Kod incelemesi döngüseldir: Feyza'nın pull request'lerini Kıvanç,
Kıvanç'ınkileri Sena, Sena'nınkileri Feyza inceler.

## İş takibi

- [Issue listesi](https://github.com/afeyza/pardus-about/issues): her iş
  için sorumlu, bağımlılık ve tamamlanma ölçütü
- [Proje panosu](https://github.com/users/afeyza/projects/1): Todo /
  In Progress / Done

Bir pull request bir issue'yu kapatıyorsa açıklamasına `Closes #N`
yazılır. O issue'yu bekleyen biri varsa açıklamada etiketlenir
(örneğin `@ghkivanc #8'e başlayabilirsin`).

## Belgeler

| Belge | İçerik |
|---|---|
| [BIL461_Proje_Onerisi.pdf](BIL461_Proje_Onerisi.pdf) | Onaylanan proje önerisi: problem, mevcut araçlar, çözüm yaklaşımı, başarı ölçütleri, riskler, görev dağılımı |
| [mimari.md](mimari.md) | Dosya yapısı, bileşenler arası JSON şeması, mimari kararlar ve gerekçeleri |

## Dallar

| Dal | Amaç |
|---|---|
| `master` | Pardus'un özgün kodu; değiştirilmez |
| `onyukleme-sagligi` | Ortak çalışma dalı; bitmiş ve incelenmiş kod burada toplanır |
| kişisel dallar | Her iş kendi dalında yapılır ve pull request ile ortak dala birleştirilir |

## Testleri çalıştırma

Depo kökünden:

```bash
python3 -m unittest discover -s tests -v
```

Testler yalnızca standart kütüphaneyi kullanır ve Pardus kurulu olmayan
bir makinede de çalışır. ISO'dan çıkarılan gerçek EFI dosyaları
`tests/fixtures/efi/` altına konursa onlarla yapılan testler de çalışır.

## Kod kuralları

Pardus'un kodlama kurallarına uyulur (kök `README.md` sonundaki bölüm):

- Python kodu PEP 8 uyumlu olur (`pycodestyle` ile denetlenir).
- Değişken adları alt çizgili ve açık yazılır: `package_size`, `pkg_sz` değil.
- GTK bileşen kimlikleri `ui_<ad>_<tür>` biçimindedir, örneğin
  `ui_boot_health_box`.
- Mümkünse standart kütüphane tercih edilir.

## Lisans

Özgün proje gibi GPL-3.0 (kök dizindeki `LICENSE`).
