# Önyükleme Sağlığı modülü: mimari

Bu belge modülün dosya yapısını, bileşenler arasındaki veri biçimini ve
alınan mimari kararları gerekçeleriyle birlikte kaydeder. Şema değişirse
önce bu belge güncellenir.

Durum: taslak, grup onayı bekliyor (13 Kasım 2026; bulgu kimlikleri
21 Kasım 2026'da eklendi).

## Bileşenler ve sorumlular

```
src/util/boothealth/
    pe.py          PE ayrıştırıcı                               (Feyza)
    efivars.py     EFI değişken okuyucu                         (Feyza)
    collect.py     yetkisiz toplama: değişkenler, çekirdek, paketler (Feyza)
    rules.py       kural motoru                                 (Feyza)
    messages.py    mesaj kimliği -> çevrilebilir metin          (Sena)
src/BootHealthHelper.py    pkexec ile çalışan yardımcı araç     (Kıvanç)
polkit/                    yardımcı araç için yeni eylem        (Kıvanç)
tests/
    pe_builder.py          testler için sentetik PE üretici
    test_pe.py             PE ayrıştırıcı testleri
    fixtures/efi/          ISO'dan çıkarılan gerçek dosyalar
    fixtures/roots/        senaryo başına sahte kök dizin
```

## Veri akışı

1. `collect.py` yetkisiz okunabilen her şeyi toplar: EFI değişkenleri,
   `/boot` altındaki çekirdek, `dpkg` paket durumu.
2. Kullanıcı izin verirse arayüz `BootHealthHelper.py` aracını `pkexec`
   ile çalıştırır. Araç parametre almaz, EFI bölümündeki sabit yollardaki
   dosyaları `pe.py` ile ayrıştırır, sonucu standart çıktıya JSON olarak
   yazar ve hiçbir şey yazmaz.
3. İki çıktı tek bir durum nesnesinde birleşir. Yetki verilmediyse `esp`
   alanı `null` kalır.
4. `rules.py` durum nesnesini bulgu listesine çevirir.
5. `messages.py` bulgu kimliklerini kullanıcıya gösterilecek metne çevirir.

## Durum nesnesi (şema sürümü 1)

```json
{
  "schema": 1,
  "live_session": false,
  "firmware": { "uefi": true, "secure_boot": false, "setup_mode": false },
  "shim": {
    "validation_disabled": null,
    "mok_hashes": [],
    "sbat_level": { "shim": 4, "grub": 3, "grub.debian": 4 }
  },
  "kernel": {
    "path": "/boot/vmlinuz-6.12.0",
    "status": "ok",
    "pe": { "signed": true, "signature_count": 1 }
  },
  "packages": { "shim-signed": true, "grub-efi-amd64-signed": false },
  "esp": {
    "path": "/boot/efi",
    "files": [
      {
        "role": "grub",
        "path": "/boot/efi/EFI/pardus/grubx64.efi",
        "status": "ok",
        "pe": {
          "signed": false,
          "signature_count": 0,
          "authenticode_sha256": "9f2c...",
          "sbat": [ { "component": "grub", "generation": 5 } ],
          "vendor_cert_present": null
        }
      }
    ],
    "errors": []
  }
}
```

Kurallar:

- **Üç durumlu değerler.** Her mantıksal alan `true`, `false` ya da `null`
  olabilir. `null`, "okunamadı ya da bilinmiyor" demektir. Kural motoru
  `null` gördüğünde uyarı üretmez; kontrolün yapılamadığını bildirir.
- **`status`** dört değerden biridir: `ok`, `missing`, `unreadable`,
  `malformed`. `status` `ok` değilse `pe` alanı `null` olur.
- **`role`** üç değerden biridir: `shim`, `grub`, `fallback`
  (`EFI/BOOT/BOOTX64.EFI`).
- **`pe` nesnesi** `pe.parse()` çıktısının aynısıdır. `sbat` ve
  `vendor_cert_present`, ilgili bölüm dosyada yoksa `null` olur.
- **`sbat_level`** `SbatLevelRT` değişkeninin bileşen adı → en düşük
  kabul edilen sürüm sözlüğüdür. Değişkendeki `sbat,1,<tarih>` başlık
  satırı alınmaz; `grub_sbat_revoked` kuralı yalnızca bileşen adına ve
  sürüme bakar. Değişken okunamazsa `null` olur (28 Kasım 2026).
- Şemaya alan eklemek serbesttir; alan silmek ya da anlamını değiştirmek
  `schema` sayısını artırmayı gerektirir.

## Kural motorunun çıktısı

```json
{
  "live_session": false,
  "overall": "warning",
  "findings": [
    { "id": "sb_off_grub_unsigned", "level": "warning", "evidence": "signature_absent" },
    { "id": "check_unavailable", "level": "info", "evidence": null, "subject": "SbatLevelRT" }
  ]
}
```

- **`findings`**: uyan her bulgu listelenir. Senaryolar birbirini
  dışlamaz; örneğin Setup Mode açık ve GRUB imzasız aynı anda olabilir.
- **`overall`**: listedeki en ciddi seviye (`ok` < `info` < `warning`).
  Arayüzün en üstünde gösterilen genel durum budur.
- **`live_session`**: canlı oturumda `true` olur. Bulgular değişmez;
  arayüz her mesajın yanına "bu kurulu sistem değil" notunu bu alandan
  ekler.

Bulgu nesnesinin alanları:

- **`level`**: `ok` (sağlıklı), `info` (bilgi), `warning` (uyarı).
- **`evidence`**: mesajın kurabileceği en güçlü iddiayı belirler.
  - `signature_absent`: dosyada imza tablosu yok.
  - `signature_present`: imza tablosu var; imza doğrulanmadı.
  - `booted_with_secure_boot`: sistem Secure Boot açıkken açıldı, yani
    *açılışta kullanılan* zincir firmware ve shim tarafından doğrulandı.
    Diskte şu an duran dosyalar hakkında tek başına bir şey söylemez.
  - `state`: bulgu bir EFI değişkenine ya da sistem durumuna dayanıyor,
    imzaya değil.
  - `verified`: kriptografik olarak doğrulandı. Yalnızca isteğe bağlı
    imza doğrulama işlevi (#21) yazılırsa kullanılır.
  - `null`: bulgu bir kanıta dayanmıyor (`esp_not_checked`,
    `check_unavailable`).
- **`subject`** (isteğe bağlı): bulgunun ilgili olduğu kontrol, örneğin
  `grub`, `kernel`, `SbatLevelRT`. Yalnızca `check_unavailable` kullanır.
- **`variant`** (isteğe bağlı): yalnızca `shim_validation_disabled`
  kullanır; birleştirme kuralı 5'e bakınız.
- Kural motoru metin döndürmez. Metinler `messages.py` içinde İngilizce
  yazılır ve `po/tr.po` ile Türkçeye çevrilir; depodaki diğer metinler de
  böyle çalışıyor.

## Bulgu kimlikleri

Durum: taslak, #2'de grup onayı bekliyor (21 Kasım 2026).

Her bulgu için kullanıcıya **tek** bir adım önerilir (gerekçe: karar 5).
Bir bulgu için tek ve net bir öneri yazılamıyorsa o bulgu yanlış
tanımlanmış demektir.

| Kimlik | Seviye | Kanıt | Önerilen tek adım | Geri alma |
|---|---|---|---|---|
| `legacy_boot` | bilgi | `state` | İşlem gerekmiyor; bu kipte Secure Boot kullanılamaz. | – |
| `sb_off_chain_signed` | bilgi | `signature_present` | Secure Boot'u açabilirsiniz. | Açılmazsa BIOS'tan kapatın. |
| `sb_off_grub_unsigned` | uyarı | `signature_absent` | Secure Boot'u açmayın. | Açtıysanız BIOS'tan kapatın. |
| `sb_off_kernel_unsigned` | uyarı | `signature_absent` | Secure Boot'u açmayın. | Açtıysanız BIOS'tan kapatın. |
| `sb_on_chain_ok` | sağlıklı | `booted_with_secure_boot` | İşlem gerekmiyor. | – |
| `sb_on_grub_mok_hash` | bilgi | `booted_with_secure_boot` | GRUB güncellemesinden sonra, yeniden başlatmadan önce bu sayfayı kontrol edin. | Açılmazsa BIOS'tan Secure Boot'u kapatın. |
| `sb_on_grub_changed` | uyarı | `signature_absent` | Bir sonraki açılış başarısız olabilir; yeniden başlatmadan önce bunu bilin. | Açılmazsa BIOS'tan Secure Boot'u kapatın. |
| `sb_on_kernel_unsigned` | uyarı | `signature_absent` | Bir sonraki açılış başarısız olabilir; yeniden başlatmadan önce bunu bilin. | Açılmazsa BIOS'tan Secure Boot'u kapatın. |
| `shim_validation_disabled` | uyarı | `state` | GRUB ve çekirdek imzalıysa doğrulamayı yeniden açın; imzasızsa olduğu gibi bırakın. | `mokutil --disable-validation` |
| `setup_mode` | uyarı | `state` | BIOS'ta Secure Boot anahtarlarını fabrika ayarına döndürün. | BIOS'tan anahtarları yeniden silin. |
| `grub_sbat_revoked` | uyarı | `state` | Secure Boot'u açmayın; açıksa yeniden başlatmadan önce sistemi güncelleyin. | Açılmazsa BIOS'tan Secure Boot'u kapatın. |
| `esp_not_checked` | bilgi | `null` | Tam sonuç için "EFI bölümünü de incele"ye basın. | – |
| `check_unavailable` | bilgi | `null` | İşlem gerekmiyor; sonuç bu kontrol olmadan verildi. | – |

Koşullar:

| Kimlik | Ne zaman üretilir |
|---|---|
| `legacy_boot` | `/sys/firmware/efi` yok |
| `sb_off_chain_signed` | Secure Boot kapalı; shim, GRUB ve çekirdek imzalı |
| `sb_off_grub_unsigned` | Secure Boot kapalı, GRUB imzasız |
| `sb_off_kernel_unsigned` | Secure Boot kapalı, çekirdek imzasız |
| `sb_on_chain_ok` | Açılış Secure Boot ile yapıldı **ve** diskteki GRUB ile çekirdek imzalı |
| `sb_on_grub_mok_hash` | Secure Boot açık, GRUB imzasız ama Authenticode özeti `MokListRT`'de |
| `sb_on_grub_changed` | Secure Boot açık, GRUB imzasız ve özeti `MokListRT`'de yok (açılıştan sonra diskteki GRUB değişmiş olmalı) |
| `sb_on_kernel_unsigned` | Secure Boot açık, çalışan çekirdeğin diskteki dosyası imzasız (açılıştan sonra değişmiş olmalı) |
| `shim_validation_disabled` | `MokSBStateRT` = 1 |
| `setup_mode` | `SetupMode` = 1 |
| `grub_sbat_revoked` | GRUB'un `.sbat` bölümündeki bileşenlerden herhangi birinin sürümü, `SbatLevelRT`'deki aynı bileşenin en düşük sürümünden küçük |
| `esp_not_checked` | Kullanıcı yetki vermedi; `esp` alanı `null` |
| `check_unavailable` | Bir bulgu için gereken değer `null`, ya da dosya `missing`, `unreadable` veya `malformed` |

Birleştirme kuralları:

1. `legacy_boot` varsa başka hiçbir bulgu üretilmez.
2. `sb_off_chain_signed` ile `sb_off_grub_unsigned` / `sb_off_kernel_unsigned`
   birbirini dışlar. `sb_off_chain_signed` yalnızca üç dosyanın durumu da
   biliniyorsa üretilir; biri bilinmiyorsa onun yerine `check_unavailable`
   çıkar.
3. `sb_on_chain_ok`, `sb_on_grub_mok_hash` ve `sb_on_grub_changed` birbirini
   dışlar. `sb_on_kernel_unsigned` bunların yanına eklenebilir, ama
   `sb_on_chain_ok` ile birlikte çıkmaz.
4. `shim_validation_disabled`, `setup_mode` ve `grub_sbat_revoked`
   diğerlerinden bağımsızdır, yanlarına eklenir.
5. `shim_validation_disabled` için hangi önerinin gösterileceğini kural
   motoru imza durumuna bakarak seçer; kullanıcıya seçenek sunulmaz.
   Seçim bulgunun `variant` alanındadır: `chain_signed` (GRUB ve çekirdek
   imzalı, doğrulamayı yeniden açın), `chain_unsigned` (biri imzasız,
   olduğu gibi bırakın) ya da `null` (bilinmiyor; mesaj temkinli olanı,
   yani "olduğu gibi bırakın"ı göstermeli).

28 Kasım 2026'da eklenen birleştirme kuralları (#5):

6. **ESP okunmadıysa zincir hakkında iddia yok.** Secure Boot açık ve
   `esp` `null` ise `sb_on_chain_ok` üretilmez, `esp_not_checked` çıkar.
   GRUB'u bilmeden "her şey yolunda" demek delilsiz bir iddia olurdu.
7. **ESP okunmadıysa çekirdek yine değerlendirilir.** Çekirdek imzasızsa
   `sb_off_kernel_unsigned` / `sb_on_kernel_unsigned` `esp` olmadan da
   çıkar. GRUB ve shim için ayrıca `check_unavailable` üretilmez;
   `esp_not_checked` ikisini de kapsar.
8. **`secure_boot` `null` ise** hiçbir `sb_*` bulgusu üretilmez;
   `check_unavailable` (konu `SecureBoot`) çıkar. 4. kuraldaki bağımsız
   bulgular yine değerlendirilir.
9. **shim doğrulaması kapalıysa** (`validation_disabled` `true`) `sb_on_*`
   bulguları üretilmez. shim doğrulama yapmadıysa "Secure Boot ile
   açıldı" zincir hakkında kanıt değildir; durumu
   `shim_validation_disabled` anlatır.
10. **`validation_disabled` `null` ise** `check_unavailable` yalnızca
    Secure Boot açıkken çıkar. Kapalıyken shim zaten hiçbir şeyi
    doğrulamaz, bu değeri bilmemek sonucu değiştirmez.
11. **Her konu bir kez.** Aynı konu için `check_unavailable` ve
    `esp_not_checked` listede en fazla bir kez geçer.
12. **Sıra.** Bulgular en ciddiden en hafife sıralanır (`warning`,
    `info`, `ok`); arayüz listeyi bu sırayla gösterebilir.

`check_unavailable` için kullanılan `subject` değerleri: `SecureBoot`,
`SetupMode`, `MokSBStateRT`, `MokListRT`, `SbatLevelRT`, `kernel`, `grub`,
`shim`, `grub_sbat` (GRUB'da `.sbat` bölümü yok).

Test ve demo kuralı: her bulgu kimliği için `tests/fixtures/roots/`
altında en az bir sahte kök dizin bulunur (#8). Böylece her senaryo
birim testinde sınanır ve demoda Secure Boot açık bir makine
gerektirmeden gösterilebilir.

Öneriden sapmalar (sapmalar belgesine işlenecek):

- Önerideki "Secure Boot kapalı, GRUB veya çekirdek imzasız" senaryosu
  ikiye bölündü (`sb_off_grub_unsigned`, `sb_off_kernel_unsigned`), çünkü
  iki durumun nedeni ve çözümü farklı.
- Önerideki tabloda olmayan dört bulgu eklendi: `sb_on_grub_changed`,
  `sb_on_kernel_unsigned` (28 Kasım), `esp_not_checked`,
  `check_unavailable`.
- `evidence` alanına `booted_with_secure_boot` ve `state` değerleri
  eklendi.

## Kararlar ve gerekçeleri

### 1. Modül `src/util/boothealth/` alt paketi olarak yazılır

Depodaki diğer yardımcı modüller (`DualBootManager.py`,
`SystemReportManager.py`) `src/util/` altında tek dosyadır. Bu modül için
alt paket seçildi, çünkü:

- Modül beş dosyadan oluşuyor. Tek dosyada toplanırsa üç kişinin aynı
  dosyada çalışması birleştirme çakışması üretir; ayrı dosyalarda iş
  bölümü dosya sınırlarıyla örtüşür.
- Önerideki "bağımsız modül" iddiası depoda görünür olur: mevcut koda
  dokunan yerler (arayüz bağlantısı, rapor satırı, polkit eylemi) ile
  yeni yazılan kod ayrı durur. Pull request incelemesinde ve raporda
  "bizim katkımız şu klasör" denebilir.
- `pe.py`, `efivars.py` ve `rules.py` GTK'ye ve çalışan sisteme bağlı
  değildir. Alt paket, bunların Pardus kurulu olmayan bir makinede
  `unittest` ile sınanmasını kolaylaştırır.

Değerlendirilen alternatif: `src/util/BootHealthManager.py` tek dosyası.
Depo düzenine daha yakın, ama yukarıdaki üç yararı sağlamıyor.

### 2. İlk sürümde imzalayanın adı okunmaz; yalnızca imza var/yok

"Microsoft UEFI CA 2011 ile imzalı" diyebilmek için imza bloğunun
(PKCS#7, DER kodlu ASN.1) ayrıştırılması gerekir. İlk sürümde bu
yapılmıyor, çünkü:

- Standart kütüphanede ASN.1 ayrıştırıcı yok. Ya elle yazılmalı ya da ek
  paket bağımlılığı eklenmeli; ikincisi "ek paket gerekmez" hedefine
  aykırı.
- Sekiz teşhis senaryosunun hiçbiri imzalayanın adına bakmıyor. Hepsi
  imzanın varlığına, MOK'taki özete, SBAT seviyesine ya da EFI
  değişkenlerine dayanıyor.
- Yardımcı araç root yetkisiyle çalışıyor. Root olarak çalışan kodda
  karmaşık bir ikili biçim ayrıştırıcısı, gereksiz yere büyüyen bir
  saldırı yüzeyi demek.

İmzalayan adı, isteğe bağlı "kriptografik doğrulama" işleviyle birlikte
ele alınır; o işlev sertifikayı zaten ayrıştırmak zorunda.

Sonucu: ilk sürümün mesajları "imzalı" der, "geçerli imzalı" ya da
"Microsoft tarafından imzalı" demez. `evidence` alanı bunu zorunlu kılar.

### 3. Rapor özeti arşive `boot_health.json` olarak eklenir

Önerideki "sistem raporu satırı" şöyle gerçekleştirilir:
`SystemReportManager._generate_report()` içinde durum nesnesi ve bulgu
listesi rapor arşivine `boot_health.json` adıyla yazılır. Gerekçe:

- Rapor zaten `pkexec` ile root olarak üretiliyor. EFI bölümü aynı
  yetkiyle okunur; kullanıcıdan ikinci bir yetki istenmez.
- Mevcut koda eklenen şey tek bir işlev çağrısıdır. Arşivdeki diğer
  dosyaların biçimi değişmez.
- Destek tarafında JSON, serbest metinden daha kolay işlenir; arşivde
  `system_info.json` da bu biçimde duruyor.

### 4. Yardımcı araç ayrı dosya ve ayrı polkit eylemidir

Depodaki `Actions.py` de `pkexec` ile çalışıyor, ancak komut parametresi
alıyor ve etkin oturumda parola sormuyor. 19 Ekim kararı (parametre
almayan, kullanıcı onayıyla çalışan yardımcı) bununla bağdaşmadığı için
`BootHealthHelper.py` ayrı tutulur ve kendi eylem tanımını alır.

## `pe.py` hakkında notlar

- Yalnızca standart kütüphaneyi (`struct`, `hashlib`) kullanır.
- `parse(data)` bozuk dosyada `PEError` fırlatır. `inspect_file(path)`
  hiçbir zaman hata fırlatmaz; sonucu `status` alanında bildirir.
- **Authenticode özeti düz dosya özeti değildir.** Sağlama toplamı alanı,
  sertifika tablosu girdisi ve sertifika tablosunun kendisi hesap dışında
  tutulur. shim, MOK'a kayıtlı özetleri bu değerle karşılaştırır; "GRUB
  imzasız ama özeti MOK'a kayıtlı" senaryosu bu yüzden bu alana dayanır.
- **Uzun bölüm adları.** PE bölüm adı 8 baytla sınırlıdır. `.vendor_cert`
  ve `.sbatlevel` gibi daha uzun adlar bölüm tablosunda `/<sayı>` olarak
  durur ve gerçek ad COFF dizgi tablosundan okunur.

### Doğrulananlar ve doğrulanmayanlar

- Sentetik PE dosyalarıyla 33 test geçiyor (ikisi gerçek dosya
  bulunmadığı için atlanıyor).
- Authenticode özeti, beş sentetik dosyada bağımsız bir uygulamanın
  (LIEF kütüphanesi) sonucuyla aynı çıkıyor.
- **Gerçek EFI dosyalarıyla henüz sınanmadı.** ISO'dan çıkarılan
  `grubx64.efi` ve `bootx64.efi` dosyaları `tests/fixtures/efi/` altına
  konduğunda `RealFileTests` çalışır. Özellikle `.vendor_cert` bölümünün
  uzun ad olarak saklandığı varsayımı gerçek shim dosyasında
  doğrulanmalı.
- Gerçek dosyada Authenticode özeti `pesign --hash --in <dosya>`
  çıktısıyla karşılaştırılmalı.

## `efivars.py` hakkında notlar

28 Kasım 2026'da grupça alınan kararlar (#3):

- **Ham durum, anlam değil.** `efivars.py` her değişken için
  `pe.inspect_file` ile aynı dört `status` değerini döndürür. "Yok"
  ile "okunamadı" ayrı tutulur, çünkü bazı değişkenlerin yokluğu bir
  anlam taşır: `MokSBStateRT` yoksa shim doğrulaması açıktır. Bu
  yorumu `collect.py` yapar.
- **Yalnızca `efivars`.** Yeni çekirdekler MOK değişkenlerini
  `/sys/firmware/efi/mok-variables/` altında da gösterir, ama oradaki
  dosyaları yalnızca root okuyabilir. Yetkisiz kod tek bir yoldan,
  `/sys/firmware/efi/efivars` altından okur.
- **Bölünmüş `MokListRT`.** shim büyük bir listeyi `MokListRT`,
  `MokListRT1`, `MokListRT2`... diye böler. Parçalar ilk eksik numaraya
  kadar okunup tek liste gibi ayrıştırılır.
- **`sbat_level` sözlüktür** (şema bölümüne bakınız). Aynı bileşen iki
  kez geçerse büyük sürüm alınır, çünkü daha sıkı olan odur.

Biçimle ilgili ayrıntılar:

- `efivarfs` dosyalarının ilk 4 baytı öznitelik alanıdır; veri ondan
  sonra başlar.
- GUID'ler dosyada karışık bayt sırasıyla durur (ilk üç alan
  little-endian). Kod `uuid.UUID(...).bytes_le` kullanır; bunu bir test
  sabitler.
- Okuma 1 MB ile sınırlıdır; bozuk bir değişken belleği şişiremez.

### Doğrulananlar ve doğrulanmayanlar

- Sahte kök dizinlerle 42 test geçiyor: her değişken için var, yok,
  okunamıyor ve bozuk durumları; gerçekçi bir MOK listesi (iki
  sertifika, bir SHA-256 özeti); bölünmüş liste; shim'in
  `SBAT_VAR_LATEST` biçimindeki bir SBAT seviyesi.
- **Gerçek bir makinede henüz denenmedi.** Pardus 25.2 kurulu bir
  sistemde `MokListRT` ve `SbatLevelRT` okunup `mokutil --list-enrolled`
  ve `mokutil --list-sbat-revocations` çıktılarıyla karşılaştırılmalı
  (#7).

## `collect.py` hakkında notlar

28 Kasım 2026'da grupça alınan kararlar (#4). Temel ilke: bir alan
yalnızca okuma soruyu kesin olarak yanıtlıyorsa `true` ya da `false`
olur, aksi hâlde `null`.

| Alan | Değişken okundu | Değişken yok | Okunamadı / bozuk |
|---|---|---|---|
| `firmware.secure_boot` | değeri | `false` | `null` |
| `firmware.setup_mode` | değeri | `false` | `null` |
| `shim.validation_disabled` | değeri | shim açtıysa `false`, yoksa `null` | `null` |
| `shim.mok_hashes` | özet listesi | `null` | `null` |
| `shim.sbat_level` | sözlük | `null` | `null` |

- **`SecureBoot` yoksa `false`.** Değişken UEFI 2.3.1'den beri
  standarttır; yokluğu firmware'in Secure Boot desteklemediğini, yani
  kapalı olduğunu gösterir. `null` seçilseydi Secure Boot desteği olmayan
  sanal makinelerde boş yere "kontrol yapılamadı" çıkardı.
- **"Shim açtı" = `MokListRT` okunabildi.** shim her açılışta bu
  değişkeni oluşturur. shim olmadan açılmış bir sistemde
  `MokSBStateRT`'nin yokluğu bir şey söylemez.
- **`firmware.uefi`** `/sys/firmware/efi` klasörünün varlığıdır.
- **Çekirdek** çalışan çekirdektir: `/boot/vmlinuz-<uname -r>`. Canlı
  oturumda (`/proc/cmdline` içinde `boot=live`) `/boot` boş olduğu için
  `/run/live/medium/live/vmlinuz` okunur; orada yoksa `/boot`'a
  dönülür. `/proc/cmdline` okunamazsa `live_session` `null` olur.
- **Paketler** `dpkg` çalıştırılmadan `/var/lib/dpkg/status` dosyasından
  okunur: alt süreç açılmaz ve testte sahte dosya verilebilir. Paketin
  `Status` satırının son kelimesi `installed` ise `true`, değilse
  `false`; dosya okunamazsa `null`.
- `esp` her zaman `null` döner. Yardımcı aracın çıktısını arayüz
  ekler (#12).

### Doğrulananlar ve doğrulanmayanlar

- Sahte kök dizinlerle 30 test geçiyor: Legacy, UEFI, canlı oturum;
  yukarıdaki tablonun her hücresi; okunamayan ve bozuk çekirdek.
- **Gerçek sistemde doğrulanacaklar (#7):** paket adlarının
  (`shim-signed`, `grub-efi-amd64-signed`) Pardus 25.2'de aynı olduğu;
  Pardus canlı USB'sinde çekirdeğin `/run/live/medium/live/` altındaki
  adı; `/boot/vmlinuz-*` dosyasının normal kullanıcıya okunabilir
  olduğu.

## Testleri çalıştırma

```bash
python3 -m unittest discover -s tests -v
```

LIEF karşılaştırması isteğe bağlıdır; kütüphane kurulu değilse o test
atlanır (`pip install lief`).
