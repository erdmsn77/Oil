---
description: Oil için zorunlu çalışma protokolü, test disiplini ve sınır durumu kontrol listesi
---

# Oil İşleyiş Protokolü (her görevde geçerli)

## A. Görev Döngüsü (atlanamaz)
1. **Keşif (yazma yok):** İlgili modülü ve mevcut testleri oku. Etkilenen fonksiyonları ve çağıranlarını listele.
2. **Plan:** Implementation plan artifact'i üret. İçermesi gereken: değişecek dosyalar, değişmeyecek dosyalar, risk, eklenecek testler. Plan onaylanmadan kod yazma.
3. **Önce test:** Sorunu yeniden üreten (başarısız olan) regresyon testini yaz ve başarısız olduğunu çalıştırıp doğrula. Sonra düzeltmeyi yaz.
4. **Uygula:** En küçük değişiklik. İlgisiz refactor, yeniden adlandırma, biçim değişikliği yok.
5. **Doğrula:** `AGENTS.md` bölüm 3'teki üç komut. Biri başarısızsa düzelt; kendi eklediğin testi gevşeterek geçirme.
6. **Rapor:** `AGENTS.md` bölüm 5 formatı. Walkthrough artifact'inde test çıktısını göster.

Bir adımda takılırsan veya plandan sapman gerekirse **dur ve sor**; sessizce kapsamı genişletme.

## B. Kapsam Disiplini
- Görev tek modül/tek problem. Plan başka modüle dokunmayı gerektiriyorsa, planı böl ve insana bildir.
- `oil-core` içine terminal/renk/IO sunumu, `oil-cli` içine analiz mantığı koyma.
- Yeni public API eklerken mevcut imzaları bozma; bozucu değişiklik gerekiyorsa önce sor.
- Dosya silme, `git reset --hard`, `git push`, `git clean`: yalnızca açık talimatla.

## C. Karar Modeli Kuralları (`risk.rs` ve çıktı katmanları)
- Karar türü tam olarak dört değerdir; beşincisini ekleme.
- Bir dosya için bileşenlerden herhangi biri analiz edilemediyse (örn. arşivde bir üye şifreli) ve diğerlerinde gösterge yoksa sonuç `INCONCLUSIVE` olur, `NO INDICATORS FOUND` olamaz.
- `NO INDICATORS FOUND` anlamı: "analiz edilebilen her şey incelendi ve gösterge çıkmadı". "Güvenli" veya "temiz" anlamı taşımaz; mesaj metinleri bunu ima etmemeli.
- Yeni gösterge eklerken ağırlığını ve hangi kombinasyonlarda yükseldiğini `risk.rs` testlerinde açıkça göster.

## D. Sınır Durumu Kontrol Listesi (parser/analiz kodu için)
Her yeni veya değişen okuma/parse mantığı için aşağıdakilerin hangilerinin geçerli olduğunu düşün ve geçerli olanların testini yaz:
- Boş girdi (0 bayt), 1 bayt, yalnızca `MZ`.
- `e_lfanew` dosya boyutundan büyük, sıfır veya `u32::MAX`.
- Section sayısı gerçek tablo boyutundan çok büyük; section tablosu dosya sonunu aşıyor.
- `SizeOfHeaders`, `SizeOfRawData`, `PointerToRawData`, `VirtualSize` birbirleriyle ve dosya boyutuyla çelişiyor.
- RVA + boyut toplamı `u32`/`usize` taşıyor.
- Certificate table / overlay offset'i dosya dışında.
- Kesilmiş dosya (başlık tam, gövde yarım).
- Arşivde: şifreli üye, iç içe arşiv, bütçe aşımı, aşırı sıkıştırma oranı, bozuk üye.
- Beklenen sonuç her zaman: panik yok, bellek patlaması yok, `INCONCLUSIVE` (veya belgelenmiş başka bir güvenli sonuç).

## E. Test Yazım Kuralları
- Test girdileri bellekte üretilen sentetik bayt dizileridir; gerçek zararlı yazılım veya telifli ikili dosya repoya eklenmez.
- Test adları davranışı anlatır: `truncated_pe_header_returns_inconclusive`.
- Her hata düzeltmesi, düzeltmeden önce başarısız olan bir regresyon testi içerir.
- Sınır durumu testleri yalnızca "panik etmiyor" değil, **doğru kararı** da doğrular.
- Test süresi kısa kalmalı (mevcut toplam ~0.04 sn); büyük tampon gerektiren testlerde boyutu gerekçelendir.

## F. Stratejist Taslağını Uygularken
Taslak şu dört bölümle gelir: Analiz ve Gerekçe, Hangi Modül, Hedef Kod, Birim/Entegrasyon Testi. Uygulamadan önce:
1. Hedef kodun gerçek kod tabanıyla uyumunu kontrol et (imzalar, tipler, modül yolu).
2. Kırmızı çizgi ihlali var mı bak (özellikle panik, indeksleme, saturating aritmetik, yasak sözcük).
3. Sapma varsa uygulamadan önce **listele**: "taslakta X yazıyor, kodda Y var, şöyle uyarlayacağım".
4. Taslaktaki testleri olduğu gibi ekle; geçmiyorsa testi değil önce varsayımı sorgula ve raporla.

## G. Yapma Listesi
- Çalıştırmadığın komutun sonucunu uydurma; hata varsa olduğu gibi göster.
- "Muhtemelen çalışır" ile görev kapatma.
- Uyarıyı `#[allow(...)]` ile susturma; nedenini düzelt. Zorunluysa gerekçeli yorum ve insan onayı.
- Başarısız doğrulamayı atlamak için test/komut değiştirme.
- Geçici hata ayıklama çıktısını (`println!`, `dbg!`) bırakma.
