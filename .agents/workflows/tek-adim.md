---
description: Oil'de tek bir problemi keşif-plan-test-uygula-doğrula döngüsüyle çözer. Kullanım: /tek-adim <modül> <problem>
---

Girdi: `<modül> <problem>`. Aşağıdaki adımları sırayla uygula; her adımın çıktısını kısaca belirt.

1. `AGENTS.md` ve `.agents/rules/oil-isleyis.md` dosyalarını yeniden oku.
2. **Taban çizgisini al:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Test sayısını not et (bu ölçülen değer taban çizgisidir ve düşemez). Taban çizgisi kırmızıysa dur ve bildir.
3. **Keşif (yazma yok):** yalnızca belirtilen modülü, çağıranlarını ve ilgili testleri oku. Problemi tek cümleyle yeniden ifade et.
4. **Plan artifact'i üret:** değişecek dosyalar, değişmeyecekler, riskler, eklenecek testler (sınır durumu listesinden). **İnsan onayını bekle.**
5. Onaydan sonra: önce başarısız regresyon testini yaz ve başarısızlığını çalıştırarak göster.
6. En küçük düzeltmeyi uygula.
7. Üç doğrulama komutunu çalıştır. Test sayısı ≥ taban çizgisi + eklenen test sayısı olmalı.
8. Yasak sözcük taraması yap: `[CLEAN]` ve `clean_count` kodda ve çıktıda geçmemeli.
9. `AGENTS.md` bölüm 5 formatında rapor ver. Kapsam dışı gördüğün sorunları ayrıca listele, düzeltme.
