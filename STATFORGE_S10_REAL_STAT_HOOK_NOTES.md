# StatForge Season 10 Gerçek Stat Sonuç Kancaları

Bu dosya Hero Siege 7.0.5.0 üzerinde 29 Ağustos 2026 tarihinde yapılan canlı
araştırmanın kalıcı kaydıdır. Yeni stat eklerken önce buradaki yöntem
uygulanmalıdır. Yalnız belleğe yazının başarılı olması, özelliğin oyunda
çalıştığı anlamına gelmez.

## Kesin kök neden

- `ac_dll_gm.dll` korumalı tablosundaki Magic Find `10` ve Movement Speed `25`
  hücreleri okunup değiştirilebiliyordu; XOR ve integrity değerleri de doğru
  yazılıyordu. Buna rağmen oyun sonucu değişmiyordu.
- Bunlar karakterin güncel toplam stat sonucu değildi. Oyunun kullandığı değer,
  `gml_Script_StatMagicFind` ve `gml_Script_StatMovementSpeed` fonksiyonlarının
  döndürdüğü GameMaker dizisinin sıfırıncı elemanıdır.
- Eski EXP yolu `gml_Script_EnemyCalculateExperience` içindeki `1.0` sabitini
  değiştiriyordu. O sabit nihai ödül değeri değildi. Doğru hedef fonksiyonun
  tamamen hesaplanmış dönüş RValue değeridir.

## RValue ve stat dizisi düzeni

64-bit Season 10 YYC çalışma zamanında gözlenen düzen:

```text
RValue (16 bayt)
+0x00  8 bayt union: double veya pointer
+0x08  4 bayt flags
+0x0C  4 bayt kind

VALUE_REAL  = 0
VALUE_ARRAY = 2
```

Stat fonksiyonu `VALUE_ARRAY` döndürdüğünde:

```text
result_rvalue + 0x00 -> dynamic array object
dynamic array object + 0x08 -> RValue element dizisi
element array + 0x00 -> element[0] RValue
element[0] + 0x00 -> oyunun kullandığı nihai double stat değeri
```

Movement Speed canlı gözleminde dizi `[77, 0, 0, 600]` idi. Karaktere ve
bonuslara göre ilk eleman değişir; sabit `77` kullanılmamalıdır.

## 7.0.5.0 doğrulama kaydı

```text
Hero_Siege.exe version: 7.0.5.0
SHA-256: 438bf4848688c5be52ac15f26f02b46da620d90587c28e766a9cea190f3a7de4
Image size: 0x11193000
```

ASLR nedeniyle canlı mutlak adresler kaydedilmez. Aşağıdaki RVA değerleri
yalnız araştırma ve regresyon kontrolü içindir; çalışma zamanında fonksiyonlar
isim tablosundan bulunmalı ve kapanış yapısı doğrulanmalıdır.

| Stat | GameMaker fonksiyonu | Function RVA | Hook RVA | Orijinal tam talimatlar |
|---|---|---:|---:|---|
| Magic Find | `gml_Script_StatMagicFind` | `0x5A51CB0` | `0x5A6074E` | `48 8B 85 20 22 00 00` |
| Movement Speed | `gml_Script_StatMovementSpeed` | `0x5AD07A0` | `0x5B00E82` | `48 8B 85 30 6C 00 00` |
| EXP | `gml_Script_EnemyCalculateExperience` | `0x187AAE0` | `0x187E3AE` | `49 8B C7 48 8B 9C 24 00 01 00 00` |

Magic Find ve Movement Speed kapanışları yedi baytlık
`MOV RAX,[RBP+disp32]` talimatıdır. Hemen arkasında XMM6/frame geri yükleme ve
`RET` bulunması zorunlu olarak doğrulanır.

EXP 7.0.5.0'da farklıdır. Sonuç pointer'ı R15 içindedir:

```asm
mov rax, r15
mov rbx, [rsp+100h]
add rsp, 0B0h
pop r15 ... pop rbp
ret
```

İlk iki tam talimat toplam 11 bayttır. Yama hiçbir zaman talimatın ortasında
bitmemelidir. Beş baytlık yakın `CALL` ve altı `NOP` kullanılır; mağara iki
orijinal talimatı tekrar çalıştırıp sonucu ölçekler.

## Canlı çalışma kanıtı

`dist-v2.2.3/hs_statforge.log` içinden doğrulanmış sonuçlar:

```text
Magic Find:     345 × 126 = 43470, gerçek oyun çağrısı görüldü
Magic Find:     345 × 14  = 4830,  gerçek oyun çağrısı görüldü
Magic Find:     345 × 2   = 690,   gerçek oyun çağrısı görüldü
Movement Speed: 77 × 2    = 154,   gerçek oyun çağrısı görüldü
EXP:             3 × 100  = 300,   91 gerçek oyun çağrısı görüldü
```

Bu sayaçlar kodun yalnız yazıldığını değil, oyunun kancadan gerçekten geçtiğini
kanıtlar. Oyuncunun gözlemi de bu sonuçlarla uyuşmuştur.

## Güvenlik ve geri alma kuralları

1. Fonksiyon adresini sabit RVA ile değil GameMaker isim tablosuyla bul.
2. Kapanışta yalnız doğrulanmış tam talimatları kapsa.
3. Yakın executable mağara ayır; `CALL rel32` mesafesini doğrula.
4. Kod yazarken bütün oyun thread'lerini durdur ve hiçbir RIP'in hedef
   talimatların içinde olmadığını kontrol et.
5. Stat dizisini tekrar tekrar çarpmayı engelle. Aynı element pointer'ı ve aynı
   son ölçeklenmiş değer görülürse ikinci kez çarpma.
6. Kapatırken array hook'u önce disabled moda geçir; bir sonraki gerçek çağrıda
   son native değeri geri koydur, sonra orijinal kodu byte-for-byte yükle.
7. Çalıştırılmış code cave'i süreç yaşarken serbest bırakma. Ulaşılamaz halde
   bırak; oyun kapanınca işletim sistemi temizler.
8. Panelde ve `hs_statforge.log` içinde native değer, çarpan, sonuç ve gerçek
   çağrı sayısı görünmeden “çalışıyor” deme.
9. Restore sonrasında hedef byte'ların diskteki orijinal talimatlarla birebir
   aynı olduğunu doğrula.

## Yeni stat bulma prosedürü

1. Aday GameMaker adını bul: çoğunlukla `gml_Script_Stat<Name>`.
2. İlk testte sonuç değiştirme; yalnız RValue union/kind ve çağrı sayısını bir
   code cave'e kaydet.
3. Oyunda ilgili eylemi yaptır ve çağrı sayacının arttığını doğrula.
4. `VALUE_ARRAY` ise dynamic object `+0x08` üzerinden element dizisini oku;
   element zero'nun karakter ekranı veya gerçek oyun sonucuyla eşleştiğini
   kanıtla.
5. `VALUE_REAL` ise nihai dönüşü doğrudan ölçekle.
6. En az iki farklı native değer veya iki farklı çarpanla sonucu doğrula.
7. Özelliği kapat, orijinal byte'ları doğrula ve oyunun native değerine
   döndüğünü gözle.
8. Ancak bundan sonra UI ve yayın paketine ekle.

## Sonraki stat adayları ve özel kuralları

ForgePact araştırmasında bulunan adaylar:

- Attack Speed: canlı saldırı zamanlaması `StatAttackSpeed` kök sonucunu kullanır.
  7.0.5.0 telemetrisi bunun array değil skaler `VALUE_REAL` olduğunu kanıtladı.
  `StatAttackSpeedMainHand/OffHand` yalnız stat-detay yollarıdır.
- Faster Cast Rate: `StatFasterCastRate` tabanı sıfır olabildiği için çarpma
  yerine toplama gerekir.
- Skill Haste: `StatSpellHaste` bir stat array'i döndürür; cooldown recovery
  değeri element sıfırdadır ve çarpma yerine toplama uygulanmalıdır.
- Total Damage: karakter ekranındaki `StatTotalDamage` gerçek vuruş değildir.
  Düşmana giden nihai sonuç `CalculateEndDamage` dönüşüdür.
- Life Replenish: `StatLifeReplenish`.
- Mana Replenish: `StatManaReplenish`.
- Defense: `StatDefense`.
- Physical Critical Damage: `StatCritDamage`.
- Physical Critical Chance: `StatCritRate`.
- Spell Critical Damage: `StatSpellCritDamage`.
- Spell Critical Chance: `StatSpellCritRate`.
- Extra Gold: `StatExtraGold`.

Her aday ayrı ayrı read-only telemetry ile doğrulanmalıdır. Fonksiyon adının
mantıklı görünmesi tek başına yeterli kanıt değildir.

## 7.0.5.0 sonraki-stat salt-okunur taraması

29 Ağustos 2026 tarihinde çalışma zamanı isim tablosunda hedeflerin tamamı
bulundu. Bu tarama hiçbir oyun değeri değiştirmedi.

| Özellik | Fonksiyon | Function RVA | Doğrulanmış hook RVA |
|---|---|---:|---|
| Total Damage | `CalculateEndDamage` | `0x39E000` | `0x3A5714` |
| Spell Critical Chance | `StatSpellCritRate` | `0x5A175B0` | `0x5A1B87C` |
| Critical Strike Damage | `StatCritDamage` | `0x5A22A70` | `0x5A3021C` |
| Spell Critical Damage | `StatSpellCritDamage` | `0x5A1B8B0` | `0x5A1FA5C` |
| Critical Strike Chance | `StatCritRate` | `0x5A1FA90` | `0x5A22A3C` |
| Defense | `StatDefense` | `0x5B9C140` | `0x5BA4613` |
| Attack Speed | `StatAttackSpeed` | `0x5B0C410` | `0x5B3A05C` |
| Faster Cast Rate | `StatFasterCastRate` | `0x5A30280` | `0x5A51BE2` |
| Skill Haste | `StatSpellHaste` | `0x5B928F0` | `0x5B96B16` |

8 ve 11 baytlık R14/R15 kapanışlarında ikinci talimat RSP tabanlıdır. Hook
CALL ile mağaraya girdiği için RSP sekiz bayt küçülür; mağarada tekrar oynatılan
`MOV/LEA/MOVAPS [RSP+disp]` displacement değeri bu nedenle `disp+8` olmalıdır.
Bu telafi yapılmazsa özellikle `StatSpellCritDamage` dönüşü `0x5A1FA6B`
noktasında access violation üretir. `test_extended_result_hook_execution.py`
R14+RBP, R14+R11 ve R15+RBX biçimlerini gerçek native kod olarak çalıştırır.

Canlı 7.0.5.0 sonuçları: Attack Speed `23.1×4=92.4` (48 çağrı),
Skill Haste `12+100=112` (631 çağrı), FCR `33+365=398`,
Defense `1464×5.5=8052`,
Crit Chance `25×4.22=105.5`, Crit Damage `80.9×11=889.9`, Spell Crit Chance
`34×3.35=113.9`, Spell Crit Damage `62×5.78=358.36`. Total Damage gerçek
fonksiyonda çağrı aldı fakat test çağrılarının native değeri sıfırdı; non-zero
combat hit ayrıca teyit edilmelidir. Attack Speed için önceki iki-el array
yaklaşımı tür kontrolünde her çağrıyı atladığı için kaldırıldı.

## 7.0.5.0 monster-density çökme sınırı

30 Ağustos 2026 tarihinde 5x density sonrasında oluşan access violation'ın
StatForge taramasıyla ilgisi olmadığı doğrulandı. `ac_dll_gm.dll` içindeki
korumalı değişken havuzu doluyor ve `SetVariable` RVA `0x1424` noktasında boş
entry işaretçisine yazmaya çalışıyordu.

- `ac_dll_gm.dll` SHA-256:
  `EA33261A54BA922B4074AE211990087C3A74FA840EAD44AB30F0C74E504C505A`
- PE timestamp: `0x6A844148`; image size: `0xA0A000`.
- Havuz: 512 sayfa × 512 entry = 262,144 entry.
- Sayfa boyutu `0x5008`, entry boyutu `0x28`, ilk tablo RVA `0x5688`.
- Entry kullanım bayrağı `entry+0x10`.
- Normal menü başlangıcında yaklaşık 163 bin entry zaten kullanılıyor.

Density runtime bu düzeni PE başlığı ve `SetVariable` byte imzasıyla doğrular.
Doğrulanırsa canlı doluluğu ölçer ve 200,000 kullanımda ek creator üretimini
durdurur; böylece oyun için 62,144 entry rezerve kalır. Ayrıca tüm build'lerde
saniyede en fazla 800 ek creator oluşturulur. Bilinmeyen `ac_dll_gm.dll`
düzenlerinde adres tahmini yapılmaz; yalnız build-bağımsız burst sınırı kalır.

Canlı 5x testi üç ardışık savaş haritasında 468 native creator ve 1,872 ek
creator gözledi. Son doluluk 179,770 / 262,144 idi; oyun açık ve yanıt verir
kaldı, DLL temiz kaldırıldı ve Windows yeni çökme kaydı üretmedi.
