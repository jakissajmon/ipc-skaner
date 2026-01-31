[```English```](/README-EN.md) | **```Polski```**

## Generator niezabezpieczonych kamer IP Dahua
> [!CAUTION]
> Ten program to PoC(Proof of Concept) dla celów naukowych. Nie odpowiadam za jakiekolwiek szkody wyrządzone przy użyciu tego oprogramowania. Wszystko robisz na własną odpowiedzialność.

Ten program szuka niezabezpieczonych kamer firmy **Dahua**, generując plik z numerem seryjnym i domyślnym hasłem `admin`, który może zostać zaimportowany do programu [SmartPSS](https://dahuawiki.com/SmartPSS) lub [SmartPSS Lite](https://dahuawiki.com/SmartPSS_Lite). Jest zbudowany na bazie portugalskiego skanera z Discorda(autor jest mi nieznany).
**Nie wszystkie wygenerowane kamery będą działały. Niektóre mają losowe hasła, są wyłączone albo nie są skonfigurowane. Jest to losowe.**

Więcej informacji na [Discord](https://discord.gg/eF9wWm3ufU).

### Wymagania
* Zainstaluj Python: `winget install python`
* Zainstaluj bibliotekę "xmltodict": `py -m pip install xmltodict`

### Jak używać?
**Wszystkie komendy można zobaczyć używając `py skaner.py -h`. Poniższe komendy to tylko przykłady użycia skanera.**

* Aby użyć interaktywnych ustawień, użyj `py skaner.py -i -f (plik z prefiksami)`.
* Aby skanować używając jednego, losowego prefiksu z pliku użyj `py skaner.py -r -f (plik)`.
* Aby skanować używając wszystkich prefixów z pliku użyj `py skaner.py -ma -f (plik)`.
* Aby zmienić liczbę wątków, użyj argumentu `-t (liczba)`.

> [!WARNING]
> Liczbę wątków należy dopasować do prędkości swojego internetu - w przeciwnym razie może doprowadzić do awarii/znacznego jego spowolnienia.

**Ważne pojęcia:**
* prefix(/ks) - początek, pierwsze 10 znaków SN;
* suffix(/ks) - koniec, ostatnie 5 znaków SN
