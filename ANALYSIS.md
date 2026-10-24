# Analiza obu repozytoriów

Data przeglądu: 2026-10-24.

## Pauli1Go/iphone-mirroring-eu-enabler

Aktualny `enable.py` ma około 1 KB. Otwiera na żywo:

```text
/private/var/db/os_eligibility/eligibility.plist
```

Następnie w `OS_ELIGIBILITY_DOMAIN_IRON` ustawia:

```text
os_eligibility_answer_t = 4
status.OS_ELIGIBILITY_INPUT_COUNTRY_BILLING = 3
status.OS_ELIGIBILITY_INPUT_COUNTRY_LOCATION = 3
```

Na końcu uruchamia `/System/Applications/iPhone Mirroring.app`.

Mechanizm identyfikuje właściwy podsystem, lecz zapis przez `open(..., "wb")` nie jest atomowy. Nie ma backupu, przywracania, blokady równoległych operacji, kontroli struktury, porównania metadanych ani weryfikacji zapisu. Jeśli domeny lub kluczy brakuje, skrypt może ogłosić sukces mimo braku skutecznej zmiany. Repo zgłasza też przypadki `Operation not permitted` bez Full Disk Access oraz przeliczanie wartości przez macOS.

## TimBitBox/mac-location-spoofer

`mac_location_lab.py` zapisuje trzy wartości symulacji do dwóch domen preferencji użytkownika `_locationd`, czyli łącznie sześć kluczy:

```text
SimulatedLocationLatitude
SimulatedLocationLongitude
SimulatedLocationAccuracy
```

Po zapisie restartuje cache preferencji i `locationd`. Ma sensowną walidację współrzędnych, prywatny backup sześciu kluczy, blokadę oraz próbę rollbacku. Sam README zaznacza jednak, że używa prywatnych preferencji, a świeża instalacja i pełny cykl set/reset nie zostały szeroko zweryfikowane.

Ten mechanizm nie zmienia `eligibility.plist` i nie odpowiada za domenę `IRON`. Dodanie go do narzędzia Mirroring zwiększyłoby zasięg zmian systemowych bez dowodu, że pomaga. Poprzednia nieudana próba resetu jest dodatkowym argumentem, aby pozostawić `locationd` w spokoju; obecnie sześć kluczy jest nieobecnych, a usługa działa.

## macOS 27.2 arm64 na tym Macu

Odczyt bez zmian potwierdził:

```text
macOS 27.2 (26B5101f)
arm64
SIP enabled
iPhone Mirroring.app present
eligibilityd running
eligibility.plist: root:_eligibilityd, mode 0644, no file flags
```

Odczyt zawartości `eligibility.plist` został poprawnie zablokowany przez TCC, ponieważ proces nie miał Full Disk Access. To oczekiwane i pokazuje, że `sudo` nie wystarcza. Narzędzie zgłasza ten przypadek bez prób obchodzenia ochrony.

## Decyzja projektowa

Helper dotyka wyłącznie trzech istniejących kluczy `IRON`. `CESIUM`, Core Location i wszystkie pozostałe domeny pozostają bez zmian. Brak domeny, brak klucza, inny typ wartości, nieznany format, symlink, flaga immutable, zmiana równoległa albo rozbieżność metadanych powodują odmowę zapisu.

Domyślną drogą jest krótkotrwałe `launch`: patch → uruchomienie aplikacji → dokładne przywrócenie. `apply` istnieje jako świadoma opcja trwała, ale nie instaluje pętli ani flagi immutable. To ogranicza skutki uboczne i pozostawia systemowi możliwość normalnego przeliczenia eligibility.

## Granica po stronie iPhone’a

Nowsze wersje iOS mogą odrzucić parowanie kodem `SFAuthenticationErrorCodeRegionLocked` już po przejściu sprawdzenia Maca. Narzędzie potrafi rozpoznać ten wzorzec w logach, lecz go nie obchodzi. To ważna granica: sukces zmiany `IRON` nie gwarantuje działającego Mirroringu.
