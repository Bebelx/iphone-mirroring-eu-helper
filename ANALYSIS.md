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

Helper dotyka wyłącznie trzech istniejących kluczy `IRON`. `CESIUM`, Core Location i wszystkie pozostałe domeny pozostają bez zmian. Brak domeny, brak klucza, inny typ wartości, nieznany format, symlink, flaga immutable, zmiana równoległa albo rozbieżność istotnych metadanych powodują odmowę zapisu. Systemowy znacznik `com.apple.provenance`, który macOS może automatycznie dopisać do nowego inode, jest raportowany, ale nie jest traktowany jako uprawnienie ani wejście eligibility.

Domyślną drogą jest krótkotrwałe `launch`: patch → uruchomienie aplikacji → dokładne przywrócenie. `apply` istnieje jako świadoma opcja trwała, ale nie instaluje pętli ani flagi immutable. Gdy log jawnie pokazuje, że `eligibilityd` zdążył przywrócić `answer: 2` przed kontrolą aplikacji, opcjonalne `launch --guard-recompute` ustawia wyłącznie użytkową flagę `uchg` na kilka sekund. Flaga jest zdejmowana i weryfikowana przed dokładnym przywróceniem; SIP i systemowa flaga immutable pozostają nietknięte. Przed operacją drukowany jest identyfikator backupu oraz polecenie awaryjne na wypadek nieprzechwytywalnego `SIGKILL` albo utraty zasilania.

## Granica po stronie iPhone’a

Nowsze wersje iOS mogą odrzucić parowanie kodem `SFAuthenticationErrorCodeRegionLocked` już po przejściu sprawdzenia Maca. Narzędzie potrafi rozpoznać ten wzorzec w logach, lecz go nie obchodzi. To ważna granica: sukces zmiany `IRON` nie gwarantuje działającego Mirroringu.

Test na macOS 27.2 i iOS 27 doprecyzował tę granicę. Tryb z krótką ochroną `uchg` utrzymał patch Maca podczas wielu kolejnych kontroli, a lokalny błąd `answer: 2` pojawił się dopiero po zdjęciu ochrony i przywróceniu oryginalnego pliku. Zsynchronizowane logi obu urządzeń pokazały, że iPhone przeszedł lokalne etapy eligibility i restriction, zaakceptował sesję oraz osiągnął `readyForUnlock`. Następnie wymiana LTK/AKS zakończyła się `com.apple.sharing.authentication Code=10`, który lokalna funkcja Apple `SFAuthenticationErrorCodeToString` mapuje na `SFAuthenticationErrorCodeInternal`. Wartość `RegionLocked` to kod 35 i nie wystąpiła w tej zarejestrowanej próbie. Pierwszym działaniem naprawczym dla kodu 10 powinno być ponowne uruchomienie urządzeń i wyzerowanie wyłącznie parowania iPhone Mirroring, nie dalsze zmiany pliku eligibility ani Core Location.

Na iPhonie było wtedy aktywne amerykańskie konto Media i zakupy. Sama zmiana storefrontu, nawet jeśli odblokowuje funkcje Siri lub Apple Intelligence, nie przesądza więc o wyniku oddzielnej domeny `IRON` ani późniejszego uwierzytelniania iPhone Mirroring.
