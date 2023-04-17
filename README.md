DIESES REPOSITORY ALS **PRIVATES PROJEKT** FORKEN, SONST KEINE PUNKTE BZW. MINUSPUNKTE!

# Aufgabe 1 SoSe 2023

Die Aufgabe beinhaltet lediglich ein Bild. Gesucht wird allerdings eine Flagge in der Form `HTB{s0me_t3xt}`, die vermutlich in einer passwortgeschützten Datei versteckt wurde. Die Flagge in dieser Datei ist zudem verschlüsselt worden, allerdings handelt es sich um eine schwache Verschlüsselungsmethode, die rekonstruiert werden kann um den Ursprungswert wiederherzustellen.

1. Ein Bild ist möglicherweise nicht nur ein Bild. Mach dir Gedanken, wie Dir die gegebenen Informationen bei der Suche nach der eigentlichen Flagge helfen.
2. Wie kann der Passwortschutz gehackt werden?
3. Nutze [Reverse Engineering](https://de.wikipedia.org/wiki/Reverse_Engineering) zum Rekonstruieren der Verschlüsselungsmethode.
4. Beachte etwaige Konvertierungen, die beim Verarbeiten der Flagge vorgenommen worden sein können.
5. Entschlüssele die Nachricht, um die Flagge in der Form `HTB{s0me_t3xt}` zu erhalten. Du kannst diese auch zur Lösung einer [Hack The Box Challenge](https://app.hackthebox.com/challenges/) verwenden. Den genauen Link zur Challenge verraten wir nach Ablauf beider Abgabefristen.
6. Dokumentiere dein Vorgehen, sowie deine Fehler. Auch Teilergebnisse werden bewertet.
7. Denk daran, deine Lösung vor der Abgabefrist im Mattermost-Kanal [Hack The Box SoSe 2023](https://mm.ide3.de/ide3/channels/hack-the-box-sose-2023) einzureichen.

Abgabefrist für Krefeld: 17.04.2023 23:59
Abgabefrist für Mönchengladbach: 19.04.2023 23:59^

---
---
---

# Dokumentation

## 1. Analyse

Da das Bild als Hinweis für die versteckte Flagge dient und wir wissen, dass die Flagge in einer passwortgeschützten Datei versteckt ist, sollten wir uns auf Steganographie konzentrieren. Die gegebenen Informationen können uns dabei helfen, die richtigen Techniken und Tools auszuwählen, um die Flagge zu finden.

Die gegebenen Informationen:


- Form der Flagge: HTB{s0me_t3xt}
- Flagge ist verschlüsselt
- Flagge in passwortgeschützter Datei

Wie können uns diese Informationen bei der Suche nach der eigentlichen Flagge helfen?

Die Form der Flagge gibt uns einen Anhaltspunkt dafür, wonach wir suchen müssen. Sobald wir eine verschlüsselte Nachricht finden, können wir überprüfen, ob sie dem Muster HTB{...} entspricht, um sicherzustellen, dass es sich tatsächlich um die Flagge handelt. Da die Flagge verschlüsselt ist, wissen wir, dass wir sie entschlüsseln müssen, nachdem wir sie gefunden haben. Dies ist ein wichtiger Schritt, den wir im Hinterkopf behalten sollten, wenn wir die Flagge extrahieren. Da die Flagge in einer passwortgeschützten Datei versteckt ist, müssen wir uns auf Steganographie-Techniken konzentrieren, um sie zu finden. Dies hilft uns dabei, den Fokus auf die richtigen Werkzeuge und Methoden zu legen, um das Bild zu analysieren und die versteckte Datei zu extrahieren.

## 2. Datei identifikation & extraktion 
  
Da Steghide einen Zufallszahlengenerator mit einem begrenzten 32-Bit-Seed zum Einbetten der versteckten Daten verwendet können wir mithilfe von Stegseek einen möglichen Seed Brute-Forcen. 
```bash
stegseek --seed just_an_image.jpg
````
Nach kurzer Zeit findet Stegseek dann auch einen möglichen Seed. Als Ausgabe erhalten wir den Seed-Wert, die Datengröße, den Verschlüsselungsalgorithmus und den Verschlüsselungsmodus. Diese Informationen bestätigen, dass wir uns auf dem richtigen Weg befinden.

```bash
[i] Gefundener (möglicher) Seed: "42b3aa48"            
    Klartextgröße: 628,0 Byte(s) (komprimiert)
    Verschlüsselungsalgorithmus: rijndael-128
    Verschlüsselungsmodus:      cbc
```

Mithilfe von StegSeek und ein paar Wordlists stoßen wir recht schnell auf das Passwort "ultra-secret" und können die enthaltene Datei "xor.zip" extrahieren.
![](https://i.imgur.com/9zhU7Q9.png)

## 3. Entschlüsselung der Flagge
Nach dem entpacken von xor.zip erhalten wir das Verzeichniss xor welches die Dateien challenge.py & output.txt enthält. 

Das Python-Skript öffnet die Datei "flag.txt" und verschlüsselt ihren Inhalt mit einer einfachen XOR-Verschlüsselung. Der verschlüsselte Text wird anschließend in hexadezimaler Form ausgegeben. Output.txt scheint eine solche Ausgabe zu enthalten.

Um die Flagge zu entschlüsseln, müssen wir den Verschlüsselungsprozess rückgängig machen, der in "challenge.py" definiert ist. Da die XOR-Verschlüsselung symmetrisch ist, können wir dieselbe Methode sowohl zum Verschlüsseln als auch zum Entschlüsseln verwenden.

Zuerst müssen wir die Schlüssellänge ermitteln, die in diesem Fall 4 Byte beträgt. Anschließend müssen wir den Schlüssel finden, indem wir einen Brute-Force-Angriff durchführen, da der Schlüssel aus "os.urandom(4)" generiert wurde.

Möglicher Lösungsansatz mit einem Python-Skript:

```python
import itertools

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    decrypted = b''
    for i in range(len(data)):
        decrypted += bytes([data[i] ^ key[i % len(key)]])
    return decrypted

encrypted_flag = bytes.fromhex("5296a4c868a796802eb6d5d745bad6c145acd6c745b1d6ec69f185c668f19b")


for key in itertools.product(range(256), repeat=4):
    key_bytes = bytes(key)
    decrypted = xor_decrypt(encrypted_flag, key_bytes)
    if decrypted.startswith(b"HTB{"):
        print("Found key:", key_bytes)
        print("Decrypted flag:", decrypted.decode())
        break
```

![Decryption](https://i.imgur.com/wDWQZCY.png)

Nach dem Ausführen des Skripts erhalten wir die entschlüsselte Flagge in der korrekten Form **HTB{rep34t3d_x0r_n0t_s0_s3cur3}**
