#!/usr/bin/env python3
"""Toglie dai JSON delle liste gli IP elencati in eccezioni.txt.

Uso: python3 filtra_eccezioni.py [--blocchi] file.json [file.json ...]

Formato JSON (letto da secupd sul MikroTik):
  {"#":{"format":1,"entries":N,"generated":T}, "<o1>":{"<o2>":{"<resto>":1,...},...},...}
--blocchi: file diviso in blocchi da 32768 byte, ognuno un JSON completo riempito di spazi
  (blocklist_xl.json): secupd legge ogni blocco da solo e confronta il totale con "entries",
  quindi i confini dei blocchi vanno mantenuti e "entries" aggiornato.
Se qualcosa non torna esce con errore: la Action si ferma e non pubblica un file guasto.
"""
import ipaddress
import json
import sys

BLOCCO = 32768
SEP = (",", ":")


def carica_eccezioni(path="eccezioni.txt"):
    ips = []
    with open(path, encoding="utf-8") as f:
        for riga in f:
            riga = riga.split("#", 1)[0].strip()
            if riga:
                ips.append(ipaddress.ip_address(riga))
    return ips


def filtra(albero, eccezioni, nome):
    """Toglie le voci che sono (o contengono) un IP di eccezione; ritorna quante ne ha tolte."""
    tolte = 0
    for o1, livello2 in albero.items():
        if o1 == "#":
            continue
        for o2, resti in livello2.items():
            for resto in list(resti):
                indirizzo = f"{o1}.{o2}.{resto}"
                try:
                    rete = ipaddress.ip_network(indirizzo, strict=False)
                except ValueError:
                    continue
                trovati = [ip for ip in eccezioni if ip in rete]
                if trovati:
                    del resti[resto]
                    tolte += 1
                    avviso = "" if rete.num_addresses == 1 else f" (ATTENZIONE: tolta l'intera rete per {', '.join(map(str, trovati))})"
                    print(f"{nome}: tolto {indirizzo}{avviso}")
    return tolte


def conta(albero):
    return sum(len(r) for k, l2 in albero.items() if k != "#" for r in l2.values())


def file_a_blocchi(path, eccezioni):
    dati = open(path, "rb").read()
    blocchi = [json.loads(dati[i:i + BLOCCO].decode("utf-8")) for i in range(0, len(dati), BLOCCO)]
    tolte = sum(filtra(b, eccezioni, path) for b in blocchi)
    if tolte == 0:
        print(f"{path}: nessuna eccezione presente")
        return
    testa = next(b["#"] for b in blocchi if "#" in b)
    testa["entries"] -= tolte
    out = []
    for n, b in enumerate(blocchi):
        s = json.dumps(b, separators=SEP, ensure_ascii=False).encode("utf-8")
        if n < len(blocchi) - 1:
            if len(s) > BLOCCO:
                sys.exit(f"ERRORE {path}: blocco {n} oltre {BLOCCO} byte")
            s = s.ljust(BLOCCO, b" ")
        out.append(s)
    nuovo = b"".join(out)
    # verifica come farebbe secupd: ogni blocco da solo, totale = entries, eccezioni assenti
    totale, attese = 0, None
    for i in range(0, len(nuovo), BLOCCO):
        b = json.loads(nuovo[i:i + BLOCCO].decode("utf-8"))
        if "#" in b:
            attese = b["#"]["entries"]
        if filtra(b, eccezioni, "verifica"):
            sys.exit(f"ERRORE {path}: eccezione ancora presente")
        totale += conta(b)
    if totale != attese:
        sys.exit(f"ERRORE {path}: entries {totale} != {attese}")
    open(path, "wb").write(nuovo)
    print(f"{path}: tolte {tolte}, entries {attese}, blocchi {len(out)}")


def file_unico(path, eccezioni):
    albero = json.load(open(path, encoding="utf-8"))
    tolte = filtra(albero, eccezioni, path)
    if tolte == 0:
        print(f"{path}: nessuna eccezione presente")
        return
    albero["#"]["entries"] -= tolte
    if conta(albero) != albero["#"]["entries"]:
        sys.exit(f"ERRORE {path}: conteggio entries incoerente")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(albero, f, separators=SEP, ensure_ascii=False)
    print(f"{path}: tolte {tolte}, entries {albero['#']['entries']}")


if __name__ == "__main__":
    args = sys.argv[1:]
    a_blocchi = "--blocchi" in args
    files = [a for a in args if a != "--blocchi"]
    if not files:
        sys.exit(__doc__)
    eccezioni = carica_eccezioni()
    print("Eccezioni:", ", ".join(map(str, eccezioni)) or "nessuna")
    for p in files:
        (file_a_blocchi if a_blocchi else file_unico)(p, eccezioni)
