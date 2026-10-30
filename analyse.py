"""Projet 1 - Analyse des journaux d'un pare-feu.

Lancer avec : python analyse.py
Lit data/logs_reseau.csv, nettoie les donnees, calcule les resultats,
enregistre les figures dans figures/ et ecrit resultats.json.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # pas besoin d'ecran
import matplotlib.pyplot as plt
import pandas as pd

BASE = Path(__file__).parent
CSV = BASE / "data" / "logs_reseau.csv"
FIG_DIR = BASE / "figures"
FIG_DIR.mkdir(exist_ok=True)


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Doublons exacts, protocol en majuscules, bytes_sent manquants -> mediane."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculee apres suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer(df: pd.DataFrame) -> dict:
    ports_par_ip = df.groupby("src_ip")["dst_port"].nunique()
    octets_par_ip = df.groupby("src_ip")["bytes_sent"].sum()
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(ports_par_ip.idxmax()),
        "ip_exfiltration": str(octets_par_ip.idxmax()),
    }


def sauver(nom: str) -> None:
    plt.tight_layout()
    plt.savefig(FIG_DIR / nom, dpi=120)
    plt.close()


def figures(df: pd.DataFrame, res: dict) -> None:
    # 1. Top 10 des ports de destination
    top = df["dst_port"].value_counts().head(10)
    plt.figure(figsize=(8, 5))
    plt.bar(top.index.astype(str), top.values, color="steelblue")
    plt.title("Top 10 des ports de destination")
    plt.xlabel("Port de destination")
    plt.ylabel("Nombre de connexions")
    sauver("top_ports.png")

    # 2. Connexions par heure
    par_heure = df.groupby(df["timestamp"].dt.hour).size()
    plt.figure(figsize=(9, 5))
    plt.plot(par_heure.index, par_heure.values, marker="o")
    plt.title("Connexions par heure de la journee")
    plt.xlabel("Heure (0-23)")
    plt.ylabel("Nombre de connexions")
    plt.xticks(range(0, 24, 2))
    plt.grid(alpha=0.3)
    sauver("connexions_par_heure.png")

    # 3. Volume d'octets par type d'appareil
    vol = df.groupby("device_type")["bytes_sent"].sum().sort_values(ascending=False)
    plt.figure(figsize=(8, 5))
    plt.bar(vol.index, vol.values / 1e6, color="darkorange")
    plt.title("Volume d'octets envoyes par type d'appareil")
    plt.xlabel("Type d'appareil")
    plt.ylabel("Volume total (Mo)")
    sauver("octets_par_appareil.png")

    # 4. Repartition ALLOW / DENY
    rep = df["action"].value_counts()
    plt.figure(figsize=(6, 6))
    plt.pie(rep.values, labels=rep.index, autopct="%1.1f%%",
            colors=["seagreen", "indianred"])
    plt.title("Repartition ALLOW / DENY")
    sauver("allow_deny.png")

    # 5. Ports distincts contactes par IP source (top 10) -> scanner
    ports = df.groupby("src_ip")["dst_port"].nunique().sort_values(ascending=False).head(10)
    plt.figure(figsize=(9, 5))
    plt.barh(ports.index[::-1], ports.values[::-1], color="firebrick")
    plt.title("Ports distincts contactes par IP source (top 10)")
    plt.xlabel("Nombre de ports distincts")
    plt.ylabel("IP source")
    sauver("ports_distincts_par_ip.png")

    # 6. Octets envoyes par IP source (top 10) -> exfiltration
    octets = df.groupby("src_ip")["bytes_sent"].sum().sort_values(ascending=False).head(10)
    plt.figure(figsize=(9, 5))
    plt.barh(octets.index[::-1], octets.values[::-1] / 1e6, color="purple")
    plt.title("Octets envoyes par IP source (top 10)")
    plt.xlabel("Volume total (Mo)")
    plt.ylabel("IP source")
    sauver("octets_par_ip.png")


def main() -> None:
    df = nettoyer(pd.read_csv(CSV))
    res = calculer(df)
    figures(df, res)
    (BASE / "resultats.json").write_text(
        json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
