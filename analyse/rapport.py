#!/usr/bin/env python3
"""Construit un rapport HTML a partir du fichier produit par analyse.py.

    python3 rapport.py resultats/stats.json -o resultats/rapport.html

Le HTML est autonome (pas de CDN, pas de dependance) pour pouvoir etre ouvert
depuis une cle USB ou joint a un compte rendu. Volontairement sobre : c'est
destine a etre imprime ou colle dans un dossier, pas a faire joli.
"""

import argparse
import html
import json
import sys

GABARIT = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Honeypot Cowrie - rapport d'analyse</title>
<style>
body {
  max-width: 46em;
  margin: 2em auto;
  padding: 0 1em;
  font-family: Georgia, "Times New Roman", serif;
  font-size: 15px;
  line-height: 1.5;
  color: #111;
  background: #fff;
}
h1 { font-size: 1.4em; margin-bottom: 0.2em; }
h2 { font-size: 1.05em; margin-top: 2em; }
p.sous-titre { margin-top: 0; color: #555; font-size: 0.9em; }
table { border-collapse: collapse; margin-bottom: 1em; width: 100%; }
th, td { text-align: left; padding: 3px 10px 3px 0; border-bottom: 1px solid #ddd; }
th { font-weight: normal; font-style: italic; color: #555; }
td.n { text-align: right; white-space: nowrap; }
td.v { font-family: Consolas, monospace; font-size: 0.85em; word-break: break-all; }
td.vide { color: #777; font-style: italic; }
table.heures { table-layout: fixed; }
table.heures td { border: none; padding: 0 1px; vertical-align: bottom; }
table.heures td.etiq { text-align: center; font-size: 0.7em; color: #777; padding-top: 2px; }
table.heures div { background: #666; }
p.note { color: #555; font-size: 0.9em; }
@media print { body { margin: 0; } }
</style>
</head>
<body>

<h1>Honeypot SSH Cowrie - rapport d'analyse</h1>
<p class="sous-titre">Periode du __DEBUT__ au __FIN__, soit __JOURS__ jours.
Genere le __GENERE__.</p>

<table>
__RESUME__
</table>

<h2>Connexions par heure (UTC)</h2>
<table class="heures">
<tr>__BARRES__</tr>
<tr>__ETIQUETTES__</tr>
</table>
<p class="note">Maximum a __H_MAX__ h (__V_MAX__ connexions), minimum a __H_MIN__ h
(__V_MIN__). Le rapport entre les deux est de __RATIO__.</p>

__TABLEAUX__

<p class="note">Produit par analyse.py puis rapport.py a partir des journaux
JSON de Cowrie. Les journaux bruts et les fichiers deposes par les attaquants
restent sur le serveur.</p>

</body>
</html>
"""


def espace(n):
    """12345 -> 12 345"""
    return "{:,}".format(n).replace(",", " ")


def ligne_resume(libelle, valeur):
    return "<tr><td>%s</td><td class=\"n\">%s</td></tr>" % (libelle, valeur)


def tableau(titre, lignes, limite=15, entete="Valeur"):
    corps = ""
    for valeur, n in lignes[:limite]:
        corps += "<tr><td class=\"v\">%s</td><td class=\"n\">%s</td></tr>" % (
            html.escape(str(valeur)), espace(n))
    if not corps:
        corps = "<tr><td class=\"vide\" colspan=\"2\">rien a signaler</td></tr>"
    return ("<h2>%s</h2>\n<table>\n"
            "<tr><th>%s</th><th class=\"n\">Occurrences</th></tr>\n%s</table>\n"
            % (html.escape(titre), entete, corps))


def construire(stats):
    t = stats["totaux"]
    p = stats["periode"]

    resume = "".join([
        ligne_resume("Connexions", espace(t["connexions"])),
        ligne_resume("Adresses IP distinctes", espace(t["ip_uniques"])),
        ligne_resume("Tentatives d'authentification", espace(t["tentatives"])),
        ligne_resume("dont refusees", espace(t["echecs"])),
        ligne_resume("dont acceptees", "%s (%s %%)" % (
            espace(t["succes"]),
            ("%.1f" % t["taux_de_succes"]).replace(".", ","))),
        ligne_resume("Sessions ayant lance une commande",
                     espace(t["sessions_avec_commandes"])),
        ligne_resume("Commandes executees", espace(t["commandes"])),
        ligne_resume("Fichiers deposes", espace(t["telechargements"])),
        ligne_resume("Ouvertures de tunnel demandees", espace(t["tunnels"])),
    ])

    heures = stats["par_heure"]
    maxi = max(heures) or 1
    mini = min(heures)
    barres = "".join(
        "<td><div style=\"height:%dpx\" title=\"%02d h : %d connexions\"></div></td>"
        % (max(1, round(v / maxi * 90)), h, v) for h, v in enumerate(heures))
    etiquettes = "".join("<td class=\"etiq\">%02d</td>" % h for h in range(24))

    top = stats["top"]
    tableaux = "".join([
        tableau("Adresses IP les plus actives", top["ip"], entete="Adresse"),
        tableau("Identifiants testes", top["utilisateurs"], entete="Identifiant"),
        tableau("Mots de passe testes", top["mots_de_passe"], entete="Mot de passe"),
        tableau("Couples identifiant / mot de passe", top["combos"],
                entete="Couple"),
        tableau("Clients SSH annonces", top["clients_ssh"], entete="Banniere"),
        tableau("Commandes les plus frequentes", top["commandes"], limite=12,
                entete="Commande"),
        tableau("Empreintes SHA-256 des fichiers deposes", top["empreintes"],
                entete="Empreinte"),
        tableau("Cibles des tentatives de tunnel", top["cibles_tunnel"],
                entete="Destination"),
        tableau("Techniques ATT&CK declenchees",
                [("%s %s" % (tid, nom), n) for tid, nom, n in stats["mitre"]],
                limite=20, entete="Technique"),
    ])

    page = GABARIT
    for cle, valeur in [
        ("__DEBUT__", (p["debut"] or "?")[:10]),
        ("__FIN__", (p["fin"] or "?")[:10]),
        ("__JOURS__", str(p["jours"])),
        ("__GENERE__", stats["genere_le"]),
        ("__RESUME__", resume),
        ("__BARRES__", barres),
        ("__ETIQUETTES__", etiquettes),
        ("__H_MAX__", "%02d" % heures.index(maxi)),
        ("__V_MAX__", espace(maxi)),
        ("__H_MIN__", "%02d" % heures.index(mini)),
        ("__V_MIN__", espace(mini)),
        ("__RATIO__", ("%.1f" % (maxi / mini)).replace(".", ",") if mini else "-"),
        ("__TABLEAUX__", tableaux),
    ]:
        page = page.replace(cle, valeur)
    return page


def main():
    parseur = argparse.ArgumentParser(description="Rapport HTML du honeypot")
    parseur.add_argument("stats", help="fichier JSON produit par analyse.py")
    parseur.add_argument("-o", "--sortie", default="rapport.html")
    args = parseur.parse_args()

    with open(args.stats, encoding="utf-8") as f:
        stats = json.load(f)

    with open(args.sortie, "w", encoding="utf-8") as f:
        f.write(construire(stats))
    print("ecrit : %s" % args.sortie)
    return 0


if __name__ == "__main__":
    sys.exit(main())
