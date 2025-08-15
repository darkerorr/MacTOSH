#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Crackito OSINT Multi-Tool — Red-Tiger Style Menu (3 colonnes)
Dépendances: requests, bs4, python-whois
Installer: pip3 install requests beautifulsoup4 python-whois
"""

import requests
from bs4 import BeautifulSoup
import whois
import re
import socket
import ssl
import sys
import os
import json
import time
from urllib.parse import urlparse

# ============================
# Couleurs ANSI & helpers UI
# ============================
R = "\033[1;31m"  # rouge
G = "\033[1;32m"  # vert
Y = "\033[1;33m"  # jaune
B = "\033[1;34m"  # bleu
M = "\033[1;35m"  # magenta
C = "\033[1;36m"  # cyan
W = "\033[0m"     # reset
DIM = "\033[2m"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    clear()
    print(f"""{M}
██╗  ██╗██████╗  █████╗  ██████╗██╗  ██╗████████╗ ██████╗ 
██║ ██╔╝██╔══██╗██╔══██╗██╔════╝██║  ██║╚══██╔══╝██╔═══██╗
█████╔╝ ██████╔╝███████║██║     ███████║   ██║   ██║   ██║
██╔═██╗ ██╔══██╗██╔══██║██║     ██╔══██║   ██║   ██║   ██║
██║  ██╗██║  ██║██║  ██║╚██████╗██║  ██║   ██║   ╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ 
{W}{DIM}                    Multi-Tool OSINT  —  Red-Tiger Style{W}
""")

def make_boxed_menu(options, cols=3, width=78):
    """
    options: list of "label" strings already numbered like "[1] ..."
    Affichage en N colonnes avec bordure ASCII.
    """
    # calcul largeur par colonne
    inner_width = width - 2
    col_width = inner_width // cols
    # regroupe par lignes
    lines = []
    for i in range(0, len(options), cols):
        chunk = options[i:i+cols]
        padded = []
        for item in chunk:
            # tronque et pad
            txt = item[:col_width-1].ljust(col_width)
            padded.append(txt)
        while len(padded) < cols:
            padded.append("".ljust(col_width))
        lines.append(padded)

    top = "╔" + "═"*inner_width + "╗"
    bot = "╚" + "═"*inner_width + "╝"
    body = []
    for row in lines:
        body.append("║" + "".join(row) + "║")
    return "\n".join([top] + body + [bot])

def pause():
    input(f"\n{DIM}Appuyez sur Entrée pour revenir au menu…{W}")

# ============================
# Outils OSINT
# ============================

def normalize_target(user_input: str):
    """
    Retourne (url, domain) cohérents.
    """
    if not user_input.startswith(("http://", "https://")):
        url = "https://" + user_input.strip()
    else:
        url = user_input.strip()
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]
    return url, domain

def website_scan(url):
    try:
        t0 = time.time()
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        dt = (time.time()-t0)*1000
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else "Pas de titre"
        print(f"{G}[+] Titre:{W} {title}")
        print(f"{G}[+] Status:{W} {r.status_code}  {G}Temps:{W} {dt:.0f} ms")
        # meta description + keywords
        desc = soup.find("meta", attrs={"name":"description"})
        if desc and desc.get("content"):
            print(f"{G}[+] Meta description:{W} {desc.get('content')[:200]}")
        keys = soup.find("meta", attrs={"name":"keywords"})
        if keys and keys.get("content"):
            print(f"{G}[+] Mots-clés:{W} {keys.get('content')[:200]}")
        # liens
        links = [a.get("href") for a in soup.find_all("a") if a.get("href")]
        print(f"{G}[+] Liens trouvés:{W} {len(links)} (aperçu 15)")
        for l in links[:15]:
            print("   -", l)
    except Exception as e:
        print(f"{R}[-] Erreur website_scan:{W} {e}")

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        fields = ['domain_name','registrar','creation_date','expiration_date','status','emails','name_servers']
        for k in fields:
            print(f"{G}{k}:{W} {w.get(k)}")
    except Exception as e:
        print(f"{R}[-] Erreur whois:{W} {e}")

def extract_emails_from_page(url):
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text))
        print(f"{G}[+] Emails trouvés ({len(emails)}):{W}")
        for e in sorted(emails):
            print("  -", e)
    except Exception as e:
        print(f"{R}[-] Erreur emails:{W} {e}")

def http_headers(url):
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        print(f"{G}[+] En-têtes HTTP:{W}")
        for k, v in r.headers.items():
            print(f"  - {k}: {v}")
    except Exception as e:
        print(f"{R}[-] Erreur headers:{W} {e}")

def ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{G}[+] IP:{W} {ip}")
        return ip
    except Exception as e:
        print(f"{R}[-] Erreur DNS:{W} {e}")

def quick_port_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{G}[+] Scan rapide de ports sur {ip}{W}")
        common = [21,22,25,53,80,110,143,443,465,587,993,995,8080,8443]
        for p in common:
            s = socket.socket()
            s.settimeout(0.5)
            res = s.connect_ex((ip, p))
            if res == 0:
                print(f"  - Port {p} {G}OUVERT{W}")
            s.close()
    except Exception as e:
        print(f"{R}[-] Erreur port scan:{W} {e}")

def fetch_robots(url):
    if not url.endswith("/"):
        url += "/"
    try:
        r = requests.get(url+"robots.txt", timeout=10)
        if r.status_code == 200:
            print(f"{G}[+] robots.txt:{W}\n{r.text}")
        else:
            print(f"{Y}[!] robots.txt non trouvé (status {r.status_code}){W}")
    except Exception as e:
        print(f"{R}[-] Erreur robots:{W} {e}")

def detect_cms_and_tech(url):
    """
    Heuristiques : meta generator, X-Powered-By, cookies WordPress/PHPSESSID, headers Server, fichiers classiques.
    """
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        tech = set()

        gen = soup.find("meta", attrs={"name":"generator"})
        if gen and gen.get("content"):
            tech.add(f"Generator: {gen.get('content')}")

        # Headers
        srv = r.headers.get("Server")
        xpb = r.headers.get("X-Powered-By")
        if srv: tech.add(f"Server: {srv}")
        if xpb: tech.add(f"X-Powered-By: {xpb}")

        # Cookies
        cookies = r.headers.get("Set-Cookie","")
        if "wordpress" in cookies.lower(): tech.add("WordPress (cookie)")
        if "php" in cookies.lower(): tech.add("PHP (cookie)")
        if "laravel" in cookies.lower(): tech.add("Laravel (cookie)")
        if "django" in cookies.lower(): tech.add("Django (cookie)")

        # Patterns HTML
        html = r.text.lower()
        if "/wp-content/" in html: tech.add("WordPress (wp-content)")
        if "content=\"drupal" in html: tech.add("Drupal (generator)")
        if "content=\"joomla" in html: tech.add("Joomla (generator)")
        if "shopify" in html: tech.add("Shopify")
        if "woocommerce" in html: tech.add("WooCommerce")
        if "__next" in html: tech.add("Next.js (marker)")
        if "react" in html and "root" in html: tech.add("React (heuristique)")

        # Fichiers communs
        indicators = [("wp-login.php", "WordPress (wp-login.php)"),
                      (".env", ".env (dangereux si accessible!)"),
                      ("admin/", "Répertoire admin/")]
        for path, label in indicators:
            try:
                test = requests.get(url.rstrip("/") + "/" + path, timeout=5)
                if test.status_code in (200, 401, 403):
                    tech.add(label)
            except:
                pass

        if tech:
            print(f"{G}[+] Technologies détectées:{W}")
            for t in sorted(tech):
                print("  -", t)
        else:
            print(f"{Y}[!] Rien de probant détecté via heuristiques.{W}")
    except Exception as e:
        print(f"{R}[-] Erreur detect_cms_and_tech:{W} {e}")

def username_scan(username):
    """
    Check basique sur quelques plateformes (HEAD -> GET fallback).
    """
    targets = {
        "GitHub": f"https://github.com/{username}",
        "X(Twitter)": f"https://x.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
    }
    for name, url in targets.items():
        try:
            r = requests.head(url, timeout=8, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
            if r.status_code >= 400:
                r = requests.get(url, timeout=8, allow_redirects=True, headers={"User-Agent":"Mozilla/5.0"})
            exists = r.status_code < 400
            print(f" - {name:<10} {G if exists else R}{'EXISTE' if exists else 'ABSENT'}{W}  ({r.status_code}) {DIM}{url}{W}")
        except Exception as e:
            print(f" - {name:<10} {Y}INCONNU{W}  ({e})")

def subdomain_scan(domain):
    """
    Petit wordlist intégré (rapide). Pour du lourd, utiliser une wordlist externe.
    """
    wordlist = ["www","mail","dev","test","api","blog","staging","admin","cdn","img","static","vpn","portal","m","beta"]
    print(f"{G}[+] Scan de sous-domaines sur:{W} {domain}")
    for sub in wordlist:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            print(f"  - {host:<30} {G}{ip}{W}")
        except:
            pass

def ip_geolocate(ip_or_domain):
    """
    Utilise ip-api.com (gratuit). Peut être limité par le réseau.
    """
    try:
        ip = ip_or_domain
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_or_domain):
            ip = socket.gethostbyname(ip_or_domain)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query,timezone"
        r = requests.get(url, timeout=10)
        data = r.json()
        if data.get("status") == "success":
            print(f"{G}[+] IP:{W} {data.get('query')}")
            print(f"    {data.get('country')} / {data.get('regionName')} / {data.get('city')}")
            print(f"    ISP: {data.get('isp')} | ORG: {data.get('org')} | AS: {data.get('as')}")
            print(f"    Timezone: {data.get('timezone')}")
        else:
            print(f"{Y}[!] Impossible d’obtenir la géolocalisation.{W}")
    except Exception as e:
        print(f"{R}[-] Erreur geoloc:{W} {e}")

def ssl_info(domain):
    """
    Récupère le certificat TLS (sans SNI avancée).
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        print(f"{G}[+] Sujet:{W} {subject.get('commonName')}")
        print(f"{G}[+] Emetteur:{W} {issuer.get('commonName')}")
        print(f"{G}[+] Valide du:{W} {cert.get('notBefore')}  {G}au:{W} {cert.get('notAfter')}")
    except Exception as e:
        print(f"{R}[-] Erreur SSL:{W} {e}")

def http_methods(url):
    try:
        r = requests.options(url, timeout=10)
        allow = r.headers.get("Allow") or r.headers.get("allow")
        if allow:
            print(f"{G}[+] Méthodes autorisées:{W} {allow}")
        else:
            print(f"{Y}[!] En-tête Allow non présent. (OPTIONS status {r.status_code}){W}")
    except Exception as e:
        print(f"{R}[-] Erreur OPTIONS:{W} {e}")

def dorks_builder(domain):
    base = f"site:{domain}"
    dorks = [
        f"{base} intitle:index.of",
        f"{base} ext:sql | ext:env | ext:log",
        f"{base} inurl:admin | inurl:login",
        f"{base} \"password\" OR \"mot de passe\"",
        f"{base} filetype:pdf | filetype:docx | filetype:xlsx",
        f"{base} \"confidential\" | \"interne\"",
        f"{base} inurl:backup | inurl:old | inurl:test",
    ]
    print(f"{G}[+] Google Dorks pour {domain}:{W}")
    for d in dorks:
        print("  -", d)

def fetch_sitemap(url):
    if not url.endswith("/"):
        url += "/"
    for path in ["sitemap.xml", "sitemap_index.xml"]:
        try:
            r = requests.get(url + path, timeout=10)
            if r.status_code == 200:
                print(f"{G}[+] {path}:{W}\n{r.text[:3000]}")
                return
        except:
            pass
    print(f"{Y}[!] sitemap non trouvé.{W}")

def status_and_time(url):
    try:
        t0 = time.time()
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        dt = (time.time()-t0)*1000
        print(f"{G}[+] Statut:{W} {r.status_code}  —  {G}Temps:{W} {dt:.0f} ms")
        print(f"{G}[+] Taille réponse:{W} {len(r.content)} octets")
    except Exception as e:
        print(f"{R}[-] Erreur requête:{W} {e}")

def wayback_check(domain):
    try:
        api = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1"
        r = requests.get(api, timeout=10)
        if r.status_code == 200 and r.text.strip():
            data = json.loads(r.text)
            if len(data) > 1:
                print(f"{G}[+] Snapshot Wayback disponible.{W}")
            else:
                print(f"{Y}[!] Pas de snapshot Wayback trouvé.{W}")
        else:
            print(f"{Y}[!] Wayback non concluant.{W}")
    except Exception as e:
        print(f"{R}[-] Erreur Wayback:{W} {e}")

def email_hunt_follow_links(url, max_pages=5):
    """
    Suit les 1ers liens internes (max_pages) et agrège les emails.
    """
    try:
        base = urlparse(url).netloc
        r = requests.get(url, timeout=10, headers={"User-Agent":"Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "html.parser")
        pool = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/"):
                href = f"{urlparse(url).scheme}://{base}{href}"
            if href.startswith(("http://","https://")) and urlparse(href).netloc.endswith(base):
                pool.append(href)
            if len(pool) >= max_pages:
                break
        emails = set()
        for link in [url] + pool:
            try:
                rr = requests.get(link, timeout=8, headers={"User-Agent":"Mozilla/5.0"})
                emails |= set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", rr.text))
            except:
                pass
        print(f"{G}[+] Emails trouvés sur {len(pool)+1} page(s):{W} {len(emails)}")
        for e in sorted(emails):
            print("  -", e)
    except Exception as e:
        print(f"{R}[-] Erreur email_hunt:{W} {e}")

# ============================
# Menu & routing
# ============================

OPTIONS = [
    "[1]  Scan site web + liens",
    "[2]  Whois lookup",
    "[3]  Extraction d’emails (page)",
    "[4]  En-têtes HTTP",
    "[5]  IP lookup",
    "[6]  Scan rapide de ports",
    "[7]  Télécharger robots.txt",
    "[8]  Détection CMS & technologies",
    "[9]  Recherche username multi-sites",
    "[10] Scan de sous-domaines",
    "[11] Géolocalisation IP",
    "[12] Infos certificat SSL",
    "[13] Méthodes HTTP autorisées",
    "[14] Google Dorks builder",
    "[15] Télécharger sitemap",
    "[16] Statut & temps de réponse",
    "[17] Wayback snapshot check",
    "[18] Email hunter (liens internes)",
    "[0]  Quitter",
]

def print_menu():
    banner()
    colored = []
    for item in OPTIONS:
        # Colorise le numéro et garde le label blanc
        num, label = item.split("]", 1)
        colored.append(f"{C}{num}]{W}{label}")
    print(make_boxed_menu(colored, cols=3, width=90))
    print()

def main():
    while True:
        print_menu()
        choice = input(f"{Y}Sélectionnez une option:{W} ").strip()
        if choice == "0":
            print(f"{G}Bye!{W}")
            sys.exit(0)

        # Récupération arguments selon l’outil
        if choice in {"1","3","4","7","8","15","16","18"}:
            target_in = input(f"{C}Entrez une URL (ex: https://example.com): {W}").strip()
            url, domain = normalize_target(target_in)
        elif choice in {"2","5","6","10","12","14","17"}:
            target_in = input(f"{C}Entrez un domaine (ex: example.com): {W}").strip()
            url, domain = normalize_target(target_in)
        elif choice in {"9"}:
            username = input(f"{C}Nom d’utilisateur à rechercher: {W}").strip()
        elif choice in {"11","13"}:
            target_in = input(f"{C}Entrez un IP ou domaine (ex: 8.8.8.8 / example.com): {W}").strip()
            # pas forcément URL
        else:
            print(f"{R}Option invalide.{W}")
            time.sleep(1)
            continue

        # Routing
        print()
        if choice == "1":
            website_scan(url)
        elif choice == "2":
            whois_lookup(domain)
        elif choice == "3":
            extract_emails_from_page(url)
        elif choice == "4":
            http_headers(url)
        elif choice == "5":
            ip_lookup(domain)
        elif choice == "6":
            quick_port_scan(domain)
        elif choice == "7":
            fetch_robots(url)
        elif choice == "8":
            detect_cms_and_tech(url)
        elif choice == "9":
            username_scan(username)
        elif choice == "10":
            subdomain_scan(domain)
        elif choice == "11":
            ip_geolocate(target_in)
        elif choice == "12":
            ssl_info(domain)
        elif choice == "13":
            # si IP -> convertir en URL http://IP
            t = target_in.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
                u = f"http://{t}"
            elif t.startswith(("http://","https://")):
                u = t
            else:
                u = "https://" + t
            http_methods(u)
        elif choice == "14":
            dorks_builder(domain)
        elif choice == "15":
            fetch_sitemap(url)
        elif choice == "16":
            status_and_time(url)
        elif choice == "17":
            wayback_check(domain)
        elif choice == "18":
            email_hunt_follow_links(url)
        else:
            print(f"{R}Option inconnue.{W}")

        pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Interrompu par l’utilisateur.{W}")
