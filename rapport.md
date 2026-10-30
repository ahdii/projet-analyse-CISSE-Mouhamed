# Rapport — Analyse des journaux du pare-feu (semaine du 5 octobre 2026)

## 1. Résumé
Après nettoyage (60 doublons supprimés, protocoles mis en majuscules, 166 valeurs `bytes_sent`
manquantes remplacées par la médiane), il reste **5 440 connexions**. Le trafic est dominé par
HTTPS (port 443, le plus fréquent), suivi de HTTP, DNS et MQTT. Le taux de connexions bloquées
est de **13,57 %**, avec beaucoup de refus sur des ports sensibles (Telnet 23, RDP 3389).
Deux comportements anormaux ressortent nettement : un **scan de ports** depuis `192.168.1.99`
et une **fuite de données probable** depuis la caméra `192.168.1.11`.

## 2. Comportements suspects

### a) Scan de ports : `192.168.1.99`
- **328 ports distincts** contactés en 400 connexions, tous vers `10.0.0.5`, alors que les autres
  machines n'en contactent que **8 au maximum**.
- Tout s'est passé en **15 minutes** (le 8 octobre entre 00:00 et 00:15) : c'est le pic de la
  figure `connexions_par_heure.png` à minuit.
- **383 connexions sur 400 ont été refusées** (DENY) : le pare-feu a bloqué l'essentiel, mais
  17 ont été autorisées, donc le scanner a trouvé des ports ouverts.
- Preuve : `figures/ports_distincts_par_ip.png`.

### b) Exfiltration de données : `192.168.1.11` (caméra IoT)
- Cette caméra a envoyé **environ 260 Mo**, soit **94,7 %** de tout le volume du réseau.
  La 2e machine n'envoie que 0,6 Mo.
- Les plus gros envois (jusqu'à 8,7 Mo par connexion) partent vers `8.8.8.8` sur le **port 8080**
  et ont été **autorisés** (ALLOW), à toute heure, y compris la nuit.
- Une caméra n'a aucune raison d'envoyer autant de données vers l'extérieur : elle est
  probablement compromise.
- Preuve : `figures/octets_par_ip.png` et `figures/octets_par_appareil.png`.

## 3. Recommandations
1. **Bloquer et alerter sur les scans** : règle de limitation du débit de connexions par IP source
   et alerte (IDS/Snort) quand une IP touche plus de ~20 ports en quelques minutes.
2. **Isoler la caméra `192.168.1.11`** : la mettre en quarantaine, l'analyser, changer ses
   identifiants et mettre à jour son firmware.
3. **Segmenter les objets IoT** dans un VLAN dédié, avec une règle par défaut « tout refuser vers
   Internet » et seulement les flux nécessaires autorisés (ex. MQTT vers le broker interne).
4. **Fermer Telnet (23)** et restreindre RDP (3389) et SSH (22) à des machines d'administration
   identifiées, via VPN ; remplacer Telnet par SSH.
5. **Surveiller les volumes sortants** : alerte si une IP dépasse un seuil d'octets par heure.

## 4. Limites
Les adresses `8.8.8.8` et `1.1.1.1` sont ici des destinations de test : en réel, on
vérifierait la réputation de l'IP de destination avant de conclure.
