# Deux comptes : `store` (licence) et `play` (identité en jeu)

> **Statut : backend implémenté et testé (branche `dual-account`).** Reste :
> intégration dans le fork Nexus (lock, connexion du compte `play`, affichage),
> puis test manuel en jeu.
>
> Objectif : reproduire Windows. Le compte qui a le Game Pass (`store`) ne sert
> qu'aux licences, en arrière-plan, comme le Microsoft Store. Tout ce que
> l'utilisateur voit (identité en jeu, gamertag, succès, temps de jeu, cloud
> saves), en jeu comme dans le launcher, est le compte perso (`play`), comme
> l'app Xbox.
>
> Maintenu comme forks ([xodus-dual-account](https://github.com/PinkFloyd1213/xodus-dual-account),
> [xodus-nexus-dual-account](https://github.com/PinkFloyd1213/xodus-nexus-dual-account)),
> mais écrit pour rester fusionnable : changements additifs, aucun refactoring,
> comportement identique tant qu'aucun compte `play` n'est configuré.

## Base de travail

| Élément | Valeur |
|---|---|
| Nexus lu | `domsvoboda/xodus-nexus` @ `59fb0798f034` (21.10.2026) |
| Lock backend | version `0.2.10`, commit `53ea781dcd07`, patchId `linux-run-v38`, compatibility `linux-run-v22`, rust `1.99.0` |
| `Cargo.lock` | sha256 conforme au lock (`2259b343…`) |
| Branche `nexus-base` | commit fixé + 38 patches du lock, appliqués dans l'ordre (`git apply --check` puis `git apply`, comme `backend.ts` et `scripts/build-backend.mjs`), un commit par patch, sha256 vérifié pour chacun |
| Build | `cargo build --locked --release --no-default-features -p xodus-cli -p xodus-service` avec rustc 1.99.0 : OK |
| Capacités | `--help` expose tout ce que `parseBackendHelp`/`validate()` et `build-backend.mjs` attendent (account, profile, game-activity, achievements, library, login, logout, download, streaming, run, resolve-package, keyring-*, `--external-webview-stdio`, `--progress-json`, `--control-stdin`, `--download-limit-kib`, `--selected-content-id`, `run --materialize-chain`). Aucune librairie webview native liée. |

Remarque : le lock ne contient **pas** de `LINUX_RUN_PATCH` séparé.
`LINUX_RUN_PATCH` est simplement `lock.compatibility` (`linux-run-v22`) ; le
« patch linux-run » est `xodus-linux-run.patch`, le premier de la liste.

## Stockage actuel (état patché)

`TokenManager` (`crates/xodus/src/tokens/manager.rs`) écrit dans le trousseau
Secret Service, collection/service `Xodus Service`, sous ces clés :

| Clé | Contenu | Rôle |
|---|---|---|
| `user-session` | compte + jeu complet de STS (format écrit par `login` depuis `xodus-keyring-credentials`) | utilisateur |
| `user-tokens`, `user-DA` | ancien format éclaté, encore lu si `user-session` est absent | utilisateur |
| `device-tokens` | STS appareil | appareil |
| `dev_license` | identité + licence appareil | appareil |
| `nexus-subscription-v2` | cache 10 min de l'abonnement, lié au `username` (`commands/subscription.rs`) | `store` |

Le cache XSTS éphémère (`get_cached_xsts`/`cache_xsts`, en mémoire) n'a
**aucun appelant** aujourd'hui.

## Ce que le jeu envoie au service

Le runtime Wine de Nexus (`assets/xgameruntime-*.patch`) n'envoie que quatre
messages à `xodus-service` (`crates/xodus/proto/xodus/common.proto`) :
`PING`, `MSA_TOKEN_REQUEST`, `STORE_LICENSE_TOKEN_REQUEST`,
`STORE_PACKAGE_UPDATES_REQUEST`. Le chemin protobuf est `unimplemented!`.

Tout le reste est fait **dans le runtime** à partir du token renvoyé par
`MSA_TOKEN_REQUEST` : XUser, XSTS des services de jeu, cloud saves
(`titlestorage.xboxlive.com/connectedstorage/users/xuid(...)`, via
`xuser_device_authorization`), gamerpic, etc. Router `MSA_TOKEN_REQUEST` vers
`play` suffit donc à faire passer **toute** l'identité en jeu par `play`.

Les API XStore du runtime (`xstore_entitled.h`, `xstore_receipts.h`,
licence de package) ne passent **que** par `STORE_LICENSE_TOKEN_REQUEST`. Elles
lisent l'XUID de l'XUser mais ne l'envoient pas au service. Le patch le dit
explicitement : *« The existing receipt transport uses the service's
authenticated Store account, not Xbox profile metadata. »*

## Cartographie

Chemins relatifs à `crates/`. Lignes dans l'état `nexus-base`.

### Modèle (`xodus`)

| Emplacement | Fonction | Rôle proposé | Justification |
|---|---|---|---|
| `xodus/src/tokens/manager.rs:10-16` | clés du trousseau | `store` = clés actuelles ; `play` = `play/user-session` (+ `play/user-tokens`, `play/user-DA` pour symétrie) | aucune migration ; l'existant devient `store` |
| `manager.rs:65` | `remove_persistent` | `store` (+ `device-tokens`, comme aujourd'hui) | comportement actuel de `logout` |
| `manager.rs:76-109` | device license / device STS | appareil, partagé | un seul appareil, comme sous Windows |
| `manager.rs:113` `:120` `:132` | `get_user_token_for`, `save_user_token`, `get_user_sts_token` | paramétrés par rôle | cœur du changement |
| `manager.rs:139` `:150` `:158` `:168` | `get_user`, `save_user`, `user_session`, `save_user_session` | paramétrés par rôle | idem |
| `manager.rs:186-205` | cache XSTS éphémère | inchangé | pas d'appelant ; s'il en a un un jour, la clé doit inclure le rôle (noté en commentaire) |
| `xodus/src/tokens/device.rs:12` `:36` | `ensure_device_credentials`, `refresh_existing_device_credentials` | appareil | n'utilisent pas de compte |
| `xodus/src/auth.rs:70-187` | `do_sisu` (lit puis réécrit le STS utilisateur, `:83`, `:149`) | inchangé (`store`) | seul appelant : un test `#[ignore]` ; ne pas l'étendre (diff minimal) |
| `xodus/src/auth.rs:32` `:49` `:62` | `start_new_session`, `get_xsts_token`, `refresh_tokens` | n/a | ne touchent pas au `TokenManager`, aucun appelant |
| `xodus/src/licensing/content.rs:19` `:62` | `get_license_content`, `get_license_token` | `store` (par l'appelant) | reçoivent les tokens en paramètre |

### Service (`xodus-service`)

| Emplacement | Fonction | Rôle proposé | Justification |
|---|---|---|---|
| `xodus-service/src/main.rs:47-63` | `ensure_device_credentials` + device STS au démarrage | appareil | |
| `connection/xml.rs:52-138` (`:57` lecture, `:115` écriture) | `MsaTokenRequest` (XUser, `xgameruntime.dll`) | **`play`**, repli `store` ; le STS rafraîchi est réécrit dans le rôle **effectivement lu** | identité en jeu ; tous les XSTS de jeu, cloud saves, succès, présence en découlent |
| `connection/xml.rs:47` → `store_license.rs:57-99` (`:59` STS, `:60` compte) | `StoreLicenseTokenRequest` (XStore : entitlements, DLC, reçus, licence de package) | **`store`** | Sous Windows, XStore utilise le compte du Microsoft Store. Le runtime n'envoie pas l'XUID. Voir l'ambiguïté A2. |
| `connection/xml.rs:43` → `store_updates.rs:282-333` (`:304`) | `StorePackageUpdatesRequest` (XSTS `update.xboxlive.com` → `GetBasePackage`) | **`store`** | accès au package = droit du compte qui possède le jeu |
| `connection/proto.rs:4` | protobuf | n/a | `unimplemented!` |
| `connection/router.rs`, `simple_context.rs` | contexte | portent un `TokenManager` partagé, pas de changement de structure | |

### CLI (`xodus-cli`)

| Emplacement | Fonction | Rôle proposé | Justification |
|---|---|---|---|
| `main.rs:273` | construction du `TokenManager` | inchangé | |
| `main.rs:327-354` | `account [--json]` | `store` par défaut ; `--account play` ; champ optionnel `roles` en JSON (voir le design) | Nexus lit `stored` / `username` (`account-refresh.ts`) |
| `main.rs:358` + `commands/login.rs:13-79` (`:14` cache abo, `:15` device, `:73` save) | `login` | `store` par défaut (Nexus, `externalAuth` inchangés) ; `--account play` | `play` n'efface pas le cache d'abonnement |
| `main.rs:359` + `commands/logout.rs:4-15` | `logout [--device]` | voir l'ambiguïté A5 | |
| `license.rs:7-98` (`:13` device, `:19-21` compte + STS) | `get_license` (licence de contenu, clés de déchiffrement) | **`store`** | appelé par `streaming` (`commands/streaming.rs:422`), `run` (`commands/run.rs:508`), `license`, `extract` |
| `license.rs:100-118` | `license_material` (device license) | appareil | |
| `package.rs:18-59` (`:23` device, `:27` STS) | `get_packages` (XSTS `update.xboxlive.com`) | **`store`** | `download` (`commands/download.rs:30`), `streaming` (`:145`) |
| `commands/library.rs:99-160` | `library` (entitlements `beige.xboxservices.com`) | **`store`** | bibliothèque / Game Pass |
| `commands/subscription.rs:100-221` | `store_session`, abonnement + cache | **`store`** | Game Pass |
| `commands/run.rs:27-37`, `:657-659` | `playfab_auth_header` → `XODUS_XSTS_PLAYFAB` passé au jeu | **`play`** | XSTS PlayFab = identité du joueur |
| `commands/run.rs:508` | `get_license` au lancement | **`store`** | licence |
| `commands/session.rs:16-84` | `prepare` (STS + device, contrôle « account-changed ») | rôle de l'appelant | helper générique |
| `commands/profile.rs:49-73` | `xbox_session` (XSTS `xboxlive.com`) | rôle de l'appelant | helper |
| `commands/profile.rs:75-112` | `profile --json` : gamertag/gamerpic + abonnement | **ambigu (A1)** : gamertag `play`, abonnement `store` | |
| `commands/game_activity.rs:61-104` | `game-activity` | **ambigu (A1)** | donnée du joueur |
| `commands/achievements.rs:89-128` | `achievements` | **ambigu (A1)** | donnée du joueur |
| `commands/clep.rs`, `splicense.rs`, `extract_eappx.rs`, `resolve-package`, `keyring-*` | | aucun compte | |

## Cas ambigus et points à trancher

**A1 — `profile`, `achievements` et `game-activity` vus par Nexus (décision requise).**
Nexus rejette toute réponse dont `account` diffère du `username` renvoyé par
`account --json` : voir `game-achievements.ts:19`, `game-activity.ts:42`,
`account-profile.ts:90` et `account-library.ts:22`. Ces commandes ne sont pas
vues par le jeu, seulement par l'interface Nexus.

- **Option A (recommandée pour la phase 2)** : défaut `store`, comportement
  identique à aujourd'hui, plus `--account play` pour l'usage en terminal.
  Nexus affichera le gamertag et les succès du compte `store`, ce qui est
  cohérent avec le compte qu'il montre.
- **Option B** : par défaut, gamertag, succès et activité viennent de `play`
  quand il est configuré, mais `account` garde le `username` `store` pour que
  Nexus accepte la réponse. Un champ optionnel `playAccount` est ajouté. Le
  format est inchangé, mais le sens de `account` change. C'est discutable pour
  une PR upstream et fragile si Nexus évolue.

**A2 — XStore : le reçu de licence porte l'identité `store`.**
`store_license.rs` met le ticket MSA et le PUID du compte `store` dans
`beneficiaries`. C'est le comportement Windows (le Store émet avec son compte),
donc → `store`. Risque : un éditeur qui croise, côté serveur, le bénéficiaire du
reçu avec l'XUID du joueur (`play`) peut refuser un DLC ou une monnaie. Il n'y a
pas de correctif côté Xodus : Windows a le même comportement. On le documente
dans le plan de test.

**A3 — STS rafraîchi par `MsaTokenRequest`.** On résout le rôle effectif
**une fois** (`play` s'il existe, sinon `store`) et on écrit dans ce rôle-là.
En repli, c'est donc le STS `store` qui est rafraîchi, exactement comme
aujourd'hui. Une session `play` ne peut jamais écrire dans `store`. Ce choix
évite aussi une course si `play` est connecté pendant qu'une requête est en
cours.

**A4 — PlayFab.** `XODUS_XSTS_PLAYFAB` est l'identité PlayFab du joueur → `play`,
avec repli `store`.

**A5 — `logout` sans option.** Proposition : comportement **strictement
identique** à aujourd'hui (utilisateur `store` + `device-tokens`, cache
d'abonnement), et `play` est **conservé**. Raisons : Nexus appelle `logout`
pour son propre compte. Une déconnexion Nexus qui effacerait aussi `play`
surprendrait. `play` seul ne donne accès à rien sans `store`.
`logout --account play` ne supprime que les clés `play/*`. Il ne touche ni à
l'appareil, ni au cache d'abonnement. `--device` reste réservé à `store`.

**A6 — Changement de compte en cours de partie.** Le service relit le trousseau
à chaque requête. Un `login --account play` pendant qu'un jeu tourne fera
basculer les requêtes XUser suivantes. Il faut relancer le jeu après avoir
configuré `play`.

**A7 — Sauvegardes locales.** Le runtime range les sauvegardes locales sous
`XodusGameSave\<xuid>\<scid>`. Après le passage à `play`, les sauvegardes
locales faites jusqu'ici avec l'XUID `store` ne seront plus vues. Elles restent
dans le préfixe, et le jeu synchronise le cloud de `play`. C'est attendu, et
c'est à noter pour le test.

**A8 — Bloquant pour la phase 4 telle que décrite.** Avec une source
**externe**, Nexus met `linuxRunPatch: undefined` (`src/main/backend.ts:112`).
`gameLaunchArguments` refuse alors de lancer un jeu (`src/main/game-launch.ts:16`,
« Play requires the current managed Xodus backend »). Avec la source externe
seule, on peut installer, mais **pas jouer**. Contournement sans modifier le
code de Nexus : `readPointer()` ne valide que le JSON et `validate(binaryPath)`.
On peut donc sauvegarder `current.json`, puis écrire un `current.json` qui
pointe vers notre build avec `linuxRunPatch: "linux-run-v22"`. Ça touche les
données de Nexus (`~/.config/xodus-nexus/xodus-backends/`, chemin vérifié sur
cette machine), donc je le ferai seulement avec ton accord.

**A9 — Trousseau partagé.** Nexus et la CLI en terminal utilisent le même
service Secret Service (`Xodus Service`) sur le bus de session. À vérifier en
phase 4 : si Nexus démarre son propre fournisseur de trousseau
(`keyring-session-stop`, `--provider-pid`), le terminal doit voir le même. Il
faut alors lancer `xodus-cli login --account play` pendant que Nexus tourne,
ou après un `keyring-unlock`.

## Décisions (22.10.2026)

- **A1** : le backend garde `store` par défaut pour `profile`, `achievements` et
  `game-activity`, afin que Nexus upstream fonctionne sans changement.
  `--account play` (avec repli) est ajouté. C'est le **fork Nexus** qui
  demandera `play` et liera l'affichage à `account --account play`, comme
  l'app Xbox.
- **A5** : `logout` sans option garde le comportement actuel et conserve
  `play`. `logout --account play` ne supprime que `play/*`.
- **A8** : on passe par le fork Nexus. Le patch est ajouté à son lock, et
  « Rebuild » produit un backend managed avec `linuxRunPatch` correct. On ne
  bricole pas `current.json`.

## Design implémenté (ancien titre : « Design proposé pour la phase 2 »)

Commits sur `dual-account` : `tokens: …`, `service: …`, `cli: …`.

**Modèle** (`xodus/src/tokens/manager.rs`)

- `pub enum AccountRole { Store (défaut), Play }`, exporté par `xodus::tokens`.
- `TokenManager` porte un champ `role`. `new()` donne `Store`, donc **tous les
  appelants existants sont inchangés**.
  - `for_role(role)` renvoie le même stockage, limité à un rôle.
  - `resolve(role)` renvoie `Play` si un compte `play` existe, sinon `Store`.
    Pour `Store`, il renvoie toujours `Store`.
  - `has_user()` indique si un compte est stocké pour le rôle.
- Clés : celles de `store` sont inchangées. `play` utilise
  `play/user-session`, `play/user-tokens` et `play/user-DA`. `dev_license` et
  `device-tokens` sont partagés.
- `remove_persistent()` en `Play` ne supprime que les clés `play/*`. Les device
  tokens ne sont retirés que par une déconnexion `store`, comme aujourd'hui.

**Service** (`xodus-service/src/connection/xml.rs`)

- `message_role()` est une fonction pure et testée :
  `MsaTokenRequest` → `Play` ; `StoreLicenseTokenRequest` et
  `StorePackageUpdatesRequest` → `Store`.
- `parse_message` résout le rôle une fois par requête, puis loggue au niveau
  `info` : `message`, `role` et `fallback`, sans identifiant ni token.
- `MsaTokenRequest` lit le STS et réécrit le STS rafraîchi **dans le rôle
  résolu**. En repli, c'est donc `store`, exactement comme avant.

**CLI**

| Commande | Défaut (inchangé) | `--account play` |
|---|---|---|
| `login` | `store` ; le cache d'abonnement est vidé | connecte `play` uniquement, le cache d'abonnement est conservé |
| `logout [--device]` | `store` + device tokens + cache ; `play` conservé | ne supprime que `play/*` ; refuse `--device` |
| `account [--json]` | sortie strictement identique | `{"role":"play"\|"store","fallback":bool,"stored":bool,"username"?}` : le compte qu'un jeu utiliserait |
| `profile` | inchangé | gamertag/gamerpic de `play` (repli `store`) ; l'abonnement vient toujours de `store` |
| `achievements`, `game-activity` | inchangés | données de `play` (repli `store`) ; `account` dans la sortie = compte effectif |
| `run` | — | XSTS PlayFab (`XODUS_XSTS_PLAYFAB`) via `play`, avec repli ; licence de contenu via `store` |
| `library`, `streaming`, `download`, `license`, `extract` | `store` | pas d'option, toujours `store` |

`login --account play` passe par le même transport que `login` : la webview
native, ou `--external-webview-stdio` piloté par Nexus. **Le binaire compilé
comme Nexus (`--no-default-features`) n'a pas de webview native.** Depuis un
terminal, `login` échoue donc avec « sign-in UI » non disponible. La connexion
du compte `play` doit être faite par le fork Nexus. Autre possibilité : un
build de diagnostic avec webview (`cargo build --release -p xodus-cli`, qui
demande `webkit2gtk4.1-devel`, à installer avec sudo).

**Tests** (`xodus/src/tokens/dual_account_tests.rs`, préfixe `credential_` pour
être exécutés par `build-backend.mjs` ; `xml.rs` : `store_and_play_message_roles`)

- les clés historiques sont conservées ; isolation des rôles ;
- repli `play → store`, y compris sur les entrées `store` à l'ancien format ;
- `logout play` garde `store` et l'appareil ; `logout store` garde `play` ;
- un STS `play` rafraîchi ne touche pas `store` ; un rafraîchissement en
  repli reste dans `store` et ne crée pas de compte `play`.

**Vérifications** (rustc 1.99.0)

- La séquence complète de `cargo test` de `build-backend.mjs`, plus
  `cargo test -p xodus` : tout passe.
- `cargo clippy --all-targets` : 35 avertissements avant et après, à
  l'identique. Aucun nouvel avertissement.
- `rustfmt` : le code ajouté est formaté. Les fichiers patchés par Nexus ne
  l'étaient déjà pas ; je ne les ai pas reformatés.
- Build release : `--help` expose toujours tout ce que
  `parseBackendHelp`/`validate()`/`build-backend.mjs` attendent, et
  `--account` est présent sur les six commandes.

## Patch pour Nexus

`scripts/dual-account-patch.sh` produit `xodus-dual-account.patch` à partir de
`git diff nexus-base..dual-account -- crates`. Ce patch s'applique avec
`git apply --check` puis `git apply` après les 38 patches du lock, et le
résultat est identique à `dual-account`. Entrée à ajouter **en dernier** dans
`patches` :

```json
{ "file": "xodus-dual-account.patch", "sha256": "73d6c752c74ec5372cf8cdc61eb0c8e14958f03d13efa36d95cba5a9f27e5d0a" }
```

Dans le fork Nexus, il faut aussi changer `patchId`, qui identifie la recette
(par exemple `linux-run-v38-dual-account-1`). `compatibility` reste à
`linux-run-v22`, puisque le contrat de lancement ne change pas. Avec ça,
**Rebuild** construit un backend managed qui peut lancer les jeux.

Attention : **Update** (binaire précompilé publié par Nexus upstream)
remplacerait ce backend par un backend sans double compte. Ce n'est pas
destructif (les clés `play/*` sont simplement ignorées), mais le fork Nexus
devra pointer ses releases vers le fork, ou désactiver Update.

## Mise à jour quand Nexus change

1. `git -C xodus-nexus fetch upstream` et fusion dans le fork Nexus ; lire le
   nouveau `assets/backend-source.lock.json`.
2. Dans `xodus-backend` (arbre propre) : `scripts/nexus-base.sh ../xodus-nexus nexus-base-next`.
   Le script s'arrête si un patch ne s'applique pas ou si un sha256 diffère.
3. `git rebase --onto nexus-base-next nexus-base dual-account`, puis renommer
   `nexus-base-next` en `nexus-base`. Les conflits se limitent aux fichiers
   listés ci-dessus.
4. Si le lock change de version de Rust : `rustup toolchain install <rust>`
   puis `rustup override set <rust>`.
5. Rejouer les tests (section Vérifications), puis
   `scripts/dual-account-patch.sh` et reporter le nouveau sha256 dans le lock
   du fork Nexus.

## Plan de test manuel (après intégration Nexus)

1. Sans compte `play` : tout se comporte comme avant (`account --account play`
   indique `"fallback": true`).
2. Connecter `play` par le fork Nexus, puis relancer le jeu (voir A6).
3. Jeu de référence du wiki Compatibility de Nexus (Deep Rock Galactic, Gears
   of War: E-Day…) :
   - installation via `store` ;
   - lancement ;
   - gamertag en jeu = `play` ;
   - cloud saves et succès de `play`.
4. Logs du service (`XODUS_LOG=xodus_service=info`) : `role="play"` sur
   `MsaTokenRequest`, `role="store"` sur `StoreLicenseTokenRequest` et
   `StorePackageUpdatesRequest`. Ne pas utiliser `scripts/send_msa_token_request.py` :
   il affiche le token reçu.
5. Symptômes possibles si un jeu croise le Store avec le joueur (A2) :
   - DLC ou contenu payant non reconnu alors que `store` le possède ;
   - échec de reçu ou de licence en cours de partie ;
   - monnaie virtuelle absente.

   Diagnostic : logs du service (`Store license token request failed`,
   `hresult`), puis comparer avec `logout --account play` (retour en mode
   compte unique). Si le problème disparaît, c'est une vérification croisée
   côté éditeur, et Windows se comporterait pareil.
6. Sauvegardes locales créées avant le passage à `play` : elles ne sont plus
   visibles (A7). C'est attendu, et c'est la sauvegarde cloud de `play` qui
   prend le relais.
