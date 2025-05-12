# Bitcoin Rust Indexer (TrackerSatUtxoCore)

<p align="center">
  <a href="#english">English</a> • <a href="#français">Français</a>
</p>

<div id="english">

## Bitcoin Rust Indexer

A high-performance Bitcoin blockchain indexer written in Rust. It parses and stores block data, transactions, inputs, outputs (UTXOs), and provides heuristic detection for Ordinal inscriptions. Data is stored in a RocksDB database for efficient querying.

The goal of this tool is to provide a structured database, enabling developers to build blockchain analysis applications, transaction trackers, UTXO management tools, or "satoshi" (sats) explorers, including those compatible with Ordinals theory.

### Features

* **Comprehensive Indexing:** Processes Bitcoin blocks to extract transactions, their inputs, and outputs.
* **Script Analysis:** Identifies common script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN, etc.).
* **Detailed UTXO Data:** Records the value, script (address if parsable), and script type for all UTXOs.
* **Spend Tracking:** Links transaction inputs to the UTXOs they spend, storing details of the spent output.
* **Ordinal Inscription Detection:** Implements a heuristic to detect the presence and likely MIME type of Ordinal inscriptions in transaction witnesses.
* **Efficient Storage:** Uses RocksDB for persistent and fast storage of indexed data.
* **Flexible Catch-up Modes:**
    * **Files then RPC (default):** Reads local `blk*.dat` files for a rapid initial catch-up, then uses RPC to fill any gaps and for fallback.
    * **RPC Only:** Can be configured to exclusively use RPC calls to Bitcoin Core for catch-up.
* **Continuous Synchronization:** Utilizes ZMQ to listen for new block notifications (`hashblock`) and stay synchronized with the chain tip.
* **Configurable:** All important parameters (connections, paths, catch-up mode) are managed via a `config.toml` file.
* **Multi-network Support:** Supports Mainnet, Testnet, Signet, and Regtest.
* **Robust Error Handling:** Includes RPC connection retry logic and graceful handling of common issues.

### Prerequisites

* **Rust Toolchain:** Install Rust and Cargo ([https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)). (Version 1.65+ recommended, ensure your version is compatible with dependencies).
* **Bitcoin Core Node:** A synchronized and functional Bitcoin Core node is required (version 0.21+ recommended).
    * RPC must be enabled (`server=1`).
    * ZMQ must be enabled for `hashblock` publishing (e.g., `zmqpubhashblock=tcp://127.0.0.1:28332` in `bitcoin.conf`).
    * It is highly recommended to have `txindex=1` in your `bitcoin.conf` for comprehensive transaction lookups.
* **Disk Space:** Allocate significant disk space for the RocksDB database. For Mainnet, this can grow to several hundred gigabytes or more over time.
* **System Dependencies for RocksDB:** You might need to install `clang` and `llvm` (or corresponding development packages) to compile the `rocksdb` crate. On Debian/Ubuntu: `sudo apt install clang libclang-dev llvm`.

### Setup and Configuration

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_PROJECT_NAME.git](https://github.com/YOUR_USERNAME/YOUR_PROJECT_NAME.git)
    cd YOUR_PROJECT_NAME
    ```

2.  **Configure Bitcoin Core:**
    Ensure your `bitcoin.conf` file (usually in Bitcoin's data directory) contains lines similar to:
    ```ini
    server=1
    txindex=1 # Strongly recommended

    # Adjust RPC user and password
    rpcuser=your_rpc_user
    rpcpassword=your_rpc_password 
    # Ensure rpcallowip is set correctly if indexer is on a different machine
    rpcallowip=127.0.0.1 

    # Example ZMQ configuration
    zmqpubhashblock=tcp://127.0.0.1:28332
    ```
    Restart Bitcoin Core if you modify `bitcoin.conf`.

3.  **Configure the Indexer:**
    Copy the example configuration file and modify it to your needs:
    ```bash
    cp config.toml.example config.toml
    nano config.toml # Or your preferred text editor
    ```
    Key settings to review in `config.toml`:
    * `network`: "bitcoin" (Mainnet), "testnet", "signet", or "regtest".
    * `rpc_only_catchup`: `false` (default) or `true`.
    * `bitcoin_data_dir`: Path to Bitcoin Core's data directory (especially the `blocks` subdirectory). Required if `rpc_only_catchup = false`.
    * `db_base_path`: Directory where the indexer's RocksDB databases will be created.
    * `rpc_url`, `rpc_user`, `rpc_pass`: Credentials for RPC connection to Bitcoin Core.
    * `zmq_url`: URL for ZMQ connection.
    * `rocksdb`: Advanced RocksDB performance settings.

### Building

Compile the project in release mode for optimal performance:
Bash
cargo build --release

The executable will be located at target/release/YOUR_PROJECT_NAME_IN_CARGO_TOML.

Running
Launch the indexer from the project's root directory:

Bash

./target/release/YOUR_PROJECT_NAME_IN_CARGO_TOML
The indexer will log its progress to the console. The first run, especially on Mainnet, can take a very long time.

Stored Data (RocksDB)
The indexer creates several RocksDB "column families" (effectively separate key-value stores) within the db_base_path:

tx_details:
Key: Transaction ID (Txid, 32 bytes)
Value: TxInfo struct (bincode serialized) - contains block height, version, locktime, detailed inputs (including info about the output it spends), detailed outputs (value, script, address, script type), and detected Ordinal inscription type.
Also stores indexer_tip_state_v8_no_scan (current sync state) and genesis_block_processed_v1 (flag).
utxo_spend:
Key: OutPoint (Txid of UTXO + vout index, 36 bytes)
Value: Spending Info (Txid of spending transaction + vin index, 36 bytes) - allows quickly finding if and how a UTXO was spent.
height_hash:
Key: Block height (u32 big-endian)
Value: Block hash (32 bytes)
hash_coinbase:
Key: Block hash (32 bytes)
Value: Coinbase Transaction ID (Txid, 32 bytes)
Using the Indexed Data for Tracing
This indexer's primary role is to populate these RocksDB databases. To trace UTXOs or satoshis, you will typically write separate scripts or applications that read from these databases.

Tracing UTXO Spends:

To find info about a specific transaction output (an UTXO): Query tx_details with the Txid. Deserialize the TxInfo and look at the specific output vout. This gives you its value, address, script type.
To see if that UTXO was spent: Construct the OutPoint key (Txid + vout) and query utxo_spend. If a record exists, it gives you the Txid and input index of the transaction that spent it.
You can then query tx_details again with this spending Txid to analyze the spending transaction.
Tracing Satoshis (Conceptual for Ordinals/Rare Sats):

Identify an initial UTXO of interest (e.g., from an inscription or a specific block).
Use the tx_details and utxo_spend databases to follow the chain of spends.
When a transaction spends multiple inputs and creates multiple outputs, you'll need to apply the appropriate satoshi transfer logic (e.g., FIFO for Ordinals) to determine which output(s) the satoshis of interest flowed into.
This indexer provides all the necessary transaction graph data: values of inputs/outputs and their linkage. The sat-specific accounting logic needs to be built on top of this data.
Donations
If you find this project useful and wish to support its development, you can send Bitcoin donations or raresat to the following addresses:

BTC Address 1: 3A3khdjYKSAcR4VPxkAWgtjrxiXLcsc7Jf
BTC Address 2: bc1pxevgfvsfrc2lxc2nyxmwzqmhwmtq70e4xtfevn2g4egfy5842tfs5kmv5n
Thank you for your support!

Contributing
Contributions, issues, and feature requests are welcome. Please feel free to open an issue or submit a pull request.   

License
This project is licensed under the MIT License.

&lt;/div>

&lt;div id="français">

Indexeur Bitcoin en Rust
Un indexeur haute performance pour la blockchain Bitcoin, écrit en Rust. Il analyse et stocke les données des blocs, transactions, entrées (inputs), sorties (UTXOs), et fournit une détection heuristique pour les inscriptions Ordinals. Les données sont stockées dans une base de données RocksDB pour des requêtes efficaces.

Le but de cet outil est de fournir une base de données structurée, permettant aux développeurs de construire des applications d'analyse de la blockchain, des outils de suivi de transactions, de gestion d'UTXO, ou des explorateurs de "satoshis" (sats), y compris ceux compatibles avec la théorie des Ordinals.

Fonctionnalités
Indexation complète : Traite les blocs Bitcoin pour extraire les transactions, leurs entrées et sorties.
Analyse de Scripts : Identifie les types de scripts courants (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN, etc.).
Données UTXO détaillées : Enregistre la valeur, le script (adresse si analysable), et le type de script pour tous les UTXOs.
Suivi des dépenses : Lie les entrées de transaction aux UTXOs qu'elles dépensent, en stockant les détails de l'output dépensé.
Détection d'Ordinals : Implémente une heuristique pour détecter la présence et le type MIME probable des inscriptions Ordinals dans les témoins de transaction.
Stockage Efficace : Utilise RocksDB pour un stockage persistant et rapide des données indexées.
Modes de Rattrapage Flexibles :
Fichiers puis RPC (défaut) : Lit les fichiers blk*.dat locaux pour un rattrapage initial rapide, puis utilise RPC pour combler les écarts et comme solution de repli.
RPC Uniquement : Peut être configuré pour utiliser exclusivement les appels RPC à Bitcoin Core pour le rattrapage.
Synchronisation Continue : Utilise ZMQ pour écouter les notifications de nouveaux blocs (hashblock) et rester synchronisé avec la pointe de la chaîne.
Configurable : Tous les paramètres importants (connexions, chemins, mode de rattrapage) sont gérés via un fichier config.toml.
Support Multi-réseaux : Supporte Mainnet, Testnet, Signet et Regtest.
Gestion d'Erreurs Robuste : Inclut une logique de tentatives multiples pour les connexions RPC et une gestion appropriée des problèmes courants.
Prérequis
Toolchain Rust : Installez Rust et Cargo (https://www.rust-lang.org/tools/install). (Version 1.65+ recommandée, assurez-vous de la compatibilité de votre version avec les dépendances).
Nœud Bitcoin Core : Un nœud Bitcoin Core synchronisé et fonctionnel est requis (version 0.21+ recommandée).
RPC doit être activé (server=1).
ZMQ doit être activé pour la publication de hashblock (ex: zmqpubhashblock=tcp://127.0.0.1:28332 dans bitcoin.conf).
Il est fortement recommandé d'avoir txindex=1 dans votre bitcoin.conf pour des recherches de transactions complètes.
Espace Disque : Prévoyez un espace disque conséquent pour la base de données RocksDB. Pour Mainnet, cela peut atteindre plusieurs centaines de gigaoctets ou plus avec le temps.
Dépendances système pour RocksDB : Vous pourriez avoir besoin d'installer clang et llvm (ou les paquets de développement correspondants) pour compiler la caisse rocksdb. Sur Debian/Ubuntu : sudo apt install clang libclang-dev llvm.
Installation et Configuration
Cloner le dépôt :

Bash

git clone [https://github.com/VOTRE_UTILISATEUR_GITHUB/NOM_DE_VOTRE_PROJET.git](https://github.com/VOTRE_UTILISATEUR_GITHUB/NOM_DE_VOTRE_PROJET.git)
cd NOM_DE_VOTRE_PROJET
Configurer Bitcoin Core :
Assurez-vous que votre fichier bitcoin.conf (généralement dans le répertoire de données de Bitcoin) contient des lignes similaires à :

Ini, TOML

server=1
txindex=1 # Fortement recommandé

# Ajustez l'utilisateur et le mot de passe RPC
rpcuser=votre_utilisateur_rpc
rpcpassword=votre_mot_de_passe_rpc
# Assurez-vous que rpcallowip est correctement configuré si l'indexeur est sur une autre machine
rpcallowip=127.0.0.1

# Exemple de configuration ZMQ
zmqpubhashblock=tcp://127.0.0.1:28332
Redémarrez Bitcoin Core si vous modifiez bitcoin.conf.

Configurer l'Indexeur :
Copiez le fichier d'exemple de configuration et modifiez-le selon vos besoins :

Bash

cp config.toml.example config.toml
nano config.toml # Ou votre éditeur de texte préféré
Paramètres clés à vérifier dans config.toml :

network: "bitcoin" (Mainnet), "testnet", "signet", ou "regtest".
rpc_only_catchup: false (défaut) ou true.
bitcoin_data_dir: Chemin vers le répertoire de données de Bitcoin Core (contenant les fichiers blocks/blk*.dat). Requis si rpc_only_catchup = false.
db_base_path: Répertoire où les bases de données RocksDB de l'indexeur seront créées.
rpc_url, rpc_user, rpc_pass: Identifiants pour la connexion RPC à Bitcoin Core.
zmq_url: URL pour la connexion ZMQ.
rocksdb: Paramètres de performance avancés pour RocksDB.
Compilation
Compilez le projet en mode "release" pour des performances optimales :

Bash

cargo build --release
L'exécutable se trouvera dans target/release/NOM_DE_VOTRE_PROJET_DANS_CARGO_TOML.

Exécution
Lancez l'indexeur depuis le répertoire racine du projet :

Bash

./target/release/NOM_DE_VOTRE_PROJET_DANS_CARGO_TOML
L'indexeur affichera sa progression dans la console. Le premier lancement, surtout sur Mainnet, peut prendre beaucoup de temps.

Données Stockées (RocksDB)
L'indexeur crée plusieurs "column families" RocksDB (des sortes de magasins clé-valeur séparés) dans le db_base_path configuré :

tx_details:
Clé : ID de Transaction (Txid, 32 octets)
Valeur : Structure TxInfo (sérialisée avec bincode) - contient la hauteur de bloc, version, locktime, listes détaillées d'inputs (incluant des infos sur l'output dépensé) et d'outputs (valeur, script, adresse, type de script), et le type d'inscription Ordinal détecté.
Stocke aussi indexer_tip_state_v8_no_scan (état de synchronisation) et genesis_block_processed_v1 (flag).
utxo_spend:
Clé : OutPoint (Txid de l'UTXO dépensé + index vout, 36 octets)
Valeur : Info de Dépense (Txid de la transaction dépensière + index vin, 36 octets) - permet de trouver rapidement si et comment un UTXO a été dépensé.
height_hash:
Clé : Hauteur de bloc (u32 big-endian)
Valeur : Hash de bloc (32 octets)
hash_coinbase:
Clé : Hash de bloc (32 octets)
Valeur : ID de la transaction coinbase (Txid, 32 octets)
Utilisation des Données Indexées pour le Traçage
Le rôle principal de cet indexeur est de remplir ces bases de données RocksDB. Pour tracer des UTXOs ou des satoshis, vous écrirez typiquement des scripts ou applications séparés qui lisent depuis ces bases.

Tracer les Dépenses d'UTXO :

Pour trouver des informations sur un output de transaction spécifique (un UTXO) : Interrogez tx_details avec le Txid. Désérialisez TxInfo et regardez l'output vout spécifique. Cela vous donne sa valeur, adresse, type de script.
Pour voir si cet UTXO a été dépensé : Construisez la clé OutPoint (Txid + vout) et interrogez utxo_spend. Si un enregistrement existe, il vous donne le Txid et l'index d'input de la transaction qui l'a dépensé.
Vous pouvez alors interroger tx_details à nouveau avec ce Txid dépensier pour analyser la transaction.
Tracer des Satoshis (Conceptuel pour Ordinals/Sats Rares) :

Identifiez un UTXO initial d'intérêt (ex: d'une inscription ou d'un bloc spécifique).
Utilisez les bases tx_details et utxo_spend pour suivre la chaîne des dépenses.
Quand une transaction dépense plusieurs inputs et crée plusieurs outputs, vous devrez appliquer la logique de transfert de satoshis appropriée (ex: FIFO pour les Ordinals) pour déterminer dans quel(s) output(s) de cette transaction les satoshis d'intérêt ont été transférés.
Cet indexeur fournit toutes les données nécessaires du graphe de transactions : valeurs des inputs/outputs et leurs liens. La logique comptable spécifique aux sats doit être construite par-dessus ces données.
Donations
Si vous trouvez ce projet utile et souhaitez soutenir son développement, vous pouvez envoyer des dons Bitcoin aux adresses suivantes :

Adresse BTC 1 : 3A3khdjYKSAcR4VPxkAWgtjrxiXLcsc7Jf
Adresse BTC 2 : bc1pxevgfvsfrc2lxc2nyxmwzqmhwmtq70e4xtfevn2g4egfy5842tfs5kmv5n
Merci pour votre soutien !

Contribuer
Les contributions, signalements de bugs ("issues") et demandes de fonctionnalités sont les bienvenus. N'hésitez pas à ouvrir une "issue" ou à soumettre une "pull request".

Licence
Ce projet est sous licence MIT.

&lt;/div>