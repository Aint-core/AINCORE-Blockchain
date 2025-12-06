# 🗺️ AINCORE Roadmap to Mainnet

This document outlines the strategic phases to evolve AINCORE from a prototype to a production-ready public blockchain.

## ✅ Phase 1: Core Prototype (Current Status)
- [x] **Storage:** RocksDB integration with Object-Centric Model.
- [x] **Consensus:** Basic DAG creation (Narwhal-lite) & Gossip.
- [x] **Execution:** Move VM Integration (Initialized).
- [x] **Security:** Native Account Abstraction (Ed25519 Signatures).
- [x] **Networking:** Basic P2P with mDNS discovery.

## 🚧 Phase 2: Consensus Hardening (The "Iron" Phase)
*Goal: Ensure Byzantine Fault Tolerance and Total Ordering.*
- [x] **Bullshark/Tusk Logic:** Implement global ordering of DAG vertices.
- [x] **Garbage Collection:** Prune old DAG rounds to save space.
- [x] **Recovery:** Allow nodes to recover state after a crash.

## 🚧 Phase 3: Move Framework & Economy (The "Economy" Phase)
*Goal: Enable value transfer and smart contracts.*
- [x] **Move Stdlib:** Integrate the official Move Framework.
- [x] **Gas Metering:** Implement gas costs to prevent spam.
- [x] **Genesis:** Create the genesis block with initial coin distribution.
- [x] **Move Compiler:** Integrate a working compiler for user contracts.

## 🔮 Phase 4: Global Networking (The "Internet" Phase)
*Goal: Connect nodes across the internet.*
- [x] **Discovery:** Implement Kademlia DHT (Bootnodes).
- [x] **State Sync:** Fast synchronization for new nodes (Snapshots).
- [x] **NAT Traversal:** Allow nodes behind home routers to connect.

## 🔮 Phase 5: Developer Experience (The "Interface" Phase)
*Goal: Allow public interaction.*
- [x] **JSON-RPC API:** Standard API for wallets/explorers.
- [x] **CLI Wallet:** Tool for users to create accounts and send txs.
- [x] **Block Explorer:** Web interface to view blocks and transactions.

## 🔮 Phase 6: Security & PoS (The "Fortress" Phase)
*Goal: Secure the network with economic incentives.*
- [x] **Proof of Stake:** Staking logic and validator set rotation.
- [x] **Slashing:** Penalties for misbehaving validators.
- [x] **Merkle Accumulators:** Cryptographic proofs for light clients.
- [x] **Quantum Resistance:** PQC Integration and Crypto-Agility.

## 🌉 Phase 7: Interoperability (The "Bridge" Phase)
*Goal: Connect AINCORE with the wider crypto ecosystem.*
- [ ] **BTC-to-AIN Bridge:** "Auto-Swap" Vault for Bitcoin Miners.
- [ ] **EVM Bridge:** Wrapped AIN (wAIN) on Ethereum/BSC.
- [ ] **IBC Integration:** Connect with Cosmos ecosystem.

## 🚀 Phase X: Mainnet Launch (Pending External Actions)
*Goal: Commercial public release.*
- [ ] **DA Integration:** Replace Mock Sequencer with Celestia/EigenDA.
- [ ] **Security Audits:** External review by firms like Trail of Bits/OtterSec.
- [ ] **ZK-SNARKs:** Implement ZK circuits for private transactions.
- [ ] **Infrastructure:** Deploy seed nodes and validator documentation.


cetak biru 

Cetak Biru Arsitektur AINCORE: Sintesis

Teknologi Blockchain Mutakhir

Bagian 1: Filosofi Inti dan Paradigma Arsitektur

Fondasi dari setiap protokol blockchain yang bertahan lama bukanlah sekadar

kumpulan fitur, melainkan filosofi arsitektur yang koheren dan berwawasan ke depan.

Untuk AINCORE, filosofi ini harus secara langsung mengatasi tantangan-tantangan

fundamental yang telah membatasi skalabilitas, fleksibilitas, dan laju inovasi dari

generasi blockchain sebelumnya. Analisis yang cermat terhadap evolusi arsitektur

blockchain mengungkapkan pergeseran yang tak terelakkan dari desain monolitik yang

terintegrasi secara vertikal menuju paradigma modular yang lebih terspesialisasi dan

dapat disusun. Bagian ini menetapkan landasan filosofis untuk AINCORE, dengan

argumen bahwa masa depan skalabilitas dan inovasi terletak pada adopsi arsitektur

modular yang radikal sejak awal.

1.1 Analisis Komparatif: Arsitektur Monolitik vs. Modular

Arsitektur blockchain tradisional, seperti yang dicontohkan oleh Ethereum sebelum era

rollup-sentris, dapat diklasifikasikan sebagai monolitik. Dalam model ini, fungsi-fungsi

inti dari sebuah blockchain—konsensus (bagaimana node menyepakati keadaan

jaringan), ketersediaan data (bagaimana node memastikan data transaksi telah

dipublikasikan), dan eksekusi (bagaimana transaksi diproses untuk mengubah

keadaan)—terikat erat dalam satu lapisan perangkat lunak tunggal. Setiap node dalam

jaringan diharapkan untuk melakukan ketiga fungsi tersebut. Meskipun pendekatan ini

menawarkan kesederhanaan konseptual dan model keamanan yang mudah dipahami

(di mana keamanan seluruh sistem sama dengan keamanan lapisan konsensusnya), ia

secara inheren menciptakan hambatan kinerja yang signifikan dan membatasi

fleksibilitas pengembangan. Ketika semua fungsi bersaing untuk sumber daya

komputasi yang sama pada setiap node, throughput jaringan secara keseluruhan

dibatasi oleh komponen yang paling lambat. Selain itu, setiap perubahan atau

peningkatan pada salah satu fungsi, misalnya, mesin virtual eksekusi, memerlukan

hard fork yang kompleks dan seringkali kontroversial dari seluruh jaringan, yang secara

efektif memperlambat laju inovasi.

Sebaliknya, paradigma modular, yang dipelopori oleh proyek-proyek seperti Celestia,

mengusulkan pemisahan radikal dari fungsi-fungsi inti ini menjadi lapisan-lapisan

khusus yang dapat dioptimalkan secara independen.1 Dalam arsitektur ini:

• Lapisan Konsensus hanya berfokus pada pemesanan transaksi.

• Lapisan Ketersediaan Data (DA) berspesialisasi dalam menyediakan jaminan

yang dapat diverifikasi bahwa data transaksi telah dipublikasikan dan tersedia

untuk jaringan.

• Lapisan Eksekusi (biasanya diimplementasikan sebagai rollup) hanya

bertanggung jawab untuk mengeksekusi transaksi dan menghitung keadaan

baru.

Celestia secara eksplisit memperlakukan modularitas bukan hanya sebagai ide teoretis

tetapi sebagai arsitektur kerja yang praktis, dengan pemisahan yang ketat antara

konsensus, ketersediaan data, dan eksekusi.1 Pendekatan ini memungkinkan lapisan

eksekusi, seperti rollup, untuk memperlakukan lapisan DA sebagai "hard drive

eksternal" generik.1 Rollup dapat mempublikasikan data transaksi mereka ke lapisan

DA modular dengan biaya yang jauh lebih rendah daripada mempostingnya sebagai

calldata di blockchain monolitik seperti Ethereum, sambil tetap mewarisi jaminan

keamanan dan ketahanan sensor dari lapisan DA tersebut. Pemisahan ini secara

fundamental mengubah ekonomi dan dinamika skalabilitas, memungkinkan inovasi

tanpa izin di setiap lapisan tumpukan.

Pergeseran dari arsitektur monolitik ke modular dalam dunia blockchain

mencerminkan evolusi yang lebih luas dan telah terbukti dalam rekayasa perangkat

lunak: transisi dari aplikasi monolitik besar ke arsitektur layanan mikro (microservices).

Aplikasi monolitik awal, di mana semua logika bisnis, antarmuka pengguna, dan akses

data berada dalam satu basis kode, menghadapi tantangan skalabilitas dan

pemeliharaan yang serupa. Perubahan pada satu komponen kecil berisiko merusak

seluruh sistem dan memerlukan penyebaran ulang seluruh aplikasi. Layanan mikro

memecahkan masalah ini dengan memecah fungsionalitas menjadi layanan-layanan

kecil yang independen dan dapat disebarkan secara terpisah. Demikian pula, arsitektur

blockchain modular memecah fungsi-fungsi protokol menjadi "layanan mikro" on-chain

yang terspesialisasi. Lapisan DA menyediakan "layanan ketersediaan data", lapisan

sequencer menyediakan "layanan pemesanan", dan lapisan eksekusi menyediakan

"layanan komputasi". Implikasi dari pergeseran ini sangat mendalam: ia menciptakan

potensi untuk pasar yang kompetitif di setiap lapisan. Berbagai proyek dapat bersaing

untuk menawarkan lapisan DA yang paling efisien, lapisan sequencer yang paling

terdesentralisasi, atau lingkungan eksekusi yang paling berperforma tinggi.

1.2 Rekomendasi untuk AINCORE: Merangkul Modularitas untuk

Skalabilitas dan Kedaulatan

Berdasarkan analisis ini, rekomendasi fundamental untuk AINCORE adalah untuk

dirancang sebagai protokol yang sepenuhnya merangkul modularitas sejak awal. Ini

bukan hanya pilihan teknis, tetapi juga keputusan strategis yang akan menentukan

lintasan jangka panjang dan potensi ekosistem. Dengan mengadopsi pendekatan

modular, AINCORE dapat mencapai beberapa keunggulan strategis:

1. 2. 3. Skalabilitas Horizontal: Dengan memisahkan eksekusi dari konsensus dan

ketersediaan data, AINCORE dapat fokus pada pengoptimalan mesin

eksekusinya untuk throughput maksimum, sementara lapisan lain dapat

diskalakan secara independen.

Fleksibilitas dan Inovasi: Ekosistem AINCORE dapat berinovasi di lapisan

eksekusi—menciptakan mesin virtual baru atau model eksekusi khusus—tanpa

dibatasi oleh peta jalan atau batasan teknis dari lapisan konsensus atau DA

yang mendasarinya.

Kedaulatan (Sovereignty): Modularitas memberikan tingkat kedaulatan yang

tinggi kepada rollup yang dibangun di atas tumpukan AINCORE. Seperti yang

diuraikan dalam diskusi tentang shared sequencers, pemisahan eksekusi dari

pengurutan memungkinkan sebuah rollup untuk dengan mudah menukar atau

mengubah set sequencer-nya hanya dengan hardfork minor.2 Kemampuan ini

mendorong persaingan yang sehat di antara penyedia layanan sequencer dan

melindungi rollup dari potensi sensor atau ekstraksi nilai yang berlebihan oleh

satu entitas terpusat.

Keputusan untuk AINCORE menjadi modular adalah keputusan untuk berpartisipasi

secara aktif dalam dan membentuk pasar masa depan untuk layanan blockchain yang

terdesentralisasi, daripada mencoba membangun "taman bertembok" monolitik yang

pada akhirnya akan menghadapi batas skalabilitas dan inovasi. Ini adalah strategi yang

lebih tangguh dan adaptif, yang menempatkan AINCORE pada posisi untuk berkembang

dalam lanskap Web3 yang terus berubah.

Bagian 2: Lapisan Konsensus dan Eksekusi Kinerja

Tinggi

Inti dari setiap protokol blockchain adalah mesin konsensus dan eksekusinya, yang

secara kolektif menentukan batas atas kinerja, keamanan, dan skalabilitasnya. Untuk

AINCORE, mencapai throughput yang melampaui standar industri saat ini memerlukan

pemikiran ulang yang fundamental terhadap arsitektur tradisional. Bagian ini

menguraikan proposal untuk lapisan konsensus dan eksekusi AINCORE,

merekomendasikan kombinasi sinergis dari konsensus berbasis Directed Acyclic

Graph (DAG) yang memisahkan penyebaran data dari pemesanan, dan model eksekusi

berorientasi objek yang memungkinkan paralelisasi sejati.

2.1 Melampaui BFT Tradisional: Konsensus Berbasis DAG dengan

Narwhal & Tusk

Protokol konsensus Byzantine Fault Tolerant (BFT) klasik, meskipun terbukti aman,

sering kali menghadapi hambatan kinerja karena mereka menggabungkan dua tugas

yang berbeda: penyebaran transaksi (fungsi mempool) dan pemesanan transaksi

(fungsi konsensus). Setiap validator harus menunggu untuk menerima transaksi,

menyebarkannya ke rekan-rekannya, dan kemudian berpartisipasi dalam beberapa

putaran komunikasi untuk menyepakati urutan yang tepat. Proses yang terjalin erat ini

membatasi throughput.

Sebuah kemajuan signifikan dalam bidang ini datang dari penelitian Meta dengan

Narwhal dan Tusk, sebuah arsitektur yang secara eksplisit memisahkan tugas-tugas

ini untuk memungkinkan kinerja tinggi.3

• Narwhal: Berfungsi sebagai protokol mempool berkinerja tinggi yang

terdesentralisasi. Ia menggunakan struktur data Directed Acyclic Graph (DAG)

untuk menyebarkan transaksi secara andal dan efisien ke semua validator.

Tugas utamanya adalah memastikan ketersediaan data: setiap validator dapat

yakin bahwa validator lain memiliki kumpulan transaksi yang sama untuk

dipertimbangkan untuk pemesanan. Narwhal dirancang untuk mentolerir

jaringan asinkron dan dapat diskalakan secara horizontal dengan menggunakan

beberapa pekerja di setiap validator, yang secara teoretis menghilangkan

batasan throughput untuk penyebaran data.3

• Tusk: Adalah protokol konsensus BFT asinkron yang dirancang untuk bekerja di

atas Narwhal. Setelah Narwhal menjamin ketersediaan data, Tusk dapat

memesan transaksi-transaksi ini dengan sangat efisien, seringkali dengan

overhead komunikasi nol pesan tambahan.

Kinerja arsitektur yang dipisahkan ini sangat luar biasa. Dalam pengujian di Wide Area

Network (WAN), komposisi protokol konsensus yang ada seperti HotStuff di atas

mempool Narwhal mencapai throughput 170.000 transaksi per detik (tx/s) dengan

latensi 2,5 detik. Ini merupakan peningkatan hampir 100 kali lipat dibandingkan dengan

1.800 tx/s yang dicapai oleh HotStuff saja. Lebih lanjut, dengan menambahkan pekerja

paralel pada setiap validator Narwhal, throughput dapat ditingkatkan secara linear

hingga 600.000 tx/s tanpa peningkatan latensi yang berarti.3 Tusk sendiri mencapai

140.000 tx/s dengan latensi 4 detik, 20 kali lebih baik dari protokol asinkron canggih

lainnya pada saat itu.3 Angka-angka ini menunjukkan bahwa memisahkan penyebaran

data dari pemesanan adalah kunci untuk membuka tingkat skalabilitas berikutnya.

2.2 Paradigma Eksekusi Paralel: Analisis Mendalam Model Objek Sui

Setelah transaksi disebarkan dan dipesan, mereka harus dieksekusi. Sebagian besar

blockchain, termasuk yang berbasis EVM, beroperasi pada model eksekusi sekuensial.

Mereka memproses transaksi satu per satu dalam urutan yang ketat, bahkan jika

transaksi tersebut sama sekali tidak berhubungan. Misalnya, jika Alice mentransfer

Token A ke Bob, dan Carol mentransfer Token B ke David, mesin eksekusi sekuensial

akan tetap memproses salah satu transaksi sepenuhnya sebelum memulai yang

berikutnya. Ketergantungan buatan ini menciptakan "bottleneck pengurutan global"

yang parah, di mana throughput seluruh jaringan dibatasi oleh kecepatan eksekusi satu

inti prosesor.5

Blockchain Sui memperkenalkan solusi radikal untuk masalah ini dengan mengadopsi

model data "berpusat pada objek" (object-centric).

6 Dalam model Sui, unit dasar

penyimpanan dan komputasi bukanlah akun global, melainkan "objek" individual yang

dapat dimiliki. Setiap objek memiliki ID unik dan pemilik yang jelas. Keindahan dari

pendekatan ini adalah bahwa dependensi transaksi menjadi eksplisit. Sebuah transaksi

harus menyatakan di muka objek mana yang akan dibaca atau dimodifikasi.

• Eksekusi Paralel Sejati: Dengan informasi dependensi ini, sistem dapat secara

trivial mengidentifikasi transaksi mana yang tidak tumpang tindih. Transaksi

yang memengaruhi set objek yang sepenuhnya terpisah (misalnya, dua

pengguna yang berbeda berinteraksi dengan NFT mereka sendiri) tidak memiliki

konflik dan dapat divalidasi dan dieksekusi secara paralel sepenuhnya oleh

validator.5 Sui hanya perlu menjalankan protokol konsensus BFT formal untuk

memesan subset kecil dari transaksi yang bersaing untuk mengakses objek yang

sama (disebut "objek bersama"). Ini adalah apa yang disebut "eksekusi paralel

sejati" karena sebagian besar transaksi dapat diselesaikan tanpa menunggu

pemesanan global.5

• Kontras dengan Aptos (Block-STM): Penting untuk membedakan pendekatan

Sui dari model lain seperti Block-STM yang digunakan oleh Aptos. Aptos

menggunakan "paralelisasi optimis".8 Ia mengeksekusi batch transaksi secara

paralel dengan asumsi tidak akan ada konflik. Setelah eksekusi, ia harus melalui

fase validasi yang kompleks untuk mendeteksi konflik dan mengeksekusi ulang

transaksi yang gagal. Proses verifikasi dan penyelesaian konflik ini pada

dasarnya masih bersifat sekuensial dan dapat memperlambat kecepatan

keseluruhan, terutama di bawah beban kerja yang tinggi dengan banyak

transaksi yang saling bertentangan.5 Sebaliknya, model Sui menghindari konflik

ini di muka dengan memisahkan transaksi berdasarkan dependensi objek.

2.3 Integrasi untuk AINCORE: Memisahkan Penyebaran Data dan

Pemesanan untuk Throughput Maksimal

Rekomendasi arsitektur untuk lapisan inti AINCORE adalah mengintegrasikan filosofi

dari kedua inovasi ini untuk menciptakan mesin yang sangat berperforma tinggi.

Kombinasi Narwhal dan model objek Sui menciptakan sinergi yang luar biasa. Narwhal

memecahkan masalah penyebaran data secara horizontal, sementara model objek Sui

memecahkan masalah eksekusi secara horizontal. Bersama-sama, mereka mengatasi

dua hambatan terbesar dalam skalabilitas blockchain secara independen.

Alur kerja yang diusulkan untuk AINCORE akan terlihat seperti ini:

1. 2. 3. 4. Penyebaran Berbasis Objek: Pengguna mengirimkan transaksi yang, seperti di

Sui, secara eksplisit menyatakan objek input mereka. Protokol mempool

AINCORE, yang terinspirasi oleh Narwhal, akan bertanggung jawab untuk

menyebarkan objek-objek transaksi ini ke semua validator dengan efisiensi dan

keandalan yang sangat tinggi.

Identifikasi Paralelisme: Saat transaksi tiba di validator, mesin eksekusi

AINCORE dapat segera mengkategorikannya. Transaksi yang hanya melibatkan

"objek yang dimiliki" (tidak dibagikan) dapat segera diproses secara paralel,

karena tidak ada potensi konflik.

Konsensus yang Ditargetkan: Hanya transaksi yang melibatkan "objek

bersama" yang perlu dimasukkan ke dalam protokol konsensus BFT formal

(terinspirasi oleh Tusk) untuk pemesanan.

Finalitas Cepat: Karena sebagian besar transaksi (terutama dalam kasus

penggunaan seperti game dan NFT 5) kemungkinan besar hanya akan melibatkan

objek yang dimiliki, mereka dapat mencapai finalitas hampir secara instan

setelah diproses secara paralel, tanpa harus menunggu konsensus global.

Dengan arsitektur ini, throughput efektif AINCORE tidak lagi dibatasi oleh kecepatan

konsensus BFT sekuensial, melainkan oleh jumlah transaksi yang benar-benar saling

bertentangan dalam beban kerja tertentu. Ini merupakan perubahan paradigma

fundamental dari pemrosesan berbasis blok tradisional dan menempatkan AINCORE

pada jalur untuk mencapai skalabilitas tingkat web.

Bagian 3: Membangun Fondasi Modular

Setelah menetapkan arsitektur konsensus dan eksekusi berkinerja tinggi, langkah

selanjutnya dalam merancang AINCORE adalah membangun fondasi modular yang

mendukungnya. Ini melibatkan pemilihan komponen yang cermat untuk lapisan-

lapisan penting yang berada di bawah lapisan eksekusi: lapisan ketersediaan data (DA)

dan lapisan pengurutan (sequencing). Keputusan yang dibuat di sini akan secara

fundamental membentuk model keamanan, biaya, desentralisasi, dan kemampuan

interoperabilitas dari seluruh ekosistem AINCORE.

3.1 Lapisan Ketersediaan Data (DA): Analisis Trade-off Kritis

Lapisan ketersediaan data berfungsi sebagai fondasi yang aman dan dapat diverifikasi

untuk data rollup. Tugasnya adalah untuk menyimpan data transaksi dan memberikan

bukti kriptografis bahwa data tersebut telah dipublikasikan dan tersedia bagi siapa saja

untuk diverifikasi. Tiga solusi terkemuka di pasar saat ini—Celestia, EigenDA, dan

Avail—menawarkan pendekatan yang berbeda secara fundamental.

• Celestia: Sebagai pelopor dalam ruang DA modular, Celestia dirancang dengan

satu tujuan: menyediakan ketersediaan data yang dapat diskalakan dan

diverifikasi.1 Model keamanannya berdaulat, artinya ia diamankan oleh set

validatornya sendiri yang mempertaruhkan token asli Celestia, TIA. Teknologi

intinya adalah Data Availability Sampling (DAS), yang memungkinkan node

ringan (light nodes) untuk memverifikasi ketersediaan data dengan hanya

mengunduh beberapa sampel kecil dari setiap blok, daripada seluruh blok.1 Ini

secara dramatis mengurangi persyaratan perangkat keras untuk memverifikasi

rantai, sehingga meningkatkan desentralisasi. Namun, sebagai jaringan

independen, Celestia memperkenalkan lapisan kepercayaan baru; keamanan

rollup yang menggunakannya bergantung pada kejujuran dan nilai ekonomi dari

set validator Celestia.1 Celestia sangat cocok untuk sovereign rollups yang

menginginkan kontrol maksimum dan tidak ingin terikat pada ekosistem

Ethereum.1

• EigenDA: Merupakan bagian dari ekosistem EigenLayer dan mengambil

pendekatan yang sangat berbeda. Alih-alih menciptakan jaringan keamanan

baru, EigenDA memanfaatkan keamanan ekonomi masif Ethereum melalui

restaking.

1 Validator Ethereum dapat memilih untuk "mempertaruhkan

kembali" ETH mereka untuk mengamankan EigenDA, sehingga memberikan

jaminan keamanan DA yang didukung oleh nilai miliaran dolar dari ETH yang

dipertaruhkan. EigenDA mengklaim throughput teoretis tertinggi di antara para

pesaingnya, mencapai hingga 100 MB/s, dengan memisahkan penyebaran data

dari konsensus jaringan.9 Namun, restaking adalah konsep yang relatif baru dan

memperkenalkan vektor kompleksitas dan risiko baru. Ini termasuk potensi

beban berlebih pada validator, risiko pemotongan (slashing) yang kompleks, dan

potensi pengawasan peraturan.1 Selain itu, model penalti penuhnya masih

dalam pengembangan.9 EigenDA adalah pilihan yang menarik bagi rollup yang

sangat terintegrasi dengan ekosistem Ethereum dan memprioritaskan

keamanan ekonomi bersama di atas kedaulatan.

• Avail: Berasal dari Polygon, Avail dirancang untuk melayani dunia multi-rantai

yang lebih luas, tidak hanya terfokus pada Ethereum.9 Seperti Celestia, ia

memiliki model keamanan berdaulat yang diamankan oleh token aslinya. Avail

menggabungkan yang terbaik dari kedua dunia: ia menggunakan DAS seperti

Celestia untuk skalabilitas node ringan, tetapi juga menggunakan komitmen

KZG (seperti EigenDA) untuk menghasilkan bukti validitas.9 Kombinasi ini

bertujuan untuk memberikan finalitas data yang lebih cepat, menghilangkan

kebutuhan akan jendela tantangan fraud proof yang panjang.9 Mesin

konsensusnya didasarkan pada tumpukan teknologi Polkadot (BABE untuk

produksi blok dan GRANDPA untuk finalitas), yang dirancang untuk mendukung

sejumlah besar validator.9 Avail memposisikan dirinya sebagai landasan netral

untuk masa depan multi-rantai.

Untuk membantu pengambilan keputusan arsitektur, tabel berikut menyajikan

perbandingan langsung dari ketiga solusi DA ini.

Metrik

Perban

dingan

Celestia EigenDA Avail

Model

Keaman

an

Berdaulat (token TIA) 9 Bersama (Restaked

ETH) 9 Berdaulat (token asli) 9

Mekanis

me

Validasi

Data Availability

Sampling (DAS) dengan

Fraud Proofs 9

Komitmen KZG 9 DAS dengan Komitmen

KZG 9

Through

put

(Teoritis

)

~1.33 MB/s (Mainnet) 9 Hingga 100 MB/s 9 ~0.2 MB/s (Mainnet,

dapat ditingkatkan) 9

Model

Biaya

Pasar "PayForBlob"

(Bayar sesuai

pemakaian) 9

Berjenjang / Biaya

tahunan tetap 9

Formula kompleks

(berdasarkan ukuran &

komputasi) 9

Ekosist

em &

Adopsi

Penggerak pertama, >50

rollup, integrasi luas 9

Integrasi Ethereum

yang kuat (Celo,

Mantle) 9

Fokus multi-rantai,

netralitas ekosistem

(Lumia) 9

Risiko

Utama

Pengenalan lapisan

kepercayaan baru 1

Kompleksitas &

risiko baru dari

restaking 1

Kematangan & efek

jaringan yang lebih

rendah

3.2 Lapisan Pengurutan (Sequencing): Menuju Desentralisasi dan

Interoperabilitas

Saat ini, sebagian besar rollup beroperasi dengan sequencer terpusat. Sequencer

adalah entitas yang bertanggung jawab untuk menerima transaksi pengguna,

mengurutkannya, dan memposting batch yang dihasilkan ke lapisan yang lebih rendah

(L1 atau lapisan DA). Meskipun efisien, sentralisasi ini menciptakan beberapa masalah

serius:

• Satu Titik Kegagalan (Single Point of Failure): Jika sequencer offline, seluruh

rollup berhenti.

• Potensi Sensor: Sequencer terpusat dapat secara sepihak memilih untuk tidak

menyertakan transaksi tertentu.

• Ekstraksi MEV Terpusat: Sequencer memiliki kekuatan tunggal untuk

mengekstrak Maximal Extractable Value (MEV) dengan mengatur ulang atau

menyisipkan transaksi.

Solusi untuk masalah ini adalah jaringan shared sequencer (sequencer bersama)

yang terdesentralisasi, seperti yang sedang dikembangkan oleh Astria, Espresso, dan

Radius.13 Dalam model ini, satu jaringan sequencer yang terdesentralisasi (biasanya

diamankan oleh Proof-of-Stake) melayani banyak rollup secara bersamaan.

Manfaatnya signifikan: rollup yang baru diluncurkan dapat mewarisi ketahanan sensor

dan liveness dari jaringan sequencer bersama yang sudah mapan sejak hari pertama.2

Selain itu, dengan menggabungkan transaksi dari beberapa rollup ke dalam satu batch,

biaya posting ke lapisan DA dapat dikurangi secara signifikan melalui kompresi.2

Salah satu manfaat yang paling menarik dari shared sequencers adalah potensi untuk

komposabilitas lintas-rollup. Dengan berbagi sequencer, dimungkinkan untuk

mencapai penyertaan atomik (atomic inclusion), yaitu jaminan kriptografis bahwa

transaksi untuk Rollup A dan transaksi untuk Rollup B keduanya disertakan dalam

batch yang sama yang diproduksi oleh sequencer.14 Meskipun ini lebih lemah daripada

eksekusi atomik (jaminan bahwa kedua transaksi akan berhasil dieksekusi), ini

membuka pintu untuk desain jembatan lintas-rantai yang lebih efisien dan bentuk-

bentuk arbitrase MEV lintas-rantai yang canggih.2 Namun, perlu dicatat bahwa

sequencer "malas" (lazy sequencer) seperti Astria, yang hanya mengurutkan data tanpa

mengeksekusinya, tidak dapat menjamin eksekusi atomik.14

3.3 Rekomendasi DA dan Sequencer untuk AINCORE

Berdasarkan filosofi inti AINCORE tentang modularitas dan kedaulatan, rekomendasi

arsitektur adalah sebagai berikut:

1. 2. Lapisan Ketersediaan Data: AINCORE harus, pada awalnya, menargetkan

Celestia sebagai lapisan DA utamanya. Pilihan ini selaras sempurna dengan

pendekatan modular, memberikan fleksibilitas maksimum bagi ekosistem

AINCORE untuk berkembang tanpa terikat pada asumsi keamanan atau peta

jalan dari ekosistem lain seperti Ethereum (seperti halnya dengan EigenDA). Ini

memungkinkan rollup di AINCORE untuk menjadi benar-benar berdaulat.

Lapisan Pengurutan: AINCORE harus dirancang agar secara native kompatibel

dengan arsitektur shared sequencer terdesentralisasi. Ini berarti protokol

AINCORE harus menyediakan hook dan antarmuka yang jelas yang

memungkinkan rollup untuk "mencolokkan" ke penyedia sequencer pilihan

mereka. Pendekatan ini akan mendorong pasar yang sehat dan kompetitif untuk

layanan pengurutan di dalam ekosistem, mencegah penguncian vendor, dan

memberikan pilihan kepada pengembang rollup untuk menyeimbangkan antara

desentralisasi, kinerja, dan biaya.

Munculnya lapisan DA dan shared sequencer yang dapat disusun menciptakan

"lapisan tengah" (middle layer) baru dalam tumpukan blockchain yang sebelumnya

tidak ada. Lapisan ini, yang berada di antara eksekusi dan konsensus L1, memiliki

dinamika ekonomi, keamanan, dan tata kelolanya sendiri. Keamanan rollup yang

dibangun di atas Celestia, misalnya, secara inheren terkait dengan nilai ekonomi token

TIA. Demikian pula, shared sequencers menjadi titik fokus baru untuk ekstraksi MEV

lintas-rantai. Oleh karena itu, strategi arsitektur AINCORE tidak dapat ada dalam ruang

hampa. Ia harus dirancang tidak hanya untuk menggunakan lapisan-lapisan ini, tetapi

juga untuk berpengaruh di dalamnya, mungkin melalui partisipasi DAO dalam tata

kelola jaringan sequencer atau diversifikasi strategis dukungan untuk beberapa lapisan

DA di masa depan.

Bagian 4: Lingkungan Aplikasi dan Pengalaman

Pengguna

Setelah fondasi modular yang kuat diletakkan, fokus beralih ke lapisan teratas dari

tumpukan teknologi—lingkungan di mana pengembang membangun aplikasi dan

pengguna akhir berinteraksi dengan protokol. Pilihan yang dibuat di sini secara

langsung memengaruhi keamanan kontrak pintar, kekuatan ekosistem pengembang,

dan yang terpenting, adopsi pengguna. Untuk AINCORE, tujuannya adalah untuk

menyediakan lingkungan yang secara inheren aman, sangat ekspresif, dan mampu

memberikan pengalaman pengguna yang mulus yang menyaingi aplikasi Web2. Ini

dicapai melalui adopsi strategis bahasa pemrograman generasi berikutnya dan

implementasi asli dari abstraksi akun.

4.1 Bahasa Pemrograman Generasi Berikutnya: Mengadopsi Sui Move

Pilihan bahasa kontrak pintar adalah salah satu keputusan paling penting dalam desain

blockchain. Bahasa tersebut menentukan tingkat keamanan yang dapat dicapai,

kemudahan pengembangan, dan jenis aplikasi yang dapat dibangun. Sementara

Solidity dan EVM mendominasi lanskap saat ini, mereka membawa serta warisan

kerentanan keamanan yang terkenal, seperti serangan re-entrancy dan integer

overflow.

Bahasa Move, yang awalnya dikembangkan di Meta untuk blockchain Diem,

menawarkan paradigma yang secara fundamental lebih aman.8 Dirancang dari awal

dengan mempertimbangkan keamanan aset digital, Move didasarkan pada bahasa

Rust dan memperkenalkan konsep "sumber daya" (resources) sebagai tipe data kelas

satu. Sumber daya adalah nilai yang dilindungi secara linear yang tidak dapat disalin

atau dibuang secara tidak sengaja, hanya dapat dipindahkan antar lokasi

penyimpanan.16 Model ini secara efektif menghilangkan seluruh kelas bug, termasuk

duplikasi aset dan serangan re-entrancy, di tingkat kompiler.6

Blockchain Sui telah mengambil fondasi Move yang kuat ini dan mengembangkannya

lebih lanjut, mengadaptasinya menjadi Sui Move, sebuah dialek yang dioptimalkan

untuk model data berorientasi objeknya.5 Dalam Sui Move, aset digital

direpresentasikan secara intuitif sebagai objek, yang menyederhanakan logika

pengembangan dan meningkatkan keamanan lebih lanjut.19 Beberapa fitur utama Sui

Move yang membuatnya menjadi pilihan unggul untuk AINCORE meliputi:

• Verifikasi Formal: Move dirancang bersama dengan Move Prover, sebuah alat

verifikasi formal otomatis yang kuat.15 Ini memungkinkan pengembang untuk

menulis spesifikasi formal tentang perilaku yang benar dari kode mereka

(misalnya, "fungsi ini tidak akan pernah mengurangi saldo pengguna di bawah

nol") dan kemudian secara matematis membuktikan bahwa implementasi

mereka mematuhi spesifikasi tersebut. Ini merupakan lompatan kuantum dalam

jaminan keamanan dibandingkan dengan hanya mengandalkan audit manual.

• Programmable Transaction Blocks (PTBs): Fitur inovatif ini memungkinkan

pengembang untuk menyusun hingga 1.024 panggilan fungsi yang berbeda ke

dalam satu transaksi atomik tunggal.8 Ini memindahkan komposabilitas yang

kompleks dari logika di dalam kontrak pintar ke tingkat transaksi itu sendiri.

Hasilnya adalah efisiensi gas yang jauh lebih tinggi dan kode yang lebih

sederhana, karena beberapa operasi (misalnya, menukar token, menyediakan

likuiditas, dan mempertaruhkan token LP) dapat dilakukan dalam satu langkah

yang dijamin berhasil atau gagal seluruhnya.

4.2 Abstraksi Akun (Account Abstraction): Asli vs. ERC-4337

Hambatan utama lainnya untuk adopsi massal blockchain adalah model akun primitif

yang digunakan oleh sebagian besar rantai saat ini. Externally Owned Accounts (EOAs)

secara kaku mengikat kepemilikan akun ke satu kunci privat. Kehilangan kunci ini

berarti kehilangan dana secara permanen. Model ini juga memaksa pengguna untuk

mengelola gas dan menandatangani setiap transaksi secara manual, menciptakan

pengalaman pengguna yang buruk.

Abstraksi Akun (AA) adalah konsep yang bertujuan untuk memecahkan masalah ini

dengan memisahkan akun dari keterikatan pada satu pasangan kunci, secara efektif

mengubah setiap akun pengguna menjadi kontrak pintar yang dapat diprogram.21 Ini

membuka pintu untuk fitur-fitur yang mengubah permainan seperti:

• Pemulihan Sosial: Menunjuk wali (teman, keluarga, atau layanan) yang dapat

membantu memulihkan akses ke akun jika kunci utama hilang.21

• Transaksi Multi-Tanda Tangan: Memerlukan beberapa persetujuan untuk

transaksi bernilai tinggi.22

• Pembayaran Gas yang Disponsori (Paymasters): Memungkinkan aplikasi

untuk membayar biaya transaksi atas nama pengguna mereka, menciptakan

pengalaman tanpa gas.23

Ada dua pendekatan utama untuk mengimplementasikan AA:

• ERC-4337 (Pendekatan Ethereum): Ini adalah standar lapisan aplikasi yang

cerdas yang mencapai AA tanpa memerlukan perubahan pada lapisan

konsensus Ethereum.23 Ia bekerja dengan memperkenalkan mempool alternatif

untuk objek "UserOperation" dan mengandalkan aktor off-chain yang disebut

"Bundlers" untuk mengemasnya ke dalam transaksi Ethereum reguler dan

mengirimkannya ke kontrak "EntryPoint" global.24 Meskipun ini adalah solusi

yang kuat dan kompatibel secara universal di seluruh rantai EVM, ia

memperkenalkan kompleksitas infrastruktur yang signifikan, overhead gas

tambahan, dan menciptakan dua alur transaksi yang terpisah (satu untuk EOA,

satu untuk akun pintar).25 Terutama, model paymaster-nya tidak dapat melayani

EOA tradisional.25

• Native AA (Pendekatan Asli): Blockchain seperti zkSync dan Flow

mengintegrasikan AA langsung ke dalam tingkat protokol.

22 Dalam model ini,

tidak ada perbedaan antara EOA dan akun kontrak; semua akun pada dasarnya

adalah kontrak pintar sejak awal. Ini menghasilkan arsitektur yang jauh lebih

elegan dan efisien:

o Alur Transaksi Terpadu: Hanya ada satu jenis transaksi dan satu

mempool, yang menyederhanakan arsitektur node.25

o Dukungan Paymaster Universal: Karena semua akun adalah kontrak

pintar, fitur seperti pembayaran gas yang disponsori dapat berlaku untuk

semua orang di jaringan, bukan hanya pengguna baru.25

o Efisiensi Lebih Tinggi: Dengan menghilangkan lapisan infrastruktur off-

chain (Bundlers) dan panggilan lintas kontrak yang kompleks yang

diperlukan oleh ERC-4337, AA asli umumnya lebih efisien dalam hal

gas.27

Tabel berikut merangkum perbedaan fundamental antara kedua pendekatan tersebut.

Kriteria

Perbandingan

Native Account

Abstraction (AA)

ERC-4337

Level

Implementasi Tingkat Protokol 25 Lapisan Aplikasi 23

Perubahan

Konsensus Diperlukan 27 Tidak Diperlukan 23

Alur Transaksi Terpadu, satu mempool 25 Terpisah, mempool alternatif untuk

UserOperations 24

Kompleksitas

Infrastruktur

Lebih rendah (ditangani

oleh protokol) 27

Lebih tinggi (membutuhkan Bundlers

& Paymasters eksternal) 24

Dukungan

Paymaster

Universal (untuk semua

jenis akun) 25

Terbatas (hanya untuk Akun Pintar

ERC-4337) 25

Efisiensi Gas Umumnya lebih tinggi,

lebih sedikit overhead 27

Umumnya lebih rendah karena

overhead validasi & eksekusi 26

Analisis ini dengan jelas menunjukkan bahwa untuk blockchain baru yang dirancang

dari awal seperti AINCORE, implementasi AA asli secara teknis merupakan pilihan yang

unggul dalam hampir setiap metrik. ERC-4337 adalah solusi rekayasa yang brilian

untuk mengatasi batasan-batasan yang ada pada Ethereum, bukan cetak biru untuk

desain yang ideal.

4.3 Desain Pengalaman Pengguna Unggul untuk Ekosistem AINCORE

Rekomendasi untuk AINCORE adalah mengadopsi Sui Move sebagai bahasa kontrak

pintarnya dan mengimplementasikan Account Abstraction secara native di tingkat

protokol. Kombinasi kedua teknologi ini menciptakan "lingkaran kebajikan" (virtuous

cycle) antara keamanan, fleksibilitas, dan pengalaman pengguna.

AA asli memungkinkan logika verifikasi yang sepenuhnya dapat diprogram di tingkat

akun, yang berarti sebuah akun dapat memvalidasi transaksi menggunakan berbagai

skema tanda tangan atau aturan kustom. Bahasa Move, dengan integrasi eratnya

dengan verifikasi formal, adalah alat yang ideal untuk menulis logika verifikasi yang

kompleks ini dengan tingkat jaminan kebenaran yang sangat tinggi. Selanjutnya, model

objek Sui memungkinkan representasi aset yang kaya dan berbutir halus. Sebuah akun

AINCORE (yang pada dasarnya adalah kontrak pintar berkat AA asli) dapat memiliki

logika yang sangat canggih tentang bagaimana ia berinteraksi dengan berbagai jenis

objek.

Sebagai contoh, bayangkan sebuah akun game di AINCORE. Dengan AA asli, akun

tersebut dapat mengotorisasi "kunci sesi" dengan izin terbatas—misalnya, kunci ini

hanya dapat menandatangani transaksi yang berinteraksi dengan objek "Pedang" dan

"Perisai" milik pemain (yang didefinisikan dengan aman di Move), tetapi secara eksplisit

dilarang berinteraksi dengan objek "Brankas Harta Karun". Seluruh logika izin ini dapat

diverifikasi secara formal menggunakan Move Prover. Kombinasi ini memungkinkan

tingkat keamanan dan fleksibilitas yang dapat diprogram yang jauh melampaui apa

yang mungkin dilakukan dengan tumpukan EVM + ERC-4337, membuka jalan bagi

paradigma baru interaksi on-chain yang aman dan ramah pengguna.

Bagian 5: Interoperabilitas, Privasi, dan Keamanan

Jangka Panjang

Sebuah protokol blockchain yang sukses tidak dapat ada dalam isolasi. Ia harus dapat

berkomunikasi secara aman dengan ekosistem yang lebih luas, menyediakan fitur-fitur

yang dibutuhkan oleh kasus penggunaan dunia nyata seperti privasi, dan secara

proaktif melindungi dirinya dari ancaman di masa depan. Bagian ini membahas tiga

pilar penting untuk keberlanjutan jangka panjang AINCORE: interoperabilitas yang minim

kepercayaan, privasi on-chain opsional, dan ketahanan terhadap komputasi kuantum.

5.1 Protokol Interoperabilitas: Memprioritaskan Keamanan Minim

Kepercayaan dengan IBC

Interoperabilitas lintas-rantai, atau kemampuan untuk mentransfer aset dan data antar

blockchain yang berbeda, sangat penting untuk pertumbuhan ekosistem. Namun,

jembatan (bridges) lintas-rantai secara historis menjadi salah satu vektor serangan

yang paling rentan di Web3, dengan miliaran dolar hilang karena peretasan. Kerentanan

ini seringkali berasal dari model keamanan yang bergantung pada perantara terpusat

atau semi-terpusat.

• Model yang Diverifikasi Secara Eksternal (Externally-Verified Models):

Protokol seperti LayerZero dan Axelar termasuk dalam kategori ini.28 Mereka

mengandalkan satu set entitas eksternal (misalnya, jaringan Oracle dan Relayer

di LayerZero, atau set validator di Axelar) untuk mengamati peristiwa di rantai

sumber dan menyampaikan pesan ke rantai tujuan. Model keamanan mereka

bergantung pada asumsi kriptoekonomi bahwa mayoritas dari entitas perantara

ini akan berperilaku jujur. Namun, ini secara fundamental memperkenalkan

lapisan kepercayaan tambahan; pengguna harus percaya bahwa set perantara

ini tidak akan berkolusi untuk mencuri dana atau menyensor pesan.28

• Model yang Diverifikasi Secara Lokal (Locally-Verified Model - IBC): Inter-

Blockchain Communication Protocol (IBC), yang berasal dari ekosistem

Cosmos, mengambil pendekatan yang secara fundamental lebih aman dan

terdesentralisasi.30 IBC bekerja berdasarkan prinsip verifikasi light client. Setiap

rantai yang terhubung ke IBC menjalankan light client dari rantai mitranya. Light

client ini memungkinkan satu rantai untuk secara langsung dan kriptografis

memverifikasi keadaan (misalnya, header blok) dari rantai lain tanpa bergantung

pada perantara pihak ketiga.30 Komunikasi diamankan oleh validator dari kedua

rantai yang berpartisipasi, bukan oleh set jembatan eksternal. Karena tidak ada

lapisan kepercayaan tambahan yang diperkenalkan, IBC secara luas dianggap

sebagai "standar emas" untuk interoperabilitas yang minim kepercayaan

(trust-minimized).

30

Rekomendasi: Untuk menyelaraskan dengan filosofi keamanan dan desentralisasi

yang kuat, AINCORE harus mengadopsi dan mengimplementasikan IBC sebagai

protokol interoperabilitas standarnya. Meskipun integrasi dengan rantai non-IBC

mungkin memerlukan lebih banyak upaya rekayasa (misalnya, melalui implementasi

seperti ibc-solidity 30), jaminan keamanan jangka panjang yang diberikannya jauh lebih

unggul daripada model yang bergantung pada kepercayaan eksternal. Ini memastikan

bahwa kedaulatan dan keamanan AINCORE tidak dikompromikan saat berinteraksi

dengan dunia luar.

5.2 Implementasi Privasi Opsional On-Chain dengan ZK-SNARKs

Transparansi radikal dari sebagian besar blockchain publik merupakan pedang

bermata dua. Meskipun memungkinkan auditabilitas penuh, ia tidak cocok untuk

banyak kasus penggunaan komersial dan pribadi di mana kerahasiaan sangat penting.

Keuangan institusional, manajemen rantai pasokan, dan aplikasi yang menangani data

pengguna yang sensitif semuanya memerlukan tingkat privasi on-chain.

Studi kasus yang paling sukses dalam mengimplementasikan privasi yang kuat namun

fleksibel adalah Zcash. Zcash memelopori model "privasi opsional" menggunakan

bukti tanpa pengetahuan, khususnya zk-SNARKs (Zero-Knowledge Succinct Non-

Interactive Arguments of Knowledge).31

• Mekanisme: Pengguna Zcash dapat memilih antara dua jenis alamat: alamat

transparan ('t-addresses'), yang berfungsi seperti alamat Bitcoin, dan alamat

terlindung ('shielded addresses'), seperti alamat Sapling yang dimulai dengan

'zs'.33

• Transaksi Terlindung: Ketika transaksi terjadi antara dua alamat terlindung

(shielded-to-shielded), detail transaksi—termasuk alamat pengirim, alamat

penerima, dan jumlah yang ditransfer—sepenuhnya dienkripsi di blockchain.

• Verifikasi Tanpa Pengetahuan: Jaringan masih dapat memverifikasi validitas

transaksi ini tanpa perlu mendekripsinya. Pengirim membuat bukti zk-SNARK

yang secara matematis menunjukkan bahwa semua aturan konsensus telah

dipatuhi (misalnya, mereka memiliki dana yang cukup, tidak ada uang yang

dibuat dari udara tipis) tanpa mengungkapkan informasi apa pun yang

mendasarinya.31 Bukti yang ringkas ini kemudian dipublikasikan di blockchain, di

mana node dapat memverifikasinya dengan cepat.

Rekomendasi: AINCORE harus mengintegrasikan sirkuit ZK-SNARK di tingkat protokol

untuk memungkinkan transaksi terlindung opsional, mengikuti model Zcash Sapling

yang telah terbukti.33 Ini memberikan fleksibilitas maksimum: aplikasi yang

membutuhkan transparansi penuh dapat menggunakan transaksi reguler, sementara

aplikasi yang membutuhkan kerahasiaan dapat memanfaatkan kumpulan terlindung

(shielded pool). Menyediakan privasi sebagai fitur asli protokol jauh lebih unggul

daripada mengandalkannya pada solusi lapisan aplikasi yang seringkali kurang aman

dan efisien.

5.3 Mitigasi Ancaman Kuantum: Integrasi Kriptografi Pasca-Kuantum

(PQC)

Ancaman jangka panjang yang paling signifikan terhadap keamanan semua blockchain

saat ini adalah munculnya komputer kuantum berskala besar. Komputer kuantum,

menggunakan algoritma seperti algoritma Shor, akan mampu memecahkan masalah

matematika yang mendasari sistem kriptografi kunci publik yang digunakan saat ini,

termasuk ECDSA (yang digunakan untuk tanda tangan transaksi) dan RSA.35 Ini bukan

masalah di masa depan yang jauh; serangan "panen sekarang, dekripsi nanti" (harvest

now, decrypt later) berarti bahwa data terenkripsi yang ditransmisikan hari ini dapat

disimpan oleh musuh dan didekripsi di masa depan setelah komputer kuantum

tersedia.35

Menanggapi ancaman ini, National Institute of Standards and Technology (NIST) AS

telah menjalankan proses standardisasi selama bertahun-tahun untuk memilih

algoritma Kriptografi Pasca-Kuantum (PQC) baru yang diyakini tahan terhadap

serangan dari komputer klasik dan kuantum.

• Standar yang Dipilih: Salah satu algoritma yang dipilih untuk standardisasi

sebagai Mekanisme Enkapsulasi Kunci (Key Encapsulation Mechanism - KEM)

adalah CRYSTALS-Kyber.

37 Kyber adalah skema kriptografi berbasis kisi (lattice-

based) yang efisiensinya membuatnya cocok untuk protokol seperti TLS.36

Keamanannya didasarkan pada kesulitan masalah matematika seperti Learning

With Errors (LWE).36

Rekomendasi: AINCORE harus mengambil sikap proaktif dalam mengatasi ancaman

kuantum dengan membangun "kelincahan kriptografis" (crypto-agility) ke dalam desain

intinya.

• Jangka Pendek-Menengah: AINCORE harus mengintegrasikan CRYSTALS-Kyber

sebagai mekanisme pertukaran kunci dalam lapisan jaringan peer-to-peer-nya

untuk melindungi komunikasi antar node.

• Jangka Panjang: Peta jalan protokol harus mencakup rencana transisi yang

jelas untuk skema tanda tangan digital yang digunakan oleh akun pengguna.

Abstraksi Akun Asli yang direkomendasikan di Bagian 4 sangat penting di sini,

karena memungkinkan akun untuk meningkatkan logika verifikasi mereka untuk

mendukung skema tanda tangan PQC yang distandarisasi NIST (seperti

CRYSTALS-Dilithium atau FALCON) di masa depan tanpa memerlukan hard fork

yang mengganggu di seluruh jaringan.

Secara kolektif, interoperabilitas, privasi, dan ketahanan kuantum sering dianggap

sebagai masalah terpisah. Namun, mereka secara fundamental saling terkait melalui

fondasi kriptografi bersama mereka. Peta jalan kriptografi AINCORE harus terintegrasi.

Misalnya, saat meneliti ZK-SNARKs (yang rentan kuantum 32), tim harus secara aktif

memantau dan berkontribusi pada pengembangan bukti tanpa pengetahuan yang

tahan kuantum seperti ZK-STARKs. Dengan membangun kelincahan kriptografis ke

dalam DNA protokol, AINCORE dapat beradaptasi dan bertahan dalam menghadapi

lanskap ancaman yang terus berkembang.

Bagian 6: Keberlanjutan Ekonomi dan Tata Kelola

Protokol

Sebuah arsitektur teknis yang unggul tidak cukup untuk menjamin keberhasilan jangka

panjang sebuah blockchain. Protokol juga harus berkelanjutan secara ekonomi dan

memiliki mekanisme tata kelola yang kuat untuk memandu evolusinya. Dua tantangan

eksistensial jangka panjang yang dihadapi semua blockchain publik adalah

pertumbuhan state yang tidak terkendali (state bloat) dan inefisiensi model tata kelola

on-chain. Bagian ini mengusulkan solusi untuk kedua masalah tersebut,

merekomendasikan mekanisme berbasis pasar untuk memastikan kesehatan dan

adaptasi protokol yang berkelanjutan.

6.1 Mengelola Pertumbuhan State: Proposal Teknis untuk State Rent

dan Statelessness

Setiap data yang disimpan di blockchain—saldo akun, kode kontrak pintar, variabel

penyimpanan—secara kolektif membentuk "state" jaringan. Dalam model ekonomi

sebagian besar blockchain saat ini, pengguna membayar biaya satu kali untuk menulis

ke state, tetapi kemudian data tersebut diharapkan untuk disimpan oleh semua node di

jaringan selamanya. Model "bayar sekali, simpan selamanya" ini secara ekonomi tidak

berkelanjutan dan mengarah pada pertumbuhan state yang tidak terkendali.

39 Seiring

waktu, state yang membengkak ini secara drastis meningkatkan biaya perangkat keras

(terutama RAM dan penyimpanan SSD cepat) yang diperlukan untuk menjalankan node

penuh, yang pada gilirannya mengancam desentralisasi dan kinerja jaringan.39

Dua pendekatan utama telah diusulkan untuk mengatasi masalah ini:

• State Rent: Konsep ini memperkenalkan biaya berbasis durasi untuk

penyimpanan on-chain, mengubah model dari "membeli tanah" menjadi

"menyewa apartemen".39 Proposal awal untuk state rent di Ethereum terhenti

karena kompleksitasnya, terutama dalam menentukan siapa yang harus

membayar sewa untuk kontrak bersama yang populer.39 Proposal yang lebih

baru dan disederhanakan menyarankan pendekatan yang lebih pragmatis:

menggeser beban pembayaran sewa dari "pemilik" state ke pengirim

transaksi yang mengakses state tersebut.

39 Setiap kali sebuah transaksi

membaca atau menulis ke sepotong state, ia akan membayar sewa yang

terutang pada potongan data tersebut sejak terakhir kali diakses. Mekanisme ini

menciptakan insentif ekonomi yang kuat bagi aplikasi untuk secara berkala

"menyentuh" state penting mereka dan untuk membersihkan state yang sudah

usang atau tidak lagi digunakan. Solana adalah salah satu dari sedikit

blockchain besar yang telah berhasil mengimplementasikan versi state rent di

mainnet-nya.39

• Statelessness: Ini adalah paradigma jangka panjang di mana validator tidak lagi

diharuskan untuk menyimpan seluruh state jaringan untuk memvalidasi blok

baru.40 Sebaliknya, transaksi akan dibundel dengan "saksi" (witness)

kriptografis—bukti yang berisi semua bagian state yang diperlukan untuk

memverifikasi eksekusi transaksi tersebut. Ini secara dramatis akan mengurangi

persyaratan perangkat keras untuk validator, memungkinkan lebih banyak

peserta untuk mengamankan jaringan. Namun, implementasi statelessness

penuh adalah tantangan rekayasa yang sangat kompleks.40

Rekomendasi: AINCORE harus merancang model ekonominya dengan

mempertimbangkan biaya penyimpanan state sejak hari pertama. Pendekatan yang

paling pragmatis dan dapat ditindaklanjuti adalah mengimplementasikan model state

rent yang disederhanakan, di mana biaya dibebankan pada saat akses. Ini secara

langsung mengatasi masalah ekonomi yang mendasari state bloat. Ini harus

dikombinasikan dengan peta jalan penelitian dan pengembangan jangka panjang yang

jelas menuju statelessness untuk memastikan skalabilitas validator yang

berkelanjutan saat jaringan tumbuh.

6.2 Model Tata Kelola On-Chain Tingkat Lanjut: Menjelajahi Futarchy

Tata kelola—proses di mana komunitas membuat keputusan tentang peningkatan

protokol, alokasi dana perbendaharaan, dan parameter jaringan—adalah komponen

penting lainnya untuk keberlanjutan. Model yang paling umum saat ini, pemungutan

suara berbasis token ("satu token, satu suara"), sering dikritik karena bersifat

plutokratis (memberi kekuatan yang tidak proporsional kepada pemegang besar) dan

tidak efektif dalam menggabungkan pengetahuan yang tersebar untuk membuat

keputusan yang optimal secara objektif.42

Futarchy, sebuah model tata kelola yang awalnya diusulkan oleh ekonom Robin

Hanson, menawarkan alternatif yang radikal dan menarik.43 Prinsip intinya adalah

memisahkan penentuan "nilai" (values) dari evaluasi "keyakinan" (beliefs).

43

• Vote on Values: Komunitas menggunakan proses pemungutan suara

demokratis (misalnya, pemungutan suara token) untuk memutuskan metrik

keberhasilan tingkat tinggi, atau Key Performance Indicator (KPI), yang ingin

dioptimalkan oleh protokol. Contoh KPI bisa berupa "memaksimalkan Total

Value Locked (TVL) dalam ekosistem," "memaksimalkan jumlah transaksi

harian," atau "meminimalkan latensi transaksi rata-rata".43

• Bet on Beliefs: Setelah KPI disepakati, keputusan tentang proposal spesifik

(misalnya, "Haruskah kita mendanai pengembangan Proyek A?") tidak dibuat

melalui pemungutan suara, melainkan melalui pasar prediksi (prediction

markets).

45 Dua pasar bersyarat akan dibuat: satu yang membayar jika Proyek A

didanai dan KPI tercapai, dan satu lagi yang membayar jika Proyek A tidak

didanai dan KPI tercapai. Proposal akan diadopsi secara otomatis jika pasar

memprediksi bahwa mendanai proyek tersebut lebih mungkin mengarah pada

pencapaian KPI.

Keuntungan dari Futarchy adalah ia memanfaatkan "kebijaksanaan kerumunan" dan

insentif finansial untuk menghasilkan informasi yang akurat tentang kemungkinan hasil

dari suatu kebijakan.43 Peserta yang memiliki informasi atau keyakinan yang lebih baik

didorong untuk "mempertaruhkan uang mereka", sehingga harga pasar mencerminkan

keyakinan kolektif terbaik dari komunitas tentang cara mencapai tujuan bersama.

Proyek seperti Optimism telah mulai bereksperimen dengan mekanisme yang

terinspirasi oleh Futarchy untuk alokasi dana hibah ekosistem.47

Rekomendasi: AINCORE harus menghindari penguncian ke dalam model tata kelola

yang kaku. Sebaliknya, ia harus mengadopsi kerangka tata kelola modular dan dapat

diupgrade yang memungkinkan eksperimen dengan model-model canggih seperti

Futarchy, terutama untuk keputusan yang dapat diukur secara objektif seperti alokasi

dana perbendaharaan atau hibah. Ini akan menempatkan AINCORE di garis depan

inovasi tata kelola dan meningkatkan kemungkinannya untuk membuat keputusan yang

benar-benar mengoptimalkan kesehatan dan pertumbuhan jangka panjang ekosistem.

Baik state rent maupun Futarchy, meskipun menangani domain yang berbeda, berbagi

filosofi yang sama: mereka adalah mekanisme yang menggunakan sinyal harga dan

insentif ekonomi untuk mengatur sumber daya yang langka dan kompleks secara

efisien. State rent mengatur sumber daya komputasi (penyimpanan state), sementara

Futarchy mengatur sumber daya modal dan keputusan (dana perbendaharaan dan

arah protokol). Dengan membangun AINCORE di atas fondasi "tata kelola berbasis

pasar" untuk sumber daya teknis dan sosial-ekonominya, protokol ini diposisikan untuk

keberlanjutan dan adaptasi yang jauh lebih besar dalam jangka panjang.

Bagian 7: Sintesis dan Peta Jalan Arsitektur AINCORE

Setelah menganalisis secara mendalam setiap lapisan tumpukan teknologi blockchain

modern, dari konsensus hingga tata kelola, bagian akhir ini menyatukan semua

rekomendasi menjadi satu cetak biru arsitektur yang koheren dan terintegrasi untuk

AINCORE. Arsitektur ini dirancang untuk menjadi sangat berperforma tinggi, modular,

aman, dan berwawasan ke depan. Selain itu, bagian ini menguraikan peta jalan

implementasi strategis berfase untuk memandu pengembangan AINCORE dari konsep

menjadi mainnet yang matang dan berkelanjutan.

7.1 Rekomendasi Terintegrasi: Arsitektur AINCORE yang Koheren

Arsitektur yang diusulkan untuk AINCORE adalah sintesis dari inovasi-inovasi terdepan

di seluruh spektrum teknologi blockchain, yang dirancang untuk saling melengkapi dan

menciptakan sistem yang lebih besar dari jumlah bagian-bagiannya.

• Lapisan Dasar (Konsensus & Mempool): AINCORE akan dibangun sebagai

blockchain Proof-of-Stake yang berdaulat. Inti mesin konsensusnya akan

mengadopsi arsitektur yang terinspirasi oleh Narwhal & Tusk, yang secara

fundamental memisahkan penyebaran data (mempool) dari pemesanan

transaksi (konsensus). Ini akan menjadi fondasi untuk throughput yang sangat

tinggi di tingkat protokol.3

• Lapisan Eksekusi: Di atas lapisan konsensus, AINCORE akan

mengimplementasikan mesin eksekusi paralel yang didasarkan pada model

objek Sui. Dengan membuat dependensi transaksi menjadi eksplisit melalui

objek, AINCORE dapat memproses sebagian besar transaksi yang tidak tumpang

tindih secara bersamaan, secara efektif menghindari bottleneck eksekusi

sekuensial dari arsitektur tradisional.5

• Lingkungan Pengembangan (Bahasa & Akun): Untuk memaksimalkan

keamanan dan pengalaman pengembang, AINCORE akan mengadopsi Sui Move

sebagai bahasa kontrak pintar utamanya. Ini memberikan jaminan keamanan

yang kuat di tingkat bahasa dan akses ke verifikasi formal melalui Move Prover.16

Untuk melengkapi ini, AINCORE akan mengimplementasikan Account

Abstraction secara native di tingkat protokol, mengubah setiap akun menjadi

kontrak pintar yang fleksibel dan memungkinkan pengalaman pengguna yang

setara dengan Web2.22

• Fondasi Modular: AINCORE akan dirancang sebagai protokol modular sejak

awal. Ia akan dikonfigurasi untuk mempublikasikan data transaksinya ke lapisan

ketersediaan data eksternal, dengan Celestia sebagai target integrasi utama

untuk menyelaraskan dengan filosofi kedaulatan.1 Selain itu, arsitekturnya akan

kompatibel dengan jaringan shared sequencer terdesentralisasi, memberikan

pilihan dan mendorong persaingan di lapisan pengurutan.2

• Interoperabilitas & Keamanan Lanjutan:

o Interoperabilitas: IBC akan diimplementasikan sebagai standar

komunikasi lintas-rantai asli, memastikan konektivitas yang minim

kepercayaan dan aman ke ekosistem yang lebih luas.30

o Privasi: Fungsionalitas privasi opsional akan diintegrasikan di tingkat

protokol menggunakan sirkuit ZK-SNARK, mengikuti model Zcash yang

telah terbukti.31

o Keamanan Jangka Panjang: AINCORE akan memiliki peta jalan yang jelas

untuk integrasi kriptografi pasca-kuantum (PQC), dimulai dengan

penggunaan CRYSTALS-Kyber untuk komunikasi jaringan dan

memanfaatkan AA asli untuk peningkatan skema tanda tangan di masa

depan.35

• Keberlanjutan Ekonomi & Tata Kelola:

o Ekonomi State: Mekanisme state rent yang disederhanakan, di mana

biaya dibebankan pada saat akses, akan diintegrasikan ke dalam model

ekonomi inti untuk mengelola pertumbuhan state dan memastikan

keberlanjutan jangka panjang.39

o Tata Kelola: Protokol akan diluncurkan dengan kerangka tata kelola yang

fleksibel dan dapat diupgrade, yang dirancang untuk memungkinkan

eksperimen di masa depan dengan model-model canggih seperti

Futarchy untuk pengambilan keputusan berbasis data.43

7.2 Pertimbangan Implementasi dan Peta Jalan Strategis

Pengembangan protokol yang ambisius seperti AINCORE harus dilakukan secara

bertahap, dengan setiap fase membangun di atas fondasi yang solid dari fase

sebelumnya. Peta jalan berikut menguraikan pendekatan strategis untuk implementasi.

• Fase 1: Fondasi Inti dan Jaringan Uji Internal (Testnet)

o Fokus: Mengimplementasikan komponen paling fundamental dari

protokol.

o Tugas Utama:

▪ Mengembangkan implementasi lapisan konsensus yang

terinspirasi Narwhal & Tusk.

▪ Membangun mesin eksekusi paralel awal berdasarkan model

objek.

▪ Mengintegrasikan kedua lapisan ini dan meluncurkan jaringan uji

internal yang stabil untuk pengujian kinerja dan validasi arsitektur.

o Tujuan: Membuktikan kelayakan dan keunggulan kinerja dari arsitektur

inti yang diusulkan.

• Fase 2: Ekosistem Pengembang dan Pengalaman Pengguna (UX)

o Fokus: Membangun alat dan fitur yang diperlukan untuk menarik

pengembang pertama dan memungkinkan aplikasi yang kuat.

o Tugas Utama:

▪ Implementasi penuh kompiler dan runtime Sui Move.

▪ Mengintegrasikan Abstraksi Akun secara native ke dalam protokol.

▪ Mengembangkan Software Development Kits (SDKs) awal,

dokumentasi komprehensif, dan integrasi dengan Move Prover.

▪ Meluncurkan jaringan uji publik untuk memungkinkan

pengembang eksternal mulai membangun dan bereksperimen.

o Tujuan: Menciptakan lingkungan pengembangan yang unggul yang

menonjolkan keamanan dan fleksibilitas AINCORE.

• Fase 3: Konektivitas, Modularitas, dan Peluncuran Jaringan Utama (Mainnet)

o Fokus: Menghubungkan AINCORE ke dunia luar dan sepenuhnya

mewujudkan visi modularnya.

o Tugas Utama:

▪ Mengintegrasikan kemampuan untuk mempublikasikan data ke

lapisan DA eksternal seperti Celestia.

▪ Mengimplementasikan dukungan untuk jaringan shared

sequencer.

▪ Mengembangkan dan mengaudit implementasi IBC untuk

interoperabilitas lintas-rantai.

▪ Melakukan audit keamanan menyeluruh pada seluruh basis kode.

▪ Meluncurkan mainnet publik AINCORE.

o Tujuan: Menghadirkan protokol yang aman, terdesentralisasi, dan

terhubung secara modular ke pasar.

• Fase 4: Fitur Lanjutan, Keberlanjutan, dan Evolusi

o Fokus: Memperkuat posisi AINCORE sebagai pemimpin teknologi dan

memastikan keberlanjutan jangka panjangnya.

o Tugas Utama:

▪ Mengimplementasikan dan mengaktifkan fitur privasi opsional

berbasis ZK-SNARK.

▪ Mengaktifkan mekanisme state rent untuk mengelola kesehatan

ekonomi state.

▪ Mendirikan AINCORE DAO dan memulai eksperimen tata kelola

awal, termasuk uji coba Futarchy untuk alokasi hibah.

▪ Memulai penelitian dan pengembangan aktif untuk transisi ke

kriptografi pasca-kuantum.

o Tujuan: Memastikan AINCORE tetap berada di garis depan inovasi

blockchain dan dapat beradaptasi dengan tantangan dan peluang di

masa depan.

Dengan mengikuti cetak biru arsitektur dan peta jalan strategis ini, AINCORE diposisikan

tidak hanya untuk bersaing tetapi juga untuk mendefinisikan ulang seperti apa

blockchain generasi berikutnya: dapat diskalakan, aman, fleksibel, dan pada akhirnya,

siap untuk adopsi massal.coba kamu analisa dari code ini dan dari ceta biru ini sudahkah mirip atau mendekati cetak biru ini?