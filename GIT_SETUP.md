# GIT SETUP & PUSH TO GITHUB

## 1. Initialize Git (Jika belum)
```bash
git init
git add .
git commit -m "Initial commit AINCORE Blockchain v1.0"
```

## 2. Buat Repository di GitHub
1. Buka [GitHub.com](https://github.com/new).
2. Buat repository baru (Nama: `aincore-blockchain`).
3. Jangan centang "Add README" (biarkan kosong).

## 3. Push Code
Jalankan command ini di terminal:

```bash
git remote add origin https://github.com/Aint-core/AINCORE-Blockchain.git
git branch -M main
git push -u origin main
```

## 4. (Opsional) Jika pakai Laptop Lain
Di laptop teman, cukup clone:
```bash
git clone https://github.com/USERNAME/aincore-blockchain.git
cd aincore-blockchain
cargo build --release
```
