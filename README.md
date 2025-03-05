Ce projet a pour but de tester la validation des 
certificats X.509 dans l'implémentation TLS

# Projet IFT785

## Objectif de l'atelier

Ce projet a pour but de tester la validation des 
certificats X.509 dans l'implémentation TLS

## Commandes pour exécuter le projet

1. **Installer les dépendances** :
   ```bash
   make install
   ```
2. **Lancer le serveur** :
   ```bash
   make run
   ```
3. **Accéder à l'application** :
   - Ouvrir votre navigateur et naviguer vers [http://localhost:5000](http://localhost:5000).

4. **Effectué les tests**
   ```bash
   make test
   ```

4. **Générer le rapport HTML de couverture** :
   ```bash
   make coverage-html
   ```

Pour nettoyer ou recompiler, utilisez :

```bash
make all
```

---

## Structure du Projet

```
project/p
├── src/
│   ├── app.py               # Contrôleur Flask
    ├── constants.py 
│   ├── enums/               # enums
│   ├── models/              # Modèles orientés objets
│   ├── templates/
│   │   ├ pages/             # Pages de l'aplication
│   │   ├ partials/          # Header et Footer et nav
│   ├── static/              # Static files
│   │   ├ documentation.html # Documentation du projet
│   ├── services/            # classes du service
├── Makefile                 # Commandes Make pour exécuter le projet
├── tests/
│   ├── unit/                # unit test files
│   ├── integration/         # Intgration test files
│   ├── performance/         # performance test files
```

---

## Auteure

- **Kevine Sorelle FOUEGUIM AZANGUE**
  - Code CIP : `fouk0792`

---