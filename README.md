Ce projet a pour but de tester la validation des 
certificats X.509 dans l'implémentation TLS

# Projet  Tests de validation de certificat X.509 dans l’implémentation TLS

## Objectif du projet

Ce projet a pour but de tester la validation des 
certificats X.509 dans l'implémentation TLS. En utilisant une approche orientée objet, les 
designs patterns, le refactoring et la gestion de versions. Puis d'implémenter et 
d'exécuter des tests unitaires et fonctionnels sur cette implémentation.

## Architecture du projet
le projet comporte 2 modules principaux: un module Validator (models) reponsable des opérations de validation et de la vérification des attributs des certificats, un module ServerSecurityAnalyser responsable de la vérification des propriétées de sécurité du certificat recupéré au niveau du module validator.

![new_arch.png](Images/new_arch.png)

## Conception de l'outil
Dans le cadre de ce projet, plusieurs design pattern(DP) seront utilisés.
Le premier est le DP Decorator utilisé pour la conception du module validator.
Ci-dessous l'architecture avant l'utilisation de la DP:
![packages_UML_Avant.png](Images/packages_UML_Avant.png)
l'architecture après l'utilisation du DP:
![classes_UML_Après.png](Images/classes_UML_Apr%C3%A8s.png)

Afin d'utiliser d'optimiser le processus de validation du certificat, deux autres design pattern ont été intégré à l'outil. Il s'agit du design pattern Factory responsable du processus de création des classes de validation des propriétés du certificat. Ci-dessous l'architecture après intégration de ce DP:
![classes_UML_factory_validator.png](Images/classes_UML_factory_validator.png)
Afin de permettre la selection du type de validation à effectué, le DP strategy a été intégré dans l'architecture. Ci dessous le diagramme UML:
![classes_UML_strategy_validator.png](Images/classes_UML_strategy_validator.png)
Pour finir, la nouvelle architecture du module validator avec le DP decorator utilisé initialement est le suivant:
![classes_UML_decorator_validator.png](Images/classes_UML_decorator_validator.png)

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
│   ├── config.py               # Contrôleur Flask
    ├── constants.py 
│   ├── enums/                 # enums
│   ├── models/                # Modèles orientés objets
│   ├── services/              # Couche service
│   ├── templates/
│   │   ├ pages/             # Pages de l'aplication
│   │   ├ partials/          # Header et Footer et nav
│   ├── static/              # Static files
│   │   ├ documentation.html # Documentation du projet
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