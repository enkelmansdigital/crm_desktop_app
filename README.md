# CRM Desktop App (Beta)

Een krachtige en geavanceerde CRM desktop applicatie ontwikkeld in Python met behulp van Tkinter en SQLite.  
Deze applicatie is gericht op lokaal klantenbeheer en bevindt zich momenteel in beta-fase.  
Ideaal als leerproject, demo of basis voor verdere professionele uitbreiding.

## 🚀 Functies

- ✅ Donker thema (Equilux)
- ✅ Inlogscherm met gebruikersauthenticatie
- ✅ Klanten toevoegen, bewerken en verwijderen
- ✅ Notities per klant (bij het aanmaken invulbaar)
- ✅ Afspraken per klant (met datumselectie)
- ✅ Statusselectie (Nieuw, In gesprek, Gesloten)
- ✅ Labels (categorieën) per klant
- ✅ Dashboard met interactieve line chart (matplotlib)
- ✅ Kalenderoverzicht met afspraken (tkcalendar)
- ✅ Export naar PDF
- ✅ Nette styling met ttk en ttkthemes

## 🛠️ Installatie

1. Installeer Python 3.x via [python.org](https://www.python.org/downloads/)
2. Installeer de benodigde Python-pakketten:

   ```bash
   pip install ttkthemes tkcalendar matplotlib bcrypt fpdf
Start de applicatie met:

python main.py

🔐 Inloggegevens (standaard)
Gebruikersnaam: admin

Wachtwoord: admin123

De wachtwoorden worden veilig opgeslagen met bcrypt-hashing.

📂 Structuur

crm_desktop_advanced/
├── main.py
├── database.db
├── exports/
│   └── klanten_export.pdf
├── README.md
└── ...


📤 Komende features
Export naar Excel (CSV / XLSX)

Bestanden toevoegen aan klant (bijv. PDF, DOCX)

Gebruikersrollen (Admin, Medewerker)

Meer grafieken (aantallen per status, maandelijkse groei)

Klantgeschiedenis / logboek per klant

🧑‍💻 Gemaakt door
Enkelmans Digital
GitHub: github.com/enkelmansdigital

📜 Licentie
Open-source voor educatief en persoonlijk gebruik.
Commerciële distributie is niet toegestaan zonder toestemming,
