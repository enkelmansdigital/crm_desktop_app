import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ttkthemes import ThemedTk
import sqlite3
import datetime
import json
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkcalendar import Calendar
import bcrypt
from fpdf import FPDF

DB_NAME = "crm_advanced.db"

# Database functies
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        notes TEXT,
        appointment_date TEXT,
        status TEXT DEFAULT 'Nieuw',
        labels TEXT DEFAULT '[]',
        created_at TEXT DEFAULT (DATE('now'))
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def create_default_user():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        password_hash = bcrypt.hashpw("1234".encode("utf-8"), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", password_hash))
    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return bcrypt.checkpw(password.encode("utf-8"), row[0])
    return False

def add_customer(name, email, phone, notes="", appointment_date=None, status="Nieuw", labels=None):
    if labels is None:
        labels = []
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
    INSERT INTO customers (name, email, phone, notes, appointment_date, status, labels)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (name, email, phone, notes, appointment_date, status, json.dumps(labels)))
    conn.commit()
    conn.close()

def update_customer(cid, name, email, phone, notes, appointment_date, status, labels):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
    UPDATE customers SET name=?, email=?, phone=?, notes=?, appointment_date=?, status=?, labels=?
    WHERE id=?
    """, (name, email, phone, notes, appointment_date, status, json.dumps(labels), cid))
    conn.commit()
    conn.close()

def delete_customer(cid):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM customers WHERE id=?", (cid,))
    conn.commit()
    conn.close()

def get_customers(filter_text=""):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if filter_text:
        like_filter = f"%{filter_text}%"
        c.execute("""
        SELECT id, name, email, phone, notes, appointment_date, status, labels 
        FROM customers 
        WHERE name LIKE ? OR email LIKE ? OR phone LIKE ? OR notes LIKE ?
        ORDER BY name
        """, (like_filter, like_filter, like_filter, like_filter))
    else:
        c.execute("""
        SELECT id, name, email, phone, notes, appointment_date, status, labels 
        FROM customers ORDER BY name
        """)
    rows = c.fetchall()
    conn.close()
    return rows

# CRM App class
class CRMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📇 Geavanceerde CRM App")
        self.root.state('zoomed')  # fullscreen/maximized

        # Donker thema standaard
        self.current_theme = "equilux"
        root.set_theme(self.current_theme)

        self.style = ttk.Style(root)
        self.set_dark_theme_style()

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        btn_theme = ttk.Button(self.main_frame, text="☀️ Licht thema", command=self.toggle_theme)
        btn_theme.pack(anchor="ne", padx=20, pady=10)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.tab_customers = ttk.Frame(self.notebook)
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.tab_calendar = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_customers, text="Klanten")
        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.notebook.add(self.tab_calendar, text="Kalender")

        self.build_customers_tab()
        self.build_dashboard_tab()
        self.build_calendar_tab()

    def set_dark_theme_style(self):
        self.style.configure("TFrame", background="#222222")
        self.style.configure("TLabel", background="#222222", foreground="#eeeeee", font=("Segoe UI", 12))
        self.style.configure("TButton", background="#444444", foreground="#ffffff", font=("Segoe UI", 12, "bold"))
        self.style.map("TButton",
                       background=[("active", "#666666")],
                       foreground=[("active", "#ffffff")])
        self.style.configure("Treeview",
                             background="#333333",
                             foreground="#eeeeee",
                             fieldbackground="#333333")
        self.style.map('Treeview',
                       background=[('selected', '#4a90e2')],
                       foreground=[('selected', 'white')])

    def set_light_theme_style(self):
        self.style.configure("TFrame", background="#f0f4f8")
        self.style.configure("TLabel", background="#f0f4f8", foreground="black", font=("Segoe UI", 12))
        self.style.configure("TButton", background="#4a90e2", foreground="white", font=("Segoe UI", 12, "bold"))
        self.style.map("TButton",
                       background=[("active", "#357ABD")],
                       foreground=[("active", "white")])
        self.style.configure("Treeview",
                             background="white",
                             foreground="black",
                             fieldbackground="white")
        self.style.map('Treeview',
                       background=[('selected', '#4a90e2')],
                       foreground=[('selected', 'white')])

    def toggle_theme(self):
        if self.current_theme == "equilux":
            self.current_theme = "arc"
            self.root.set_theme(self.current_theme)
            self.set_light_theme_style()
        else:
            self.current_theme = "equilux"
            self.root.set_theme(self.current_theme)
            self.set_dark_theme_style()

    # Build klanten tab
    def build_customers_tab(self):
        frame = ttk.Frame(self.tab_customers, padding=10)
        frame.pack(expand=True, fill=tk.BOTH)

        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, pady=5)

        ttk.Label(search_frame, text="Zoeken:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self.load_customers())

        ttk.Button(search_frame, text="Importeer CSV", command=self.import_csv).pack(side=tk.RIGHT, padx=5)
        ttk.Button(search_frame, text="Exporteer CSV", command=self.export_csv).pack(side=tk.RIGHT, padx=5)
        ttk.Button(search_frame, text="Exporteer PDF", command=self.export_pdf).pack(side=tk.RIGHT, padx=5)

        columns = ("name", "email", "phone", "status", "appointment_date", "labels")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=130 if col != "labels" else 160)
        self.tree.pack(expand=True, fill=tk.BOTH, pady=5)
        self.tree.bind("<Double-1>", self.on_edit_customer)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Nieuw", command=self.on_new_customer).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Bewerken", command=self.on_edit_customer).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Verwijderen", command=self.on_delete_customer).pack(side=tk.LEFT, padx=5)

        self.load_customers()

    def load_customers(self):
        filter_text = self.search_var.get()
        rows = get_customers(filter_text)
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            labels_str = ", ".join(json.loads(r[7])) if r[7] else ""
            self.tree.insert("", tk.END, iid=r[0], values=(r[1], r[2], r[3], r[6], r[5] or "", labels_str))

    def on_new_customer(self):
        dlg = EditDialog(self.root, "", "", "", "", None, "Nieuw", "[]")
        self.root.wait_window(dlg)
        if dlg.result:
            name, email, phone, notes, appointment, status, labels = dlg.result
            add_customer(name, email, phone, notes, appointment, status, labels)
            self.load_customers()

    def on_edit_customer(self, event=None):
        selected = self.tree.focus()
        if not selected:
            messagebox.showinfo("Info", "Selecteer eerst een klant om te bewerken.")
            return
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT name, email, phone, notes, appointment_date, status, labels FROM customers WHERE id=?", (selected,))
        row = c.fetchone()
        conn.close()
        if row:
            dlg = EditDialog(self.root, *row)
            self.root.wait_window(dlg)
            if dlg.result:
                name, email, phone, notes, appointment, status, labels = dlg.result
                update_customer(selected, name, email, phone, notes, appointment, status, labels)
                self.load_customers()

    def on_delete_customer(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showinfo("Info", "Selecteer eerst een klant om te verwijderen.")
            return
        if messagebox.askyesno("Bevestiging", "Weet je zeker dat je deze klant wilt verwijderen?"):
            delete_customer(selected)
            self.load_customers()

    def import_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV bestanden", "*.csv"), ("Alle bestanden", "*.*")])
        if not file_path:
            return
        try:
            with open(file_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                count = 0
                for row in reader:
                    name = row.get("Naam") or row.get("name") or ""
                    email = row.get("E-mail") or row.get("email") or ""
                    phone = row.get("Telefoon") or row.get("phone") or ""
                    notes = row.get("Notities") or row.get("notes") or ""
                    appointment = row.get("Afspraak") or row.get("appointment_date") or None
                    status = row.get("Status") or "Nieuw"
                    labels_raw = row.get("Labels") or "[]"
                    try:
                        labels = json.loads(labels_raw)
                    except:
                        labels = [label.strip() for label in labels_raw.split(",") if label.strip()]
                    if name and email and phone:
                        add_customer(name, email, phone, notes, appointment, status, labels)
                        count += 1
            messagebox.showinfo("Import voltooid", f"{count} klanten succesvol geïmporteerd.")
            self.load_customers()
        except Exception as e:
            messagebox.showerror("Fout", f"Import mislukt: {e}")

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV bestanden", "*.csv"), ("Alle bestanden", "*.*")])
        if not file_path:
            return
        rows = get_customers()
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Naam", "E-mail", "Telefoon", "Notities", "Afspraak", "Status", "Labels"])
                for r in rows:
                    writer.writerow([r[1], r[2], r[3], r[4], r[5] or "", r[6], r[7]])
            messagebox.showinfo("Export voltooid", f"Export naar {file_path} succesvol.")
        except Exception as e:
            messagebox.showerror("Fout", f"Export mislukt: {e}")

    def export_pdf(self):
        rows = get_customers()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Klantenlijst", ln=True, align='C')
        pdf.ln(10)
        for r in rows:
            labels_str = ", ".join(json.loads(r[7])) if r[7] else ""
            pdf.cell(0, 10, f"Naam: {r[1]}, Email: {r[2]}, Telefoon: {r[3]}, Status: {r[6]}, Afspraak: {r[5] or ''}, Labels: {labels_str}", ln=True)
            if r[4]:
                pdf.multi_cell(0, 10, f"Notities: {r[4]}")
            pdf.ln(5)
        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF bestanden", "*.pdf")])
            if not file_path:
                return
            pdf.output(file_path)
            messagebox.showinfo("Export voltooid", f"PDF opgeslagen als {file_path}.")
        except Exception as e:
            messagebox.showerror("Fout", f"PDF export mislukt: {e}")

    # Dashboard tab
    def build_dashboard_tab(self):
        frame = ttk.Frame(self.tab_dashboard, padding=10)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Dashboard met klantstatistieken", font=("Segoe UI", 20)).pack(pady=10)

        self.figure = plt.Figure(figsize=(8,5), dpi=100)
        self.ax = self.figure.add_subplot(111)

        self.canvas = FigureCanvasTkAgg(self.figure, frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)

        ttk.Button(frame, text="Ververs grafiek", command=self.load_dashboard_data).pack(pady=5)

        self.load_dashboard_data()

    def load_dashboard_data(self):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT created_at, COUNT(*) FROM customers GROUP BY created_at ORDER BY created_at")
        data = c.fetchall()
        conn.close()

        if not data:
            self.ax.clear()
            self.ax.text(0.5, 0.5, 'Geen data beschikbaar', ha='center', va='center', fontsize=14, color='white' if self.current_theme=="equilux" else 'black')
            self.canvas.draw()
            return

        dates = [datetime.datetime.strptime(d[0], "%Y-%m-%d") for d in data]
        counts = [d[1] for d in data]

        self.ax.clear()
        line_color = '#4a90e2' if self.current_theme=="arc" else '#4bc1ff'
        self.ax.plot(dates, counts, marker='o', linestyle='-', color=line_color)
        self.ax.set_title("Aantal klanten per dag", color='white' if self.current_theme=="equilux" else 'black')
        self.ax.set_xlabel("Datum", color='white' if self.current_theme=="equilux" else 'black')
        self.ax.set_ylabel("Aantal", color='white' if self.current_theme=="equilux" else 'black')
        self.ax.grid(True, color='gray' if self.current_theme=="equilux" else 'lightgray')
        self.figure.autofmt_xdate()
        self.canvas.draw()

    # Kalender tab
    def build_calendar_tab(self):
        frame = ttk.Frame(self.tab_calendar, padding=10)
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Kalender met afspraken", font=("Segoe UI", 20)).pack(pady=10)

        self.calendar = Calendar(frame, selectmode="day")
        self.calendar.pack(pady=10)

        ttk.Button(frame, text="Toon afspraken van dag", command=self.show_appointments).pack(pady=5)

        self.appointments_list = tk.Listbox(frame)
        self.appointments_list.pack(expand=True, fill=tk.BOTH, pady=5)

    def show_appointments(self):
        selected_date = self.calendar.get_date()
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, name, email, phone FROM customers WHERE appointment_date=?", (selected_date,))
        rows = c.fetchall()
        conn.close()

        self.appointments_list.delete(0, tk.END)
        if rows:
            for r in rows:
                self.appointments_list.insert(tk.END, f"{r[1]} | {r[2]} | {r[3]}")
        else:
            self.appointments_list.insert(tk.END, "Geen afspraken op deze dag.")

# Bewerken dialoog
class EditDialog(tk.Toplevel):
    def __init__(self, master, name, email, phone, notes, appointment_date, status, labels):
        super().__init__(master)
        self.title("Klant bewerken")
        self.result = None

        self.name_var = tk.StringVar(value=name)
        self.email_var = tk.StringVar(value=email)
        self.phone_var = tk.StringVar(value=phone)
        self.notes_text = tk.Text(self, width=40, height=5, font=("Segoe UI", 12))
        self.notes_text.insert("1.0", notes)
        self.appointment_var = tk.StringVar(value=appointment_date if appointment_date else "")
        self.status_var = tk.StringVar(value=status)
        self.labels_master = ["VIP", "Belangrijk", "Follow-up", "Lead", "Prospect"]
        self.label_vars = {}

        ttk.Label(self, text="Naam:").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        ttk.Label(self, text="E-mail:").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        ttk.Label(self, text="Telefoon:").grid(row=2, column=0, sticky="e", padx=5, pady=3)
        ttk.Label(self, text="Afspraak (YYYY-MM-DD):").grid(row=3, column=0, sticky="e", padx=5, pady=3)
        ttk.Label(self, text="Status:").grid(row=4, column=0, sticky="e", padx=5, pady=3)
        ttk.Label(self, text="Labels:").grid(row=5, column=0, sticky="ne", padx=5, pady=3)
        ttk.Label(self, text="Notities:").grid(row=6, column=0, sticky="ne", padx=5, pady=3)

        ttk.Entry(self, textvariable=self.name_var).grid(row=0, column=1, padx=5, pady=3)
        ttk.Entry(self, textvariable=self.email_var).grid(row=1, column=1, padx=5, pady=3)
        ttk.Entry(self, textvariable=self.phone_var).grid(row=2, column=1, padx=5, pady=3)
        ttk.Entry(self, textvariable=self.appointment_var).grid(row=3, column=1, padx=5, pady=3)

        status_options = ["Nieuw", "Contact", "In gesprek", "Afspraak gepland", "Gesloten"]
        ttk.Combobox(self, textvariable=self.status_var, values=status_options, state="readonly").grid(row=4, column=1, padx=5, pady=3)

        labels_frame = ttk.Frame(self)
        labels_frame.grid(row=5, column=1, padx=5, pady=3, sticky="w")
        for i, label in enumerate(self.labels_master):
            var = tk.BooleanVar(value=(label in json.loads(labels)))
            chk = ttk.Checkbutton(labels_frame, text=label, variable=var)
            chk.grid(row=0, column=i, padx=2)
            self.label_vars[label] = var

        self.notes_text.grid(row=6, column=1, padx=5, pady=3)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Opslaan", command=self.on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Annuleren", command=self.destroy).pack(side=tk.LEFT, padx=5)

    def on_save(self):
        name = self.name_var.get().strip()
        email = self.email_var.get().strip()
        phone = self.phone_var.get().strip()
        notes = self.notes_text.get("1.0", tk.END).strip()
        appointment = self.appointment_var.get().strip()
        status = self.status_var.get()
        labels = [label for label, var in self.label_vars.items() if var.get()]

        if not name or not email or not phone:
            messagebox.showerror("Fout", "Naam, e-mail en telefoon zijn verplicht.")
            return

        if appointment:
            try:
                datetime.datetime.strptime(appointment, "%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Fout", "Afspraak moet in formaat YYYY-MM-DD zijn.")
                return

        self.result = (name, email, phone, notes, appointment if appointment else None, status, labels)
        self.destroy()

# Login scherm
class LoginDialog(tk.Toplevel):
    def __init__(self, master, on_success):
        super().__init__(master)
        self.title("Login")
        self.on_success = on_success
        self.result = None
        self.geometry("300x150")
        self.resizable(False, False)
        self.grab_set()

        ttk.Label(self, text="Gebruikersnaam:").pack(pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.username_var).pack()

        ttk.Label(self, text="Wachtwoord:").pack(pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.password_var, show="*").pack()

        ttk.Button(self, text="Login", command=self.check_login).pack(pady=10)

    def check_login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        if check_user(username, password):
            self.destroy()
            self.on_success()
        else:
            messagebox.showerror("Fout", "Ongeldige gebruikersnaam of wachtwoord.")

# Main functie
def main():
    init_db()
    create_default_user()

    root = ThemedTk(theme="equilux")
    root.withdraw()  # verberg hoofdvenster eerst

    def start_crm():
        root.deiconify()  # toon hoofdvenster na login
        app = CRMApp(root)

    login = LoginDialog(root, start_crm)
    root.mainloop()

if __name__ == "__main__":
    main()
