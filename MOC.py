import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
from win10toast import ToastNotifier
import os

storage_file = "discovered_apps.txt"
safe_apps_file = "safe_apps.txt"

if not os.path.exists(safe_apps_file):
    with open(safe_apps_file, 'w', encoding='utf-8') as file:
        file.write("notepad.exe\n")

with open(safe_apps_file, 'r', encoding='utf-8') as file:
    safe_apps = set(line.strip() for line in file)


def add_safe_app():
    def save_app_name():
        new_app_name = app_name_entry.get()
        if new_app_name:
            safe_apps.add(new_app_name.strip())
            with open(safe_apps_file, 'a', encoding='utf-8') as file:
                file.write(f"{new_app_name}\n")
            safe_apps_window.destroy()

    safe_apps_window = tk.Toplevel()
    safe_apps_window.title("Add a secure application")
    safe_apps_window.geometry("400x200")

    icon_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
    if os.path.exists(icon_path):
        safe_apps_window.iconbitmap(icon_path)

    safe_apps_window.configure(bg="#20232a")

    app_name_label = tk.Label(safe_apps_window, text="App name:")
    app_name_label.pack(pady=10)

    app_name_entry = tk.Entry(safe_apps_window)
    app_name_entry.pack()

    save_button = tk.Button(safe_apps_window, text="add", command=save_app_name)
    save_button.pack(pady=10)


def find_applications_with_network_activity():
    discovered_apps = set()

    def monitor_network_activity():
        while True:
            new_apps = set()

            for process in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    open_connections = process.connections()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                else:
                    for conn in open_connections:
                        app_info = f"{process.info['name']} ({process.info['pid']})"
                        if app_info not in discovered_apps:
                            new_apps.add(app_info)
                            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                                remote_ip, remote_port = conn.raddr
                                discovered_apps.add(app_info)


                                app_path = process.info.get('exe', 'N/A')

                                if process.info['name'] in safe_apps:
                                    tree.insert('', 'end',
                                                values=(
                                                    process.info['name'], process.info['pid'], remote_port, remote_ip, app_path),
                                                tags=('safe_app',))
                                else:
                                    tree.insert('', 'end',
                                                values=(
                                                    process.info['name'], process.info['pid'], remote_port, remote_ip, app_path))


                                with open(storage_file, 'a', encoding='utf-8') as file:
                                    file.write(f"Application has been detected: {process.info['name']} ({process.info['pid']})\n"
                                               f"port: {remote_port}\n"
                                               f"IP: {remote_ip}\n"
                                               f"Application path: {app_path}\n\n")


    root = tk.Tk()
    root.title("Monitor external communications")
    root.geometry("800x400")

    toast = ToastNotifier()

    root.configure(bg="#20232a")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#282c34", foreground="white", fieldbackground="#282c34")
    style.map("Treeview", background=[("selected", "#0084FF")])

    columns = ("app name", "PID", "port", "IP", "App Path")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    tree.heading("app name", text="App name")
    tree.heading("PID", text="PID")
    tree.heading("port", text="port")
    tree.heading("IP", text="IP")
    tree.heading("App Path", text="App Path")

    tree.pack(fill=tk.BOTH, expand=True)

    vsb = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side='right', fill='y')

    style.configure("Treeview.Heading", background="#282c34", foreground="white")

    add_app_button = tk.Button(root, text="Add a secure application", command=add_safe_app, bg="#282c34", fg="white")
    add_app_button.pack()

    network_thread = threading.Thread(target=monitor_network_activity)
    network_thread.daemon = True
    network_thread.start()

    icon_path = os.path.join(os.path.dirname(__file__), 'icon.ico')
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.mainloop()


if __name__ == "__main__":
    find_applications_with_network_activity()
